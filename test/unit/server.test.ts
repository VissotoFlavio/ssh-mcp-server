import { strict as assert } from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import type { ApprovedProfileListingProvider } from '../../src/profiles/approved-profile-listing.js';
import {
  listApprovedProfilesToolName,
  reportEntrypointFailure,
  runStdioServer,
  serverName,
  validateConnectionToolName,
  type StdioServerOptions,
} from '../../src/server.js';
import type { ConnectionValidationProvider } from '../../src/validation/trusted-connection-validation.js';

function requestResponse(input: PassThrough, output: PassThrough, request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = once(output, 'data');
  input.write(`${JSON.stringify(request)}\n`);
  return response.then(([chunk]) => JSON.parse(String(chunk)) as Record<string, unknown>);
}

function createDiscoveryRuntime(
  provider: ApprovedProfileListingProvider,
  connectionValidationProvider?: ConnectionValidationProvider,
): {
  readonly input: PassThrough;
  readonly output: PassThrough;
  readonly errors: PassThrough;
  readonly runtime: Promise<void>;
} {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  const options: StdioServerOptions = {
    input,
    output,
    errorOutput: errors,
    installSignalHandlers: false,
    approvedProfileListingProvider: provider,
    connectionValidationProvider,
  };
  return { input, output, errors, runtime: runStdioServer(options) };
}

test('exposes the server name', () => {
  assert.equal(serverName, 'ssh-mcp-server');
});

test('speaks MCP over stdio and closes when its client disconnects', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  const runtime = runStdioServer({ input, output, errorOutput: errors });

  const response = once(output, 'data');
  input.write(
    `${JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      },
    })}\n`,
  );

  const [chunk] = await response;
  const message = JSON.parse(String(chunk));

  assert.equal(message.jsonrpc, '2.0');
  assert.equal(message.id, 1);
  assert.equal(message.result.serverInfo.name, serverName);
  assert.deepEqual(message.result.capabilities, { tools: {} });

  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('writes transport errors to stderr instead of stdout', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  const runtime = runStdioServer({ input, output, errorOutput: errors });
  let diagnostics = '';
  errors.on('data', (chunk) => {
    diagnostics += String(chunk);
  });

  const receivedError = once(errors, 'data');
  input.write('not JSON-RPC\n');
  await receivedError;
  input.end();
  await runtime;

  assert.equal(output.readableLength, 0);
  assert.equal(diagnostics, 'MCP server error\n');
});

test('redacts secret-bearing entrypoint startup failures', () => {
  let diagnostic = '';
  reportEntrypointFailure(
    {
      write(chunk: string) {
        diagnostic += chunk;
        return true;
      },
    },
    new Error('credential-secret'),
  );

  assert.equal(diagnostic, 'MCP server failed to start\n');
  assert.equal(diagnostic.includes('credential-secret'), false);
});

test('exposes only allowlisted approved profile metadata through the discovery tool', async () => {
  let listingCalls = 0;
  const provider: ApprovedProfileListingProvider = {
    async listApprovedProfiles() {
      listingCalls += 1;
      return [
        {
          profileId: 'production-readonly',
          classification: 'operator-approved',
          credentialReference: 'credential-secret',
          expectedHostFingerprint: 'SHA256:host-secret',
          approvedKnownHostsReference: '/private/known_hosts',
        } as unknown as { readonly profileId: string; readonly classification: 'operator-approved' },
      ];
    },
  };
  const { input, output, errors, runtime } = createDiscoveryRuntime(provider);

  const initialization = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test-client', version: '1.0.0' },
    },
  });
  assert.deepEqual((initialization.result as { capabilities: unknown }).capabilities, { tools: {} });

  const listedTools = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
  });
  assert.deepEqual(listedTools.result, {
    tools: [
      {
        name: listApprovedProfilesToolName,
        description: 'Lists the identifiers of profiles approved by the operator. Connection, credential, and host details are not disclosed.',
        inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      },
    ],
  });

  const discovery = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: listApprovedProfilesToolName, arguments: {} },
  });
  const result = discovery.result as { content: readonly { type: string; text: string }[] };
  assert.deepEqual(result.content, [
    {
      type: 'text',
      text: JSON.stringify({
        profiles: [{ profileId: 'production-readonly', classification: 'operator-approved' }],
      }),
    },
  ]);
  assert.equal(JSON.stringify(discovery).includes('credential-secret'), false);
  assert.equal(JSON.stringify(discovery).includes('host-secret'), false);
  assert.equal(JSON.stringify(discovery).includes('known_hosts'), false);
  assert.equal(listingCalls, 1);

  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('rejects unexpected discovery input before consulting the provider', async () => {
  let listingCalls = 0;
  const provider: ApprovedProfileListingProvider = {
    async listApprovedProfiles() {
      listingCalls += 1;
      return [];
    },
  };
  const { input, output, errors, runtime } = createDiscoveryRuntime(provider);

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test-client', version: '1.0.0' },
    },
  });
  const response = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: listApprovedProfilesToolName, arguments: { stateRoot: 'C:\\secret' } },
  });

  assert.deepEqual(response.result, {
    content: [{ type: 'text', text: 'Approved profile discovery is unavailable.' }],
    isError: true,
  });
  assert.equal(listingCalls, 0);

  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('fails closed for hostile provider result arrays without serializing their values', async () => {
  let mapCalls = 0;
  const maliciousMap = Object.assign([{ profileId: 'safe-profile', classification: 'operator-approved' }], {
    map: () => {
      mapCalls += 1;
      return [{ profileId: 'credential-secret', classification: 'operator-approved' }];
    },
  });
  const malformedResults: unknown[] = [maliciousMap, new Array(1), new Array(257)];
  let call = 0;
  const provider: ApprovedProfileListingProvider = {
    async listApprovedProfiles() {
      const result = malformedResults[call];
      call += 1;
      return result as readonly { readonly profileId: string; readonly classification: 'operator-approved' }[];
    },
  };
  const { input, output, errors, runtime } = createDiscoveryRuntime(provider);

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test-client', version: '1.0.0' },
    },
  });

  for (const id of [2, 3, 4]) {
    const response = await requestResponse(input, output, {
      jsonrpc: '2.0',
      id,
      method: 'tools/call',
      params: { name: listApprovedProfilesToolName, arguments: {} },
    });
    assert.deepEqual(response.result, {
      content: [{ type: 'text', text: 'Approved profile discovery is unavailable.' }],
      isError: true,
    });
    assert.equal(JSON.stringify(response).includes('credential-secret'), false);
  }
  assert.equal(mapCalls, 0);

  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('validates an approved profile through the trusted readiness provider', async () => {
  const provider: ApprovedProfileListingProvider = {
    async listApprovedProfiles() {
      return [];
    },
  };
  let received: unknown;
  const connectionValidationProvider: ConnectionValidationProvider = {
    async validateConnection(input) {
      received = input;
      return { profileId: 'production-api', ready: true };
    },
  };
  const { input, output, errors, runtime } = createDiscoveryRuntime(provider, connectionValidationProvider);
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
  });
  const listedTools = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list',
  });
  assert.equal(
    (listedTools.result as { tools: readonly { readonly name: string }[] }).tools.some((tool) => tool.name === validateConnectionToolName),
    true,
  );
  const response = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: validateConnectionToolName, arguments: { profileId: 'production-api' } },
  });

  assert.deepEqual(response.result, { content: [{ type: 'text', text: JSON.stringify({ profileId: 'production-api', ready: true }) }] });
  assert.deepEqual(received, { profileId: 'production-api' });
  const successAudit = JSON.parse(audit) as { readonly durationMs?: number; readonly [key: string]: unknown };
  assert.deepEqual(
    { ...successAudit, durationMs: 0 },
    {
      kind: 'connection-audit-event',
      version: 1,
      stage: 'readiness',
      profileId: 'production-api',
      outcome: 'success',
      code: 'success',
      durationMs: 0,
    },
  );
  assert.equal(typeof successAudit.durationMs, 'number');
  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('rejects a valid provider outcome for a different profile and audits the requested profile', async () => {
  const provider: ApprovedProfileListingProvider = {
    async listApprovedProfiles() {
      return [];
    },
  };
  const connectionValidationProvider: ConnectionValidationProvider = {
    async validateConnection() {
      return { profileId: 'staging-api', ready: true };
    },
  };
  const { input, output, errors, runtime } = createDiscoveryRuntime(provider, connectionValidationProvider);
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
  });
  const response = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: validateConnectionToolName, arguments: { profileId: 'production-api' } },
  });

  assert.deepEqual(response.result, {
    content: [{ type: 'text', text: JSON.stringify({ ready: false, outcome: 'failure', code: 'unknown' }) }],
    isError: true,
  });
  assert.equal(JSON.stringify(response).includes('staging-api'), false);
  const event = JSON.parse(audit) as {
    readonly profileId?: string;
    readonly outcome?: string;
    readonly code?: string;
    readonly durationMs?: number;
  };
  assert.deepEqual(event, {
    kind: 'connection-audit-event',
    version: 1,
    stage: 'readiness',
    profileId: 'production-api',
    outcome: 'failure',
    code: 'unknown',
    durationMs: event.durationMs,
  });
  assert.equal(typeof event.durationMs, 'number');
  assert.equal(audit.includes('staging-api'), false);
  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('rejects unexpected validation input before consulting the readiness provider', async () => {
  const provider: ApprovedProfileListingProvider = {
    async listApprovedProfiles() {
      return [];
    },
  };
  let calls = 0;
  const connectionValidationProvider: ConnectionValidationProvider = {
    async validateConnection() {
      calls += 1;
      return { profileId: 'production-api', ready: true };
    },
  };
  const { input, output, errors, runtime } = createDiscoveryRuntime(provider, connectionValidationProvider);
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
  });
  const response = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: validateConnectionToolName, arguments: { profileId: 'production-api', command: 'uname -a' } },
  });

  assert.deepEqual(response.result, {
    content: [{ type: 'text', text: JSON.stringify({ ready: false, outcome: 'failure', code: 'invalid-input' }) }],
    isError: true,
  });
  assert.equal(calls, 0);
  assert.deepEqual(JSON.parse(audit), {
    kind: 'connection-audit-event',
    version: 1,
    stage: 'selection',
    outcome: 'failure',
    code: 'invalid-input',
  });
  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('redacts host and credential validation failures', async () => {
  const provider: ApprovedProfileListingProvider = {
    async listApprovedProfiles() {
      return [];
    },
  };
  let call = 0;
  const connectionValidationProvider: ConnectionValidationProvider = {
    async validateConnection() {
      call += 1;
      if (call === 3) {
        return {
          profileId: 'production-api',
          ready: true,
          credentialReference: 'os://ssh/private',
          fingerprint: 'SHA256:private',
        } as unknown as { readonly profileId: string; readonly ready: true };
      }
      const error = new Error(
        call === 1 ? 'fingerprint=SHA256:private host=prod.internal user=deploy' : 'credential=os://ssh/private password=secret',
      );
      Object.assign(error, { code: call === 1 ? 'known-hosts-entry-mismatch' : 'credential-reference-unapproved' });
      throw error;
    },
  };
  const { input, output, errors, runtime } = createDiscoveryRuntime(provider, connectionValidationProvider);
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
  });
  for (const id of [2, 3, 4]) {
    const response = await requestResponse(input, output, {
      jsonrpc: '2.0',
      id,
      method: 'tools/call',
      params: { name: validateConnectionToolName, arguments: { profileId: 'production-api' } },
    });
    assert.equal(JSON.stringify(response).includes('private'), false);
    assert.equal(JSON.stringify(response).includes('secret'), false);
    assert.equal(JSON.stringify(response).includes('private'), false);
  }
  assert.equal(audit.includes('private'), false);
  assert.equal(audit.includes('secret'), false);
  assert.equal(audit.includes('prod.internal'), false);
  assert.equal(audit.includes('deploy'), false);
  const events = audit
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as { readonly code: string; readonly stage: string });
  assert.deepEqual(
    events.map((event) => ({ code: event.code, stage: event.stage })),
    [
      { code: 'host-key-failure', stage: 'readiness' },
      { code: 'authentication-failure', stage: 'readiness' },
      { code: 'unknown', stage: 'readiness' },
    ],
  );
  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});
