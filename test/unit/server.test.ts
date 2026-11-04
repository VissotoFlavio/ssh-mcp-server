import { strict as assert } from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import type { ApprovedProfileListingProvider } from '../../src/profiles/approved-profile-listing.js';
import { listApprovedProfilesToolName, runStdioServer, serverName, type StdioServerOptions } from '../../src/server.js';

function requestResponse(input: PassThrough, output: PassThrough, request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = once(output, 'data');
  input.write(`${JSON.stringify(request)}\n`);
  return response.then(([chunk]) => JSON.parse(String(chunk)) as Record<string, unknown>);
}

function createDiscoveryRuntime(provider: ApprovedProfileListingProvider): {
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
  assert.match(diagnostics, /^MCP server error:/);
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
