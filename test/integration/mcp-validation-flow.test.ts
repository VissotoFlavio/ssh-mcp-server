import { strict as assert } from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { HostIdentityCredentialPolicyError } from '../../src/policy/host-identity-credential-policy.js';
import type { ApprovedProfileListingProvider } from '../../src/profiles/approved-profile-listing.js';
import { listApprovedProfilesToolName, runStdioServer, validateConnectionToolName, type StdioServerOptions } from '../../src/server.js';
import type { ConnectionValidationProvider } from '../../src/validation/trusted-connection-validation.js';

type McpRuntime = {
  readonly input: PassThrough;
  readonly output: PassThrough;
  readonly errors: PassThrough;
  readonly runtime: Promise<void>;
};

function startMcp(
  approvedProfileListingProvider: ApprovedProfileListingProvider,
  connectionValidationProvider: ConnectionValidationProvider,
): McpRuntime {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  const options: StdioServerOptions = {
    input,
    output,
    errorOutput: errors,
    installSignalHandlers: false,
    approvedProfileListingProvider,
    connectionValidationProvider,
  };
  return { input, output, errors, runtime: runStdioServer(options) };
}

function requestResponse(input: PassThrough, output: PassThrough, request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = once(output, 'data');
  input.write(`${JSON.stringify(request)}\n`);
  return response.then(([chunk]) => JSON.parse(String(chunk)) as Record<string, unknown>);
}

async function initialize(input: PassThrough, output: PassThrough): Promise<void> {
  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'integration-test', version: '1.0.0' } },
  });
}

test('runs the complete injected validation flow over stdio without polluting protocol stdout', async () => {
  let listings = 0;
  let validationInput: unknown;
  const { input, output, errors, runtime } = startMcp(
    {
      async listApprovedProfiles() {
        listings += 1;
        return [{ profileId: 'production-api', classification: 'operator-approved' }];
      },
    },
    {
      async validateConnection(value) {
        validationInput = value;
        return { profileId: 'production-api', ready: true };
      },
    },
  );
  let stdout = '';
  let stderr = '';
  output.on('data', (chunk) => {
    stdout += String(chunk);
  });
  errors.on('data', (chunk) => {
    stderr += String(chunk);
  });

  await initialize(input, output);
  const tools = await requestResponse(input, output, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const names = (tools.result as { readonly tools: readonly { readonly name: string }[] }).tools.map((tool) => tool.name);
  assert.deepEqual(names, [listApprovedProfilesToolName, validateConnectionToolName]);

  const listed = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: listApprovedProfilesToolName, arguments: {} },
  });
  assert.deepEqual(listed.result, {
    content: [{ type: 'text', text: JSON.stringify({ profiles: [{ profileId: 'production-api', classification: 'operator-approved' }] }) }],
  });

  const validated = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: { name: validateConnectionToolName, arguments: { profileId: 'production-api' } },
  });
  assert.deepEqual(validated.result, { content: [{ type: 'text', text: JSON.stringify({ profileId: 'production-api', ready: true }) }] });
  assert.equal(listings, 1);
  assert.deepEqual(validationInput, { profileId: 'production-api' });
  assert.deepEqual(
    stderr
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line)),
    [
      {
        kind: 'connection-audit-event',
        version: 1,
        stage: 'readiness',
        profileId: 'production-api',
        outcome: 'success',
        code: 'success',
        durationMs: JSON.parse(stderr).durationMs,
      },
    ],
  );
  for (const line of stdout.trim().split('\n')) {
    assert.equal((JSON.parse(line) as { readonly jsonrpc?: string }).jsonrpc, '2.0');
  }

  input.end();
  await runtime;
});

test('rejects unsafe validation input before invoking the injected provider', async () => {
  let validationCalls = 0;
  const { input, output, errors, runtime } = startMcp(
    {
      async listApprovedProfiles() {
        return [];
      },
    },
    {
      async validateConnection() {
        validationCalls += 1;
        return { profileId: 'production-api', ready: true };
      },
    },
  );
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });

  await initialize(input, output);
  const rejected = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: validateConnectionToolName, arguments: { profileId: 'production-api', command: 'uname -a' } },
  });

  assert.deepEqual(rejected.result, {
    content: [{ type: 'text', text: JSON.stringify({ ready: false, outcome: 'failure', code: 'invalid-input' }) }],
    isError: true,
  });
  assert.equal(validationCalls, 0);
  assert.deepEqual(JSON.parse(audit), {
    kind: 'connection-audit-event',
    version: 1,
    stage: 'selection',
    outcome: 'failure',
    code: 'invalid-input',
  });

  input.end();
  await runtime;
});

test('redacts a host-key mismatch from MCP output and the stderr audit record', async () => {
  const secret = 'SHA256:private host=prod.internal user=deploy known-hosts://private';
  const { input, output, errors, runtime } = startMcp(
    {
      async listApprovedProfiles() {
        return [];
      },
    },
    {
      async validateConnection() {
        throw new HostIdentityCredentialPolicyError('known-hosts-entry-mismatch', secret);
      },
    },
  );
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });

  await initialize(input, output);
  const rejected = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: validateConnectionToolName, arguments: { profileId: 'production-api' } },
  });

  assert.deepEqual(rejected.result, {
    content: [{ type: 'text', text: JSON.stringify({ ready: false, outcome: 'failure', code: 'host-key-failure' }) }],
    isError: true,
  });
  assert.equal(JSON.stringify(rejected).includes('private'), false);
  assert.equal(audit.includes('private'), false);
  assert.equal(audit.includes('prod.internal'), false);
  assert.equal(audit.includes('deploy'), false);
  assert.deepEqual(JSON.parse(audit), {
    kind: 'connection-audit-event',
    version: 1,
    stage: 'readiness',
    profileId: 'production-api',
    outcome: 'failure',
    code: 'host-key-failure',
    durationMs: JSON.parse(audit).durationMs,
  });

  input.end();
  await runtime;
});
