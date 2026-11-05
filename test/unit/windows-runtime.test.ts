import { strict as assert } from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { createProductionRuntimeProviders, runStdioServer } from '../../src/server.js';
import { createWindowsRuntimeProviders } from '../../src/windows/windows-runtime.js';

test('composes Windows discovery only from the native storage boundary', async () => {
  const runtime = createWindowsRuntimeProviders({
    listProfiles: () => [
      {
        profileId: 'production-api',
        host: 'private.example',
        port: 22,
        user: 'deploy',
        authMode: 'agent-key',
        approvedKnownHostsReference: 'known-hosts://production-api',
        expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
      },
    ],
  });
  assert.deepEqual(await runtime.approvedProfileListingProvider.listApprovedProfiles(), [
    { profileId: 'production-api', classification: 'operator-approved' },
  ]);
  assert.equal(runtime.connectionValidationProvider, undefined);
});

test('does not advertise validate_connection while agent-key cannot consume the opaque native snapshot', async () => {
  const runtime = createWindowsRuntimeProviders({ listProfiles: () => [] });
  const input = new PassThrough();
  const output = new PassThrough();
  const server = runStdioServer({ input, output, errorOutput: new PassThrough(), installSignalHandlers: false, ...runtime });
  const initialized = once(output, 'data');
  input.write(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}\n',
  );
  await initialized;
  const listed = once(output, 'data');
  input.write('{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n');
  const [response] = await listed;
  const tools = JSON.parse(String(response)) as { result: { tools: Array<{ name: string }> } };
  assert.deepEqual(
    tools.result.tools.map(({ name }) => name),
    ['list_approved_profiles'],
  );
  input.end();
  await server;
});

test('keeps unsupported and unknown platforms fail closed', () => {
  let composed = 0;
  const factory = () => {
    composed += 1;
    return createWindowsRuntimeProviders({ listProfiles: () => [] });
  };
  assert.deepEqual(createProductionRuntimeProviders('win32', false, factory), {});
  assert.deepEqual(createProductionRuntimeProviders('freebsd', true, factory), {});
  assert.equal(composed, 0);
});

test('selects the injected Windows runtime only on a supported host', () => {
  const expected = createWindowsRuntimeProviders({ listProfiles: () => [] });
  let composed = 0;
  const selected = createProductionRuntimeProviders('win32', true, () => {
    composed += 1;
    return expected;
  });
  assert.equal(selected, expected);
  assert.equal(composed, 1);
});

test('does not advertise tools when Windows runtime support is unavailable', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const server = runStdioServer({
    input,
    output,
    errorOutput: new PassThrough(),
    installSignalHandlers: false,
    ...createProductionRuntimeProviders('win32', false),
  });
  const initialized = once(output, 'data');
  input.write(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}\n',
  );
  await initialized;
  const listed = once(output, 'data');
  input.write('{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n');
  const [response] = await listed;
  const tools = JSON.parse(String(response)) as { result: { tools: unknown[] } };
  assert.deepEqual(tools.result.tools, []);
  input.end();
  await server;
});
