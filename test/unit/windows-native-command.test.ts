import assert from 'node:assert/strict';
import test from 'node:test';

import { createExecutionAuthorization, RemoteExecutionError } from '../../src/execution/remote-command-execution.js';
import { WindowsNativeAgentCommandTransport } from '../../src/windows/windows-native-command.js';

const request = {
  profile: {
    profileId: 'production-api',
    host: 'private.example',
    port: 22,
    user: 'deploy',
    expectedHostFingerprint: 'SHA256:host',
    authMode: 'agent-key' as const,
    approvedKnownHostsReference: 'known-hosts://production-api',
  },
  command: 'id',
  args: [],
  timeoutMs: 1000,
  maxOutputBytes: 1000,
};

test('Windows agent-key command path fails closed without the native boundary', async () => {
  await assert.rejects(
    new WindowsNativeAgentCommandTransport(undefined).execute(request),
    (error: unknown) => error instanceof RemoteExecutionError && error.code === 'windows-agent-key-unsupported',
  );
});

test('Windows native command boundary receives only opaque capability and fixed request data', async () => {
  let seen: unknown;
  const authorization = createExecutionAuthorization(request.profile, Date.now() + 60_000, Date.now, async (work) => work({ opaque: true }));
  const result = await new WindowsNativeAgentCommandTransport({
    execute: async (capability, nativeRequest) => {
      seen = { capability, nativeRequest };
      return { exitCode: 0, stdout: 'ok', stderr: '', outputTruncated: false };
    },
  }).execute({ ...request, authorization });
  assert.equal(result.stdout, 'ok');
  assert.equal((seen as { nativeRequest: { command: string } }).nativeRequest.command, 'id');
  assert.equal((seen as { capability: { opaque: boolean } }).capability.opaque, true);
});

test('Windows native command preserves stable transport classifications', async () => {
  for (const code of ['host-key-failure', 'authentication-failure', 'connection-failure', 'remote-failure'] as const) {
    const authorization = createExecutionAuthorization(request.profile, Date.now() + 60_000, Date.now, async () => {
      throw Object.assign(new Error('native failure'), { code });
    });
    await assert.rejects(
      new WindowsNativeAgentCommandTransport({
        execute: async () => ({ exitCode: 0, stdout: '', stderr: '', outputTruncated: false }),
      }).execute({ ...request, authorization }),
      (error: unknown) => error instanceof RemoteExecutionError && error.code === code,
    );
  }
});

test('Windows native output overflow is an unknown outcome after command handoff', async () => {
  const authorization = createExecutionAuthorization(request.profile, Date.now() + 60_000, Date.now, async () => {
    throw Object.assign(new Error('native output limit'), { code: 'output-limit' });
  });
  await assert.rejects(
    new WindowsNativeAgentCommandTransport({
      execute: async () => ({ exitCode: 0, stdout: '', stderr: '', outputTruncated: true }),
    }).execute({ ...request, authorization }),
    (error: unknown) => error instanceof RemoteExecutionError && error.code === 'outcome-unknown',
  );
});
