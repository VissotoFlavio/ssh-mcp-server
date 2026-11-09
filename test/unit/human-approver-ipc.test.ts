import assert from 'node:assert/strict';
import test from 'node:test';

import { IpcHumanSudoApprovalProvider } from '../../src/execution/human-approver-ipc.js';

test('IPC approval carries operation and immutable identity internally', async () => {
  let received: unknown;
  const provider = new IpcHumanSudoApprovalProvider({ approve: async (request) => ((received = request), true) }, 'posix', () => ({
    operationId: '0123456789abcdef0123456789abcdef',
    leaseIdentityDigest: 'identity-digest',
    identity: {
      host: 'private.example',
      port: 22,
      user: 'deploy',
      expectedHostFingerprint: 'SHA256:host',
      authMode: 'agent-key',
      approvedKnownHostsReference: 'known-hosts://production-api',
    },
  }));
  assert.equal(
    await provider.approve(
      { profileId: 'production-api', command: 'sudo', args: ['id'], timeoutMs: 1000, maxOutputBytes: 100 },
      new AbortController().signal,
    ),
    true,
  );
  assert.equal((received as { version: number }).version, 1);
  assert.equal((received as { operationId: string }).operationId, '0123456789abcdef0123456789abcdef');
  assert.equal((received as { leaseIdentityDigest: string }).leaseIdentityDigest, 'identity-digest');
});

test('IPC approval fails closed on cancellation', async () => {
  const provider = new IpcHumanSudoApprovalProvider({ approve: async () => true }, 'windows', () => {
    throw new Error('must not be called');
  });
  const controller = new AbortController();
  controller.abort();
  assert.equal(
    await provider.approve({ profileId: 'production-api', command: 'sudo', args: ['id'], timeoutMs: 1000, maxOutputBytes: 100 }, controller.signal),
    false,
  );
});
