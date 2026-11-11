import assert from 'node:assert/strict';
import test from 'node:test';

import {
  IpcHumanSudoApprovalProvider,
  UnixSocketHumanApproverChannel,
  createLocalHumanSudoApprovalProvider,
  type HumanApproverIpcRequest,
  type HumanApproverIpcResponse,
} from '../../src/execution/human-approver-ipc.js';

const baseRequest = {
  profileId: 'production-api',
  command: 'sudo',
  args: ['id'],
  timeoutMs: 1000,
  maxOutputBytes: 100,
  operationId: '0123456789abcdef0123456789abcdef',
  leaseIdentityDigest: 'identity-digest',
};

function validResponse(request: HumanApproverIpcRequest, approved = true): HumanApproverIpcResponse {
  return {
    version: 1,
    type: 'approval-response',
    nonce: request.nonce,
    requestDigest: request.requestDigest,
    approved,
  };
}

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

test('IPC rejects an unavailable local peer', async () => {
  const provider = new IpcHumanSudoApprovalProvider(new UnixSocketHumanApproverChannel('/tmp/ssh-mcp-approver-does-not-exist'), 'posix');
  assert.equal(await provider.approve(baseRequest), false);
});

test('IPC rejects an invalid protocol response', async () => {
  const provider = new IpcHumanSudoApprovalProvider(
    { approve: async () => ({ version: 1, type: 'approval-response', approved: true }) as never },
    'posix',
  );
  assert.equal(await provider.approve(baseRequest), false);
});

test('IPC rejects a response for an altered request', async () => {
  const provider = new IpcHumanSudoApprovalProvider(
    {
      approve: async (request) => ({ ...validResponse(request), requestDigest: '0'.repeat(64) }),
    },
    'posix',
  );
  assert.equal(await provider.approve(baseRequest), false);
});

test('IPC rejects a replayed response nonce', async () => {
  let replay: HumanApproverIpcResponse | undefined;
  const provider = new IpcHumanSudoApprovalProvider(
    {
      approve: async (request) => {
        replay ??= validResponse(request);
        return replay;
      },
    },
    'posix',
  );
  assert.equal(await provider.approve(baseRequest), true);
  assert.equal(await provider.approve(baseRequest), false);
});

test('IPC cancellation is forwarded to the local channel', async () => {
  let cancelled = false;
  const provider = new IpcHumanSudoApprovalProvider(
    {
      approve: async (_request, signal) =>
        new Promise<boolean>((_resolve, reject) => {
          signal?.addEventListener(
            'abort',
            () => {
              cancelled = true;
              reject(new Error('cancelled'));
            },
            { once: true },
          );
        }),
    },
    'posix',
  );
  const controller = new AbortController();
  const approval = provider.approve(baseRequest, controller.signal);
  controller.abort();
  assert.equal(await approval, false);
  assert.equal(cancelled, true);
});

test('IPC accepts a bound injected success without exposing identity details', async () => {
  let received: HumanApproverIpcRequest | undefined;
  const provider = new IpcHumanSudoApprovalProvider(
    {
      approve: async (request) => {
        received = request;
        return validResponse(request);
      },
    },
    'posix',
  );
  assert.equal(
    await provider.approve({
      ...baseRequest,
      approvedIdentity: {
        host: 'private.example',
        port: 22,
        user: 'deploy',
        expectedHostFingerprint: 'secret',
        authMode: 'agent-key',
        approvedKnownHostsReference: 'private-path',
      },
    }),
    true,
  );
  assert.equal(JSON.stringify(received).includes('private.example'), false);
  assert.equal(JSON.stringify(received).includes('private-path'), false);
});

test('production factory is unavailable on Windows without the authenticated native boundary', async () => {
  assert.equal(createLocalHumanSudoApprovalProvider('win32', {}), undefined);
});
