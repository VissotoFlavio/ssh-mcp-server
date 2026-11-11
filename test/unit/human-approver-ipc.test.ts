import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  approvedIdentity: {
    host: 'private.example',
    port: 22,
    user: 'deploy',
    expectedHostFingerprint: 'SHA256:host',
    authMode: 'agent-key' as const,
    approvedKnownHostsReference: 'known-hosts://production-api',
  },
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

function encodeFrame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function requestMac(request: HumanApproverIpcRequest, secret: Buffer): string {
  const fields = [
    request.version,
    request.type,
    request.nonce,
    request.requestDigest,
    request.operationId,
    request.leaseIdentityDigest,
    request.request.profileId,
    request.request.command,
    request.request.args,
    request.request.timeoutMs,
    request.request.maxOutputBytes,
    request.request.presentation,
  ];
  return createHmac('sha256', secret)
    .update(`ssh-mcp-approver/request/v1\0${JSON.stringify(fields)}`)
    .digest('hex');
}

function responseMac(response: HumanApproverIpcResponse, secret: Buffer): string {
  const fields = [response.version, response.type, response.nonce, response.requestDigest, response.approved];
  return createHmac('sha256', secret)
    .update(`ssh-mcp-approver/response/v1\0${JSON.stringify(fields)}`)
    .digest('hex');
}

test('IPC approval carries operation and immutable destination internally', async () => {
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
  assert.deepEqual((received as { request: { presentation: unknown } }).request.presentation, {
    host: 'private.example',
    port: 22,
    user: 'deploy',
    expectedHostFingerprint: 'SHA256:host',
    authMode: 'agent-key',
    approvedKnownHostsReference: 'known-hosts://production-api',
  });
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

test('IPC accepts a bound injected success with destination only inside the local approver request', async () => {
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
  assert.equal(received?.request.presentation.host, 'private.example');
  assert.equal(received?.request.presentation.approvedKnownHostsReference, 'private-path');
});

test('production factory is unavailable on Windows without the authenticated native boundary', async () => {
  assert.equal(createLocalHumanSudoApprovalProvider('win32', {}), undefined);
});

test('POSIX IPC authenticates a fragmented response from a private Unix socket', { skip: process.platform === 'win32' }, async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'ssh-mcp-approver-'));
  const socketPath = join(root, 'approver.sock');
  const secretFile = join(root, 'approver.secret');
  const secret = randomBytes(32);
  await fs.writeFile(secretFile, secret, { mode: 0o600 });
  await fs.chmod(secretFile, 0o600);
  let received: Record<string, unknown> | undefined;
  const server = createServer((socket) => {
    let data = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length < 4) return;
      const length = data.readUInt32BE(0);
      if (data.length !== length + 4) return;
      received = JSON.parse(data.subarray(4).toString('utf8')) as Record<string, unknown>;
      assert.equal(received.requestMac, requestMac(received as unknown as HumanApproverIpcRequest, secret));
      const response: HumanApproverIpcResponse = {
        version: 1,
        type: 'approval-response',
        nonce: received.nonce as string,
        requestDigest: received.requestDigest as string,
        approved: true,
      };
      const frame = encodeFrame({ ...response, responseMac: responseMac(response, secret) });
      socket.write(frame.subarray(0, 3));
      setTimeout(() => socket.end(frame.subarray(3)), 5);
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    await fs.chmod(socketPath, 0o600);
    const provider = new IpcHumanSudoApprovalProvider(new UnixSocketHumanApproverChannel(socketPath, secretFile, 5000), 'posix');
    assert.equal(await provider.approve(baseRequest), true);
    assert.equal(received?.requestMac, requestMac(received as unknown as HumanApproverIpcRequest, secret));
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error === undefined ? resolve() : reject(error))));
    await fs.rm(root, { recursive: true, force: true });
  }
});
