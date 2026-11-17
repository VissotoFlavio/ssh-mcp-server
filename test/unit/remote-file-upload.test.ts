import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import type {
  ExecutionAuditApproval,
  ExecutionAuditFinished,
  ExecutionAuditIntent,
  ExecutionAuditJournal,
} from '../../src/execution/execution-audit-journal.js';
import { RemoteExecutionError, createExecutionAuthorization } from '../../src/execution/remote-command-execution.js';
import {
  RemoteFileUploadProvider,
  type RemoteFileUploadTransport,
  type RemoteFileUploadTransportRequest,
} from '../../src/execution/remote-file-upload.js';

const profile = {
  profileId: 'production-api',
  host: 'private.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
  authMode: 'agent-key' as const,
  approvedKnownHostsReference: 'known-hosts://production-api',
};

const input = {
  profileId: 'production-api',
  remotePath: '/srv/application/.env',
  contentBase64: Buffer.from('TOP_SECRET=value\n').toString('base64'),
};

function authorization() {
  return createExecutionAuthorization(profile, Date.now() + 60_000);
}

function provider(transport: RemoteFileUploadTransport, journal?: ExecutionAuditJournal): RemoteFileUploadProvider {
  const auditJournal: ExecutionAuditJournal = journal ?? {
    digestArguments: async () => 'a'.repeat(64),
    begin: async (intent: ExecutionAuditIntent) => ({
      operationId: intent.operationId,
      approval: async (_state: ExecutionAuditApproval['state']) => undefined,
      handoff: async () => undefined,
      finish: async (_event: ExecutionAuditFinished) => undefined,
    }),
  };
  return new RemoteFileUploadProvider({
    connectionValidation: { validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }) },
    authorizationProvider: { authorize: async () => authorization() },
    transport,
    auditJournal,
  });
}

async function approvedInput(uploadProvider: RemoteFileUploadProvider, value = input) {
  const approval = await uploadProvider.requestActionApproval(value);
  assert.equal(approval.approved, true);
  return { ...value, approvalCapability: approval.capability };
}

test('uploads once through the client-confirmed mutating tool and requires a transport-confirmed digest', async () => {
  let received: RemoteFileUploadTransportRequest | undefined;
  const uploadProvider = provider({
    upload: async (request) => {
      received = request;
      await request.onUploadHandoff?.();
      return { uploadedBytes: request.content.length, sha256: request.sha256 };
    },
  });
  const uploaded = await uploadProvider.upload(await approvedInput(uploadProvider));
  assert.equal(uploaded.outcome, 'success');
  assert.equal(uploaded.integrity, 'verified');
  assert.equal(received?.remotePath, input.remotePath);
  assert.equal(received?.content.toString('utf8'), 'TOP_SECRET=value\n');
});

test('records only a redacted destination in the durable upload journal', async () => {
  const intents: Record<string, unknown>[] = [];
  const events: Record<string, unknown>[] = [];
  const journal = {
    digestArguments: async (args: readonly string[]) => {
      assert.equal(args[0], input.remotePath);
      return 'a'.repeat(64);
    },
    begin: async (intent: ExecutionAuditIntent) => {
      intents.push(intent as unknown as Record<string, unknown>);
      return {
        operationId: intent.operationId,
        approval: async (state: ExecutionAuditApproval['state']) => {
          events.push({ event: 'approval', state });
        },
        handoff: async () => {
          events.push({ event: 'handoff' });
        },
        finish: async (event: ExecutionAuditFinished) => {
          events.push({ event: 'finished', ...event });
        },
      };
    },
  };
  const uploadProvider = provider(
    {
      upload: async (request) => {
        await request.onUploadHandoff?.();
        return { uploadedBytes: request.content.length, sha256: request.sha256 };
      },
    },
    journal,
  );
  await uploadProvider.upload(await approvedInput(uploadProvider));

  assert.deepEqual(intents[0].args, [
    '[redacted]',
    createHash('sha256').update(Buffer.from('TOP_SECRET=value\n')).digest('hex'),
    String(Buffer.from('TOP_SECRET=value\n').length),
  ]);
  assert.equal(JSON.stringify(intents).includes(input.remotePath), false);
  assert.equal(JSON.stringify(intents).includes('TOP_SECRET'), false);
  assert.deepEqual(
    events.map((event) => event.event),
    ['handoff', 'finished'],
  );
});

test('returns unknown after an upload handoff is interrupted', async () => {
  const uploadProvider = provider({
    upload: async (request) => {
      await request.onUploadHandoff?.();
      throw new RemoteExecutionError('timeout', 'timed out');
    },
  });
  const uploaded = await uploadProvider.upload(await approvedInput(uploadProvider));
  assert.equal(uploaded.outcome, 'unknown');
  assert.equal(uploaded.code, 'outcome-unknown');
});

test('rejects a non-canonical Base64 payload before remote authorization', async () => {
  const uploadProvider = provider({ upload: async () => ({ uploadedBytes: 0, sha256: '' }) });
  const uploaded = await uploadProvider.upload({ ...input, contentBase64: 'V A==' });
  assert.equal(uploaded.code, 'invalid-input');
});

test('fails closed before transport when a durable audit journal is unavailable', async () => {
  let uploaded = false;
  const uploadProvider = new RemoteFileUploadProvider({
    connectionValidation: { validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }) },
    authorizationProvider: { authorize: async () => authorization() },
    transport: {
      upload: async () => {
        uploaded = true;
        return { uploadedBytes: 0, sha256: '' };
      },
    },
  });
  const uploadedResult = await uploadProvider.upload(await approvedInput(uploadProvider));
  assert.equal(uploadedResult.code, 'execution-audit-unavailable');
  assert.equal(uploaded, false);
});
