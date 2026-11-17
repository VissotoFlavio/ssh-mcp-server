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
  type FileUploadApprovalRequest,
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

function provider(
  transport: RemoteFileUploadTransport,
  approve: (request: FileUploadApprovalRequest) => Promise<true | false | 'unavailable'> = async () => true,
  journal?: ExecutionAuditJournal,
): RemoteFileUploadProvider {
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
    humanApproval: { approve },
    transport,
    auditJournal,
  });
}

test('shows only destination, digest, and size to the upload approver before uploading', async () => {
  let approvalRequest: FileUploadApprovalRequest | undefined;
  let uploads = 0;
  const uploadProvider = provider(
    {
      upload: async () => {
        uploads += 1;
        return { uploadedBytes: Buffer.from('TOP_SECRET=value\n').length, sha256: 'ignored' };
      },
    },
    async (request) => {
      approvalRequest = request;
      return true;
    },
  );

  const approval = await uploadProvider.requestApproval(input);
  assert.equal(approval.approved, true);
  assert.equal(approvalRequest?.remotePath, input.remotePath);
  assert.equal(approvalRequest?.sizeBytes, Buffer.from('TOP_SECRET=value\n').length);
  assert.equal(approvalRequest?.sha256.length, 64);
  assert.equal('content' in (approvalRequest ?? {}), false);

  const withoutToken = await uploadProvider.upload(input);
  assert.equal(withoutToken.code, 'approval-required');
  assert.equal(uploads, 0);
});

test('binds approval to destination and content and never starts an altered upload', async () => {
  let uploaded = false;
  const uploadProvider = provider({ upload: async () => ((uploaded = true), { uploadedBytes: 0, sha256: '' }) });
  const approval = await uploadProvider.requestApproval(input);
  const altered = await uploadProvider.upload({ ...input, remotePath: '/etc/application/.env', approvalToken: approval.capability });
  assert.equal(altered.code, 'approval-altered');
  assert.equal(uploaded, false);
});

test('uploads an approved file and requires a transport-confirmed digest', async () => {
  let received: RemoteFileUploadTransportRequest | undefined;
  const uploadProvider = provider({
    upload: async (request) => {
      received = request;
      await request.onUploadHandoff?.();
      return { uploadedBytes: request.content.length, sha256: request.sha256 };
    },
  });
  const approval = await uploadProvider.requestApproval(input);
  const uploaded = await uploadProvider.upload({ ...input, approvalToken: approval.capability });
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
    async () => true,
    journal,
  );
  const approval = await uploadProvider.requestApproval(input);
  await uploadProvider.upload({ ...input, approvalToken: approval.capability });

  assert.deepEqual(intents[0].args, [
    '[redacted]',
    createHash('sha256').update(Buffer.from('TOP_SECRET=value\n')).digest('hex'),
    String(Buffer.from('TOP_SECRET=value\n').length),
  ]);
  assert.equal(JSON.stringify(intents).includes(input.remotePath), false);
  assert.equal(JSON.stringify(intents).includes('TOP_SECRET'), false);
  assert.deepEqual(
    events.map((event) => event.event),
    ['approval', 'handoff', 'finished'],
  );
});

test('returns unknown after an upload handoff is interrupted', async () => {
  const uploadProvider = provider({
    upload: async (request) => {
      await request.onUploadHandoff?.();
      throw new RemoteExecutionError('timeout', 'timed out');
    },
  });
  const approval = await uploadProvider.requestApproval(input);
  const uploaded = await uploadProvider.upload({ ...input, approvalToken: approval.capability });
  assert.equal(uploaded.outcome, 'unknown');
  assert.equal(uploaded.code, 'outcome-unknown');
});

test('rejects a non-canonical Base64 payload before requesting approval', async () => {
  const uploadProvider = provider({ upload: async () => ({ uploadedBytes: 0, sha256: '' }) });
  const approval = await uploadProvider.requestApproval({ ...input, contentBase64: 'V A==' });
  assert.deepEqual(approval, { approved: false, code: 'invalid-input', operationId: approval.operationId });
});

test('fails closed before transport when a durable audit journal is unavailable', async () => {
  let uploaded = false;
  const uploadProvider = new RemoteFileUploadProvider({
    connectionValidation: { validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }) },
    authorizationProvider: { authorize: async () => authorization() },
    humanApproval: { approve: async () => true },
    transport: {
      upload: async () => {
        uploaded = true;
        return { uploadedBytes: 0, sha256: '' };
      },
    },
  });
  const approval = await uploadProvider.requestApproval(input);
  const uploadedResult = await uploadProvider.upload({ ...input, approvalToken: approval.capability });
  assert.equal(uploadedResult.code, 'execution-audit-unavailable');
  assert.equal(uploaded, false);
});
