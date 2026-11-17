import assert from 'node:assert/strict';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { createExecutionAuthorization } from '../../src/execution/remote-command-execution.js';
import { RemoteFileUploadProvider, uploadRemoteFileToolName } from '../../src/execution/remote-file-upload.js';
import { requestActionApprovalToolName, runStdioServer } from '../../src/server.js';

const profile = {
  profileId: 'production-api',
  host: 'private.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
  authMode: 'agent-key' as const,
  approvedKnownHostsReference: 'known-hosts://production-api',
};

function requestResponse(input: PassThrough, output: PassThrough, request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = once(output, 'data');
  input.write(`${JSON.stringify(request)}\n`);
  return response.then(([chunk]) => JSON.parse(String(chunk)) as Record<string, unknown>);
}

test('registers one client-confirmed upload tool and returns a structured verified upload result', async () => {
  const provider = new RemoteFileUploadProvider({
    connectionValidation: { validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }) },
    authorizationProvider: { authorize: async () => createExecutionAuthorization(profile, Date.now() + 60_000) },
    transport: {
      upload: async (request) => {
        await request.onUploadHandoff?.();
        return { uploadedBytes: request.content.length, sha256: request.sha256 };
      },
    },
    auditJournal: {
      digestArguments: async () => 'a'.repeat(64),
      begin: async (intent) => ({
        operationId: intent.operationId,
        approval: async () => undefined,
        handoff: async () => undefined,
        finish: async () => undefined,
      }),
    },
  });
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  const runtime = runStdioServer({ input, output, errorOutput: errors, installSignalHandlers: false, remoteFileUploadProvider: provider });
  const payload = Buffer.from('sensitive=value\n').toString('base64');

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
  });
  const tools = await requestResponse(input, output, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const listed = (tools.result as { tools: readonly { name: string; annotations?: unknown; outputSchema?: { type?: string } }[] }).tools;
  assert.deepEqual(
    listed.map((tool) => tool.name),
    [requestActionApprovalToolName, uploadRemoteFileToolName],
  );
  for (const tool of listed) {
    assert.deepEqual(tool.annotations, { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });
    assert.equal(tool.outputSchema?.type, 'object');
  }

  const approval = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: requestActionApprovalToolName,
      arguments: { action: 'file-upload', profileId: profile.profileId, remotePath: '/opt/app/.env', contentBase64: payload },
    },
  });
  const approvalPayload = JSON.parse((approval.result as { content: readonly { text: string }[] }).content[0].text) as { capability: string };
  const upload = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: {
      name: uploadRemoteFileToolName,
      arguments: {
        profileId: profile.profileId,
        remotePath: '/opt/app/.env',
        contentBase64: payload,
        approvalCapability: approvalPayload.capability,
      },
    },
  });
  const result = upload.result as { content: readonly { text: string }[]; structuredContent: Record<string, unknown> };
  assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent);
  assert.equal(result.structuredContent.outcome, 'success');
  assert.equal(result.structuredContent.integrity, 'verified');
  assert.equal(JSON.stringify(upload).includes('sensitive=value'), false);

  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});
