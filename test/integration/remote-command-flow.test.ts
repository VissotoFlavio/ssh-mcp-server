import { strict as assert } from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { RemoteCommandExecutionProvider } from '../../src/execution/remote-command-execution.js';
import { runStdioServer } from '../../src/server.js';

function requestResponse(input: PassThrough, output: PassThrough, request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = once(output, 'data');
  input.write(`${JSON.stringify(request)}\n`);
  return response.then(([chunk]) => JSON.parse(String(chunk)) as Record<string, unknown>);
}

test('registers and routes remote execution without a production endpoint', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });
  const provider = new RemoteCommandExecutionProvider({
    profiles: {
      getProfile: async () => ({
        profileId: 'test-profile',
        host: 'test.invalid',
        port: 22,
        user: 'operator',
        expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
        authMode: 'agent-key',
        approvedKnownHostsReference: 'known-hosts://test-profile',
      }),
    },
    connectionValidation: {
      validateConnection: async () => ({ profileId: 'test-profile', ready: true as const }),
    },
    transport: {
      async execute() {
        return { exitCode: 0, stdout: 'test-output', stderr: '', outputTruncated: false };
      },
    },
  });
  const runtime = runStdioServer({
    input,
    output,
    errorOutput: errors,
    installSignalHandlers: false,
    remoteCommandExecutionProvider: provider,
    humanSudoApprovalProvider: { approve: async () => true },
  });

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
  });
  const tools = await requestResponse(input, output, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const listed = (tools.result as { tools: Array<{ name: string; annotations?: { destructiveHint?: boolean; readOnlyHint?: boolean } }> }).tools;
  const executionTool = listed.find((tool) => tool.name === 'execute_remote_command');
  assert.equal(executionTool?.annotations?.destructiveHint, true);
  const approvalTool = listed.find((tool) => tool.name === 'request_sudo_approval');
  assert.equal(approvalTool?.annotations?.readOnlyHint, false);

  const approval = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'request_sudo_approval', arguments: { profileId: 'test-profile', command: 'sudo', args: ['id'] } },
  });
  const approvalPayload = JSON.parse((approval.result as { content: Array<{ text: string }> }).content[0].text) as {
    approved: boolean;
    token?: string;
  };
  assert.equal(approvalPayload.approved, true);
  assert.equal(typeof approvalPayload.token, 'string');

  const result = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: {
      name: 'execute_remote_command',
      arguments: { profileId: 'test-profile', command: 'sudo', args: ['id'], approvalToken: approvalPayload.token },
    },
  });
  assert.deepEqual(JSON.parse((result.result as { content: Array<{ text: string }> }).content[0].text), {
    profileId: 'test-profile',
    outcome: 'success',
    code: 'success',
    exitCode: 0,
    stdout: 'test-output',
    stderr: '',
    outputTruncated: false,
  });

  input.end();
  await runtime;
  assert.match(audit, /remote-command-audit-event/u);
});
