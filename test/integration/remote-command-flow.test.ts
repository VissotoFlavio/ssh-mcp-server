import { strict as assert } from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import type { JsonSchemaType } from '@modelcontextprotocol/sdk/validation';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';

import { RemoteCommandExecutionProvider } from '../../src/execution/remote-command-execution.js';
import { createServer, runStdioServer } from '../../src/server.js';

function requestResponse(input: PassThrough, output: PassThrough, request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = once(output, 'data');
  input.write(`${JSON.stringify(request)}\n`);
  return response.then(([chunk]) => JSON.parse(String(chunk)) as Record<string, unknown>);
}

class LoopbackTransport implements Transport {
  peer?: LoopbackTransport;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  async start(): Promise<void> {}

  async send(message: JSONRPCMessage): Promise<void> {
    const peer = this.peer;
    if (peer?.onmessage === undefined) throw new Error('Loopback peer is not connected');
    queueMicrotask(() => peer.onmessage?.(message));
  }

  async close(): Promise<void> {
    this.onclose?.();
  }
}

function loopbackPair(): readonly [LoopbackTransport, LoopbackTransport] {
  const left = new LoopbackTransport();
  const right = new LoopbackTransport();
  left.peer = right;
  right.peer = left;
  return [left, right];
}

async function withMcpClient<T>(options: Parameters<typeof createServer>[0], run: (client: Client) => Promise<T>): Promise<T> {
  const server = createServer(options);
  const [clientTransport, serverTransport] = loopbackPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'contract-test-client', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
  try {
    return await run(client);
  } finally {
    await client.close();
    await server.close();
  }
}

interface ContractToolResult {
  readonly content: readonly { readonly type: string; readonly text?: string }[];
  readonly structuredContent?: Record<string, unknown>;
  readonly isError?: boolean;
}

function contractResult(result: Awaited<ReturnType<Client['callTool']>>): ContractToolResult {
  if (!('content' in result)) throw new Error('Expected a non-task MCP tool result');
  return result as ContractToolResult;
}

function structuredPayload(result: ContractToolResult): Record<string, unknown> {
  assert.notEqual(result.structuredContent, undefined);
  return result.structuredContent as Record<string, unknown>;
}

function textPayload(result: ContractToolResult): unknown {
  const text = result.content.find((item) => item.type === 'text')?.text;
  assert.notEqual(text, undefined);
  return JSON.parse(text!);
}

test('registers and routes remote execution without a production endpoint', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let audit = '';
  errors.on('data', (chunk) => {
    audit += String(chunk);
  });
  const profile = {
    profileId: 'test-profile',
    host: 'test.invalid',
    port: 22,
    user: 'operator',
    expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
    authMode: 'agent-key' as const,
    approvedKnownHostsReference: 'known-hosts://test-profile',
  };
  const provider = new RemoteCommandExecutionProvider({
    profiles: {
      getProfile: async () => profile,
    },
    connectionValidation: {
      validateConnection: async () => ({ profileId: 'test-profile', ready: true as const }),
      authorizeExecution: async () => ({ profile }),
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
  });

  await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
  });
  const tools = await requestResponse(input, output, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const listed = (
    tools.result as {
      tools: Array<{
        name: string;
        annotations?: { destructiveHint?: boolean; readOnlyHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
        outputSchema?: { type?: string };
      }>;
    }
  ).tools;
  const executionTool = listed.find((tool) => tool.name === 'execute_remote_command');
  assert.deepEqual(executionTool?.annotations, { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });
  assert.equal(executionTool?.outputSchema?.type, 'object');

  const result = await requestResponse(input, output, {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: {
      name: 'execute_remote_command',
      arguments: { profileId: 'test-profile', command: 'sudo', args: ['id'] },
    },
  });
  const resultPayload = JSON.parse((result.result as { content: Array<{ text: string }> }).content[0].text) as Record<string, unknown>;
  assert.equal(resultPayload.profileId, 'test-profile');
  assert.equal(resultPayload.outcome, 'success');
  assert.equal(resultPayload.code, 'success');
  assert.match(String(resultPayload.operationId), /^[a-f0-9]{32}$/u);
  assert.equal(resultPayload.stdout, 'test-output');
  assert.deepEqual((result.result as { structuredContent: unknown }).structuredContent, resultPayload);

  input.end();
  await runtime;
  assert.match(audit, /remote-command-audit-event/u);
});

test('MCP SDK 1.x validates structured output and preserves legacy text errors', async () => {
  let failDiscovery = false;
  const profile = {
    profileId: 'test-profile',
    host: 'test.invalid',
    port: 22,
    user: 'operator',
    expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
    authMode: 'agent-key' as const,
    approvedKnownHostsReference: 'known-hosts://test-profile',
  };
  const remoteProvider = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => profile },
    connectionValidation: {
      validateConnection: async () => ({ profileId: 'test-profile', ready: true as const }),
      authorizeExecution: async () => ({ profile }),
    },
    transport: {
      async execute() {
        return { exitCode: 0, stdout: 'test-output', stderr: '', outputTruncated: false };
      },
    },
  });
  const readiness = {
    getWindowsReadinessStatus: () => ({
      kind: 'windows-readiness-status' as const,
      version: 1 as const,
      runtime: 'ready' as const,
      registry: 'ready' as const,
      filesystem: 'ready' as const,
      configuration: 'ready' as const,
      knownHosts: 'ready' as const,
      credentials: 'not-checked' as const,
      validationProvider: 'ready' as const,
      remoteAuthentication: 'not-checked' as const,
    }),
  };

  await withMcpClient(
    {
      approvedProfileListingProvider: {
        async listApprovedProfiles() {
          if (failDiscovery) throw new Error('legacy provider failure');
          return [{ profileId: 'test-profile', classification: 'operator-approved' as const }];
        },
      },
      connectionValidationProvider: {
        async validateConnection() {
          return { profileId: 'test-profile', ready: true as const };
        },
      },
      windowsReadinessStatusProvider: readiness,
      remoteCommandExecutionProvider: remoteProvider,
    },
    async (client) => {
      const listed = await client.listTools();
      assert.deepEqual(
        listed.tools.map((tool) => tool.name),
        ['list_approved_profiles', 'validate_connection', 'get_windows_readiness_status', 'execute_remote_command'],
      );
      for (const tool of listed.tools) {
        assert.equal(tool.outputSchema?.type, 'object');
        assert.equal((tool.outputSchema as { additionalProperties?: boolean }).additionalProperties, false);
      }

      const list = contractResult(await client.callTool({ name: 'list_approved_profiles', arguments: {} }));
      assert.deepEqual(structuredPayload(list), { profiles: [{ profileId: 'test-profile', classification: 'operator-approved' }] });
      assert.deepEqual(textPayload(list), structuredPayload(list));

      const windows = contractResult(await client.callTool({ name: 'get_windows_readiness_status', arguments: {} }));
      assert.equal(structuredPayload(windows).remoteAuthentication, 'not-checked');
      assert.deepEqual(textPayload(windows), structuredPayload(windows));

      const validation = contractResult(await client.callTool({ name: 'validate_connection', arguments: { profileId: 'test-profile' } }));
      assert.deepEqual(structuredPayload(validation), { profileId: 'test-profile', ready: true });
      assert.deepEqual(textPayload(validation), structuredPayload(validation));

      const execution = contractResult(
        await client.callTool({
          name: 'execute_remote_command',
          arguments: { profileId: 'test-profile', command: 'sudo', args: ['id'] },
        }),
      );
      assert.equal(structuredPayload(execution).outcome, 'success');
      assert.deepEqual(textPayload(execution), structuredPayload(execution));

      failDiscovery = true;
      const legacyError = contractResult(await client.callTool({ name: 'list_approved_profiles', arguments: {} }));
      assert.equal(legacyError.isError, true);
      assert.equal(legacyError.structuredContent, undefined);
      assert.deepEqual(legacyError.content, [{ type: 'text', text: 'Approved profile discovery is unavailable.' }]);

      const validator = new AjvJsonSchemaValidator();
      const validateSchema = (name: string) => {
        const schema = listed.tools.find((tool) => tool.name === name)?.outputSchema;
        assert.notEqual(schema, undefined);
        return validator.getValidator(schema as unknown as JsonSchemaType);
      };
      const validateList = validateSchema('list_approved_profiles');
      assert.equal(validateList({ profiles: [] }).valid, true);
      assert.equal(validateList({ profiles: [{ profileId: 'test-profile' }] }).valid, false);
      assert.equal(validateList({ profiles: [], extra: true }).valid, false);

      const validateWindows = validateSchema('get_windows_readiness_status');
      assert.equal(validateWindows(structuredPayload(windows)).valid, true);
      assert.equal(validateWindows({ ...structuredPayload(windows), runtime: 'unknown' }).valid, false);

      const validateConnection = validateSchema('validate_connection');
      assert.equal(validateConnection(structuredPayload(validation)).valid, true);
      assert.equal(validateConnection({ ready: true }).valid, false);
      assert.equal(validateConnection({ ready: false, outcome: 'failure', code: 'not-a-code' }).valid, false);

      const validateRemote = validateSchema('execute_remote_command');
      assert.equal(validateRemote(structuredPayload(execution)).valid, true);
      const missingOperationId = { ...structuredPayload(execution) };
      delete missingOperationId.operationId;
      assert.equal(validateRemote(missingOperationId).valid, false);
      assert.equal(validateRemote({ ...structuredPayload(execution), outcome: 'not-an-outcome' }).valid, false);
    },
  );
});
