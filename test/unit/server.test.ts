import { strict as assert } from 'node:assert';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { runStdioServer, serverName } from '../../src/server.js';

test('exposes the server name', () => {
  assert.equal(serverName, 'ssh-mcp-server');
});

test('speaks MCP over stdio and closes when its client disconnects', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  const runtime = runStdioServer({ input, output, errorOutput: errors });

  const response = once(output, 'data');
  input.write(
    `${JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      },
    })}\n`,
  );

  const [chunk] = await response;
  const message = JSON.parse(String(chunk));

  assert.equal(message.jsonrpc, '2.0');
  assert.equal(message.id, 1);
  assert.equal(message.result.serverInfo.name, serverName);
  assert.deepEqual(message.result.capabilities, {});

  input.end();
  await runtime;
  assert.equal(errors.readableLength, 0);
});

test('writes transport errors to stderr instead of stdout', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  const runtime = runStdioServer({ input, output, errorOutput: errors });
  let diagnostics = '';
  errors.on('data', (chunk) => {
    diagnostics += String(chunk);
  });

  const receivedError = once(errors, 'data');
  input.write('not JSON-RPC\n');
  await receivedError;
  input.end();
  await runtime;

  assert.equal(output.readableLength, 0);
  assert.match(diagnostics, /^MCP server error:/);
});
