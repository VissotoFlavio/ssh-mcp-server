import process from 'node:process';
import type { Readable, Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

export const serverName = 'ssh-mcp-server';
export const serverVersion = '0.1.0';

export interface StdioServerOptions {
  input?: Readable;
  output?: Writable;
  errorOutput?: Writable;
  installSignalHandlers?: boolean;
}

export function createServer(): Server {
  return new Server(
    { name: serverName, version: serverVersion },
    { capabilities: {} },
  );
}

/**
 * Runs one MCP server over stdio until its client disconnects or the process is
 * asked to stop. The SDK transport is the sole writer to the protocol stream.
 */
export async function runStdioServer({
  input = process.stdin,
  output = process.stdout,
  errorOutput = process.stderr,
  installSignalHandlers = input === process.stdin,
}: StdioServerOptions = {}): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport(input, output);

  let completeLifecycle: () => void;
  const lifecycleComplete = new Promise<void>((resolve) => {
    completeLifecycle = resolve;
  });
  let completed = false;
  let closing = false;

  const reportError = (error: unknown): void => {
    const message = error instanceof Error ? error.message : String(error);
    errorOutput.write(`MCP server error: ${message}\n`);
  };

  const cleanup = (): void => {
    input.off('end', closeOnClientDisconnect);
    input.off('close', closeOnClientDisconnect);

    for (const [signal, handler] of signalHandlers) {
      process.off(signal, handler);
    }
  };

  const finish = (): void => {
    if (completed) {
      return;
    }

    completed = true;
    cleanup();
    completeLifecycle();
  };

  const close = async (): Promise<void> => {
    if (closing || completed) {
      return;
    }

    closing = true;
    try {
      await server.close();
    } catch (error) {
      reportError(error);
      finish();
    }
  };

  const closeOnClientDisconnect = (): void => {
    void close();
  };

  const signalHandlers: Array<[NodeJS.Signals, () => void]> = installSignalHandlers
    ? [
        ['SIGINT', closeOnClientDisconnect],
        ['SIGTERM', closeOnClientDisconnect],
      ]
    : [];

  server.onerror = reportError;
  server.onclose = finish;

  input.once('end', closeOnClientDisconnect);
  input.once('close', closeOnClientDisconnect);
  for (const [signal, handler] of signalHandlers) {
    process.once(signal, handler);
  }

  try {
    await server.connect(transport);
  } catch (error) {
    reportError(error);
    cleanup();
    throw error;
  }

  await lifecycleComplete;
}

const isEntrypoint = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  runStdioServer().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`MCP server failed to start: ${message}\n`);
    process.exitCode = 1;
  });
}
