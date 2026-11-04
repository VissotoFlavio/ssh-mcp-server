import process from 'node:process';
import type { Readable, Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import {
  APPROVED_PROFILE_CLASSIFICATION,
  createRuntimeApprovedProfileListingProvider,
  type ApprovedProfileListingProvider,
} from './profiles/approved-profile-listing.js';

export const serverName = 'ssh-mcp-server';
export const serverVersion = '0.1.0';
export const listApprovedProfilesToolName = 'list_approved_profiles';

const LIST_APPROVED_PROFILES_DESCRIPTION =
  'Lists the identifiers of profiles approved by the operator. Connection, credential, and host details are not disclosed.';
const SAFE_PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const MAX_DISCOVERABLE_PROFILES = 256;

export interface ServerOptions {
  /** Trusted provider that exposes only minimized, approved profile summaries. */
  readonly approvedProfileListingProvider?: ApprovedProfileListingProvider;
}

export interface StdioServerOptions {
  input?: Readable;
  output?: Writable;
  errorOutput?: Writable;
  installSignalHandlers?: boolean;
  approvedProfileListingProvider?: ApprovedProfileListingProvider;
}

function isEmptyDiscoveryInput(input: unknown): boolean {
  if (input === undefined) {
    return true;
  }
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(input);
  return (prototype === Object.prototype || prototype === null) && Reflect.ownKeys(input).length === 0;
}

function isSafeProfileId(value: unknown): value is string {
  return typeof value === 'string' && SAFE_PROFILE_ID.test(value);
}

/**
 * Project a provider result through the response allowlist. This defends the
 * protocol boundary even if a provider object carries extra fields at runtime.
 */
function providerProfileEntries(profiles: unknown): readonly unknown[] {
  if (!Array.isArray(profiles) || Object.getPrototypeOf(profiles) !== Array.prototype) {
    throw new TypeError('Trusted profile provider returned an invalid result');
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(profiles, 'length');
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_DISCOVERABLE_PROFILES) {
    throw new TypeError('Trusted profile provider returned an invalid result');
  }

  const keys = Reflect.ownKeys(profiles);
  if (keys.length !== length + 1 || !keys.includes('length')) {
    throw new TypeError('Trusted profile provider returned an invalid result');
  }

  const entries: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const entry = Object.getOwnPropertyDescriptor(profiles, String(index));
    if (entry === undefined || !Object.prototype.hasOwnProperty.call(entry, 'value')) {
      throw new TypeError('Trusted profile provider returned an invalid result');
    }
    entries.push(entry.value);
  }
  return entries;
}

function profileIdFromProviderEntry(entry: unknown): string {
  if (typeof entry !== 'object' || entry === null) {
    throw new TypeError('Trusted profile provider returned an invalid result');
  }
  const prototype = Object.getPrototypeOf(entry);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('Trusted profile provider returned an invalid result');
  }

  const profileId = Object.getOwnPropertyDescriptor(entry, 'profileId');
  if (profileId === undefined || !Object.prototype.hasOwnProperty.call(profileId, 'value') || !isSafeProfileId(profileId.value)) {
    throw new TypeError('Trusted profile provider returned an invalid result');
  }
  return profileId.value;
}

function toSafeProfileResponse(profiles: unknown): {
  readonly profiles: readonly { readonly profileId: string; readonly classification: typeof APPROVED_PROFILE_CLASSIFICATION }[];
} {
  const safeProfiles: Array<{ readonly profileId: string; readonly classification: typeof APPROVED_PROFILE_CLASSIFICATION }> = [];
  for (const entry of providerProfileEntries(profiles)) {
    safeProfiles.push({
      profileId: profileIdFromProviderEntry(entry),
      classification: APPROVED_PROFILE_CLASSIFICATION,
    });
  }
  return { profiles: safeProfiles };
}

function textToolResult(
  text: string,
  isError = false,
): {
  readonly content: readonly [{ readonly type: 'text'; readonly text: string }];
  readonly isError?: boolean;
} {
  return {
    content: [{ type: 'text', text }],
    ...(isError ? { isError: true } : {}),
  };
}

function unavailableDiscoveryResult(): ReturnType<typeof textToolResult> {
  return textToolResult('Approved profile discovery is unavailable.', true);
}

function registerApprovedProfileDiscovery(server: Server, approvedProfileListingProvider: ApprovedProfileListingProvider | undefined): void {
  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [
      {
        name: listApprovedProfilesToolName,
        description: LIST_APPROVED_PROFILES_DESCRIPTION,
        inputSchema: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== listApprovedProfilesToolName || !isEmptyDiscoveryInput(request.params.arguments)) {
      return unavailableDiscoveryResult();
    }
    if (approvedProfileListingProvider === undefined) {
      return unavailableDiscoveryResult();
    }

    try {
      const profiles = await approvedProfileListingProvider.listApprovedProfiles();
      return textToolResult(JSON.stringify(toSafeProfileResponse(profiles)));
    } catch {
      // Provider failures and malformed provider output stay inside the trusted boundary.
      return unavailableDiscoveryResult();
    }
  });
}

export function createServer({ approvedProfileListingProvider }: ServerOptions = {}): Server {
  const server = new Server({ name: serverName, version: serverVersion }, { capabilities: { tools: {} } });
  registerApprovedProfileDiscovery(server, approvedProfileListingProvider);
  return server;
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
  approvedProfileListingProvider,
}: StdioServerOptions = {}): Promise<void> {
  const server = createServer({ approvedProfileListingProvider });
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
  const runProductionServer = async (): Promise<void> => {
    const approvedProfileListingProvider = createRuntimeApprovedProfileListingProvider();
    await runStdioServer({ approvedProfileListingProvider });
  };

  runProductionServer().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'unknown failure';
    process.stderr.write(`MCP server failed to start: ${message}\n`);
    process.exitCode = 1;
  });
}
