import process from 'node:process';
import type { Readable, Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { serializeAuditEvent } from './diagnostics/redacted-diagnostics-audit.js';
import {
  APPROVED_PROFILE_CLASSIFICATION,
  createRuntimeApprovedProfileListingProvider,
  type ApprovedProfileListingProvider,
} from './profiles/approved-profile-listing.js';
import { createRuntimeConnectionValidationProvider } from './runtime/posix-runtime-validation.js';
import {
  toConnectionValidationFailure,
  type ConnectionValidationOutcome,
  type ConnectionValidationProvider,
} from './validation/trusted-connection-validation.js';

export const serverName = 'ssh-mcp-server';
export const serverVersion = '0.1.0';
export const listApprovedProfilesToolName = 'list_approved_profiles';
export const validateConnectionToolName = 'validate_connection';

const LIST_APPROVED_PROFILES_DESCRIPTION =
  'Lists the identifiers of profiles approved by the operator. Connection, credential, and host details are not disclosed.';
const VALIDATE_CONNECTION_DESCRIPTION =
  'Validates readiness for an operator-approved SSH connection. It accepts only a profile identifier and never accepts commands or connection settings.';
const SAFE_PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const MAX_DISCOVERABLE_PROFILES = 256;

export interface ServerOptions {
  /** Trusted provider that exposes only minimized, approved profile summaries. */
  readonly approvedProfileListingProvider?: ApprovedProfileListingProvider;
  /** Trusted provider composed from the connection policy and SSH readiness adapter. */
  readonly connectionValidationProvider?: ConnectionValidationProvider;
  /** Internal sink for already-allowlisted validation audit records. */
  readonly auditSink?: (serializedEvent: string) => void;
}

export interface StdioServerOptions {
  input?: Readable;
  output?: Writable;
  errorOutput?: Writable;
  installSignalHandlers?: boolean;
  approvedProfileListingProvider?: ApprovedProfileListingProvider;
  connectionValidationProvider?: ConnectionValidationProvider;
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
  return typeof value === 'string' && value !== 'constructor' && value !== 'prototype' && value !== '__proto__' && SAFE_PROFILE_ID.test(value);
}

/** Validate the exact public input before a trusted validation provider runs. */
function isConnectionValidationInput(input: unknown): input is { readonly profileId: string } {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    return false;
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length !== 1 || keys[0] !== 'profileId') {
    return false;
  }
  const descriptor = Object.getOwnPropertyDescriptor(input, 'profileId');
  return descriptor !== undefined && Object.prototype.hasOwnProperty.call(descriptor, 'value') && isSafeProfileId(descriptor.value);
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

function validationResult(outcome: unknown, isError = false): ReturnType<typeof textToolResult> {
  return textToolResult(JSON.stringify(outcome), isError);
}

function unavailableConnectionValidationResult(): ReturnType<typeof textToolResult> {
  return validationResult({ ready: false, outcome: 'failure', code: 'provider-failure' }, true);
}

function invalidConnectionValidationResult(): ReturnType<typeof textToolResult> {
  return validationResult({ ready: false, outcome: 'failure', code: 'invalid-input' }, true);
}

function safeValidationOutcome(value: unknown, requestedProfileId: string): ConnectionValidationOutcome {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('Trusted connection validation provider returned an invalid result');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('Trusted connection validation provider returned an invalid result');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 2 || !keys.includes('profileId') || !keys.includes('ready')) {
    throw new TypeError('Trusted connection validation provider returned an invalid result');
  }
  const profileId = Object.getOwnPropertyDescriptor(value, 'profileId');
  const ready = Object.getOwnPropertyDescriptor(value, 'ready');
  if (
    profileId === undefined ||
    ready === undefined ||
    !Object.prototype.hasOwnProperty.call(profileId, 'value') ||
    !Object.prototype.hasOwnProperty.call(ready, 'value') ||
    !isSafeProfileId(profileId.value) ||
    profileId.value !== requestedProfileId ||
    ready.value !== true
  ) {
    throw new TypeError('Trusted connection validation provider returned an invalid result');
  }
  return { profileId: profileId.value, ready: true };
}

/** Emit a fixed startup diagnostic without exposing the triggering failure. */
export function reportEntrypointFailure(errorOutput: Pick<Writable, 'write'>, _error: unknown): void {
  errorOutput.write('MCP server failed to start\n');
}

function writeAudit(sink: ((serializedEvent: string) => void) | undefined, input: unknown): void {
  if (sink === undefined) return;
  try {
    sink(serializeAuditEvent(input));
  } catch {
    // Diagnostics must never interfere with an MCP result.
  }
}

function registerTools(
  server: Server,
  approvedProfileListingProvider: ApprovedProfileListingProvider | undefined,
  connectionValidationProvider: ConnectionValidationProvider | undefined,
  auditSink: ((serializedEvent: string) => void) | undefined,
): void {
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
      ...(connectionValidationProvider === undefined
        ? []
        : [
            {
              name: validateConnectionToolName,
              description: VALIDATE_CONNECTION_DESCRIPTION,
              inputSchema: {
                type: 'object',
                properties: { profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' } },
                required: ['profileId'],
                additionalProperties: false,
              },
            },
          ]),
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === listApprovedProfilesToolName) {
      if (!isEmptyDiscoveryInput(request.params.arguments) || approvedProfileListingProvider === undefined) {
        return unavailableDiscoveryResult();
      }
      try {
        const profiles = await approvedProfileListingProvider.listApprovedProfiles();
        return textToolResult(JSON.stringify(toSafeProfileResponse(profiles)));
      } catch {
        // Provider failures and malformed provider output stay inside the trusted boundary.
        return unavailableDiscoveryResult();
      }
    }

    if (request.params.name !== validateConnectionToolName) {
      return unavailableDiscoveryResult();
    }
    if (!isConnectionValidationInput(request.params.arguments)) {
      writeAudit(auditSink, { code: 'invalid-input', outcome: 'failure', stage: 'selection' });
      return invalidConnectionValidationResult();
    }
    if (connectionValidationProvider === undefined) {
      writeAudit(auditSink, { profileId: request.params.arguments.profileId, code: 'provider-failure', outcome: 'failure', stage: 'provider' });
      return unavailableConnectionValidationResult();
    }
    const startedAt = Date.now();
    try {
      const outcome = await connectionValidationProvider.validateConnection({ profileId: request.params.arguments.profileId });
      const safeOutcome = safeValidationOutcome(outcome, request.params.arguments.profileId);
      writeAudit(auditSink, {
        profileId: safeOutcome.profileId,
        code: 'success',
        outcome: 'success',
        stage: 'readiness',
        durationMs: Date.now() - startedAt,
      });
      return validationResult(safeOutcome);
    } catch (error) {
      const failure = toConnectionValidationFailure(error);
      writeAudit(auditSink, {
        profileId: request.params.arguments.profileId,
        ...failure,
        stage: 'readiness',
        durationMs: Date.now() - startedAt,
      });
      return validationResult(failure, true);
    }
  });
}

export function createServer({ approvedProfileListingProvider, connectionValidationProvider, auditSink }: ServerOptions = {}): Server {
  const server = new Server({ name: serverName, version: serverVersion }, { capabilities: { tools: {} } });
  registerTools(server, approvedProfileListingProvider, connectionValidationProvider, auditSink);
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
  connectionValidationProvider,
}: StdioServerOptions = {}): Promise<void> {
  const server = createServer({
    approvedProfileListingProvider,
    connectionValidationProvider,
    auditSink: (serializedEvent) => errorOutput.write(`${serializedEvent}\n`),
  });
  const transport = new StdioServerTransport(input, output);

  let completeLifecycle: () => void;
  const lifecycleComplete = new Promise<void>((resolve) => {
    completeLifecycle = resolve;
  });
  let completed = false;
  let closing = false;

  const reportError = (_error: unknown): void => {
    errorOutput.write('MCP server error\n');
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
    const connectionValidationProvider = createRuntimeConnectionValidationProvider();
    await runStdioServer({ approvedProfileListingProvider, connectionValidationProvider });
  };

  runProductionServer().catch((error: unknown) => {
    reportEntrypointFailure(process.stderr, error);
    process.exitCode = 1;
  });
}
