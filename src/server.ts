import process from 'node:process';
import type { Readable, Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { serializeAuditEvent } from './diagnostics/redacted-diagnostics-audit.js';
import { remoteCommandToolName, type RemoteCommandExecutionProvider, type RemoteCommandResult } from './execution/remote-command-execution.js';
import { uploadRemoteFileToolName, type FileUploadResult, type RemoteFileUploadProvider } from './execution/remote-file-upload.js';
import {
  APPROVED_PROFILE_CLASSIFICATION,
  createRuntimeApprovedProfileListingProvider,
  type ApprovedProfileListingProvider,
} from './profiles/approved-profile-listing.js';
import {
  createRuntimeConnectionValidationProvider,
  createRuntimeRemoteCommandExecutionProvider,
  createRuntimeRemoteFileUploadProvider,
} from './runtime/posix-runtime-validation.js';
import {
  toConnectionValidationFailure,
  type ConnectionValidationOutcome,
  type ConnectionValidationProvider,
} from './validation/trusted-connection-validation.js';
import { WindowsOpenSshResolver } from './windows/windows-openssh.js';
import {
  WINDOWS_READINESS_STATUS_KIND,
  WINDOWS_READINESS_STATUS_VERSION,
  createWindowsReadinessStatusProvider,
  type WindowsReadinessStatus,
  type WindowsReadinessStatusProvider,
} from './windows/windows-readiness-status.js';
import { supportsWindowsAlphaRuntime } from './windows/windows-runtime-support.js';
import { createWindowsRuntimeProviders } from './windows/windows-runtime.js';

export const serverName = 'ssh-mcp-server';
export const serverVersion = '1.2.0';
export const listApprovedProfilesToolName = 'list_approved_profiles';
export const validateConnectionToolName = 'validate_connection';
export const getWindowsReadinessStatusToolName = 'get_windows_readiness_status';
export const requestActionApprovalToolName = 'request_action_approval';

const LIST_APPROVED_PROFILES_DESCRIPTION =
  'Lists operator-approved profile IDs only. Use an ID returned here for validation; connection, credential, and host details are never disclosed.';
const VALIDATE_CONNECTION_DESCRIPTION =
  'Checks readiness for one operator-approved SSH profile ID through the external SSH endpoint. It may perform authentication readiness checks and emit local audit records, but it executes no remote command and accepts no connection settings, credentials, or paths.';
const WINDOWS_READINESS_STATUS_DESCRIPTION =
  'Reports bounded local Windows readiness categories only. It accepts no connection settings, profile IDs, credentials, paths, or commands and never contacts a remote host.';
const REMOTE_COMMAND_DESCRIPTION =
  'Executes one bounded non-interactive command on an approved SSH profile without an executable allowlist. This mutating tool requires the MCP client to obtain explicit user confirmation in the conversation before calling it, including for sudo and command evaluators; it does not open a native server dialog. Supports no persistent SSH session or local shell.';
const FILE_UPLOAD_DESCRIPTION =
  'Uploads one Base64 file to an exact remote destination. This mutating tool requires the MCP client to obtain explicit user confirmation in the conversation before calling it; it does not open a native server dialog. The destination is not restricted by a server-side directory allowlist; remote permissions still apply.';
const SAFE_PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const MAX_DISCOVERABLE_PROFILES = 256;

const LIST_APPROVED_PROFILES_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    profiles: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
          classification: { type: 'string', enum: [APPROVED_PROFILE_CLASSIFICATION] },
        },
        required: ['profileId', 'classification'],
        additionalProperties: false,
      },
    },
  },
  required: ['profiles'],
  additionalProperties: false,
};

const WINDOWS_READINESS_STATUS_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    kind: { type: 'string', enum: [WINDOWS_READINESS_STATUS_KIND] },
    version: { type: 'integer', enum: [WINDOWS_READINESS_STATUS_VERSION] },
    runtime: { type: 'string', enum: ['ready', 'unsupported'] },
    registry: { type: 'string', enum: ['ready', 'unavailable', 'invalid', 'not-checked'] },
    filesystem: { type: 'string', enum: ['ready', 'unavailable', 'invalid', 'not-checked'] },
    configuration: { type: 'string', enum: ['ready', 'unavailable', 'invalid', 'not-checked'] },
    knownHosts: { type: 'string', enum: ['ready', 'unavailable', 'invalid', 'not-checked'] },
    credentials: { type: 'string', enum: ['ready', 'unavailable', 'not-checked'] },
    validationProvider: { type: 'string', enum: ['ready', 'unavailable', 'invalid', 'not-checked'] },
    remoteAuthentication: { type: 'string', enum: ['not-checked'] },
  },
  required: [
    'kind',
    'version',
    'runtime',
    'registry',
    'filesystem',
    'configuration',
    'knownHosts',
    'credentials',
    'validationProvider',
    'remoteAuthentication',
  ],
  additionalProperties: false,
};

const VALIDATE_CONNECTION_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
    ready: { type: 'boolean' },
    outcome: { type: 'string', enum: ['success', 'failure', 'timeout'] },
    code: {
      type: 'string',
      enum: [
        'success',
        'unknown',
        'invalid-input',
        'provider-failure',
        'timeout',
        'host-key-failure',
        'authentication-failure',
        'connection-failure',
      ],
    },
  },
  oneOf: [
    { required: ['profileId', 'ready'], properties: { ready: { const: true } } },
    { required: ['ready', 'outcome', 'code'], properties: { ready: { const: false } } },
  ],
  additionalProperties: false,
};

const REMOTE_COMMAND_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    operationId: { type: 'string', pattern: '^[a-f0-9]{32}$' },
    profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
    outcome: { type: 'string', enum: ['success', 'failure', 'timeout', 'cancelled', 'approval-required', 'unknown'] },
    code: {
      type: 'string',
      enum: [
        'success',
        'remote-failure',
        'connection-failure',
        'authentication-failure',
        'host-key-failure',
        'windows-agent-key-unsupported',
        'timeout',
        'cancelled',
        'approval-required',
        'approval-expired',
        'approval-altered',
        'approval-reused',
        'approval-unavailable',
        'approval-busy',
        'approval-rejected',
        'execution-limit',
        'execution-audit-unavailable',
        'outcome-unknown',
        'invalid-input',
        'provider-failure',
      ],
    },
    exitCode: { type: ['integer', 'null'] },
    stdout: { type: 'string' },
    stderr: { type: 'string' },
    outputTruncated: { type: 'boolean' },
  },
  required: ['operationId', 'profileId', 'outcome', 'code', 'exitCode', 'stdout', 'stderr', 'outputTruncated'],
  additionalProperties: false,
};

const FILE_UPLOAD_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    operationId: { type: 'string', pattern: '^[a-f0-9]{32}$' },
    profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$|^unknown$' },
    remotePath: { type: 'string', maxLength: 4096 },
    sha256: { type: 'string', pattern: '^[a-f0-9]{64}$|^$' },
    sizeBytes: { type: 'integer', minimum: 0, maximum: 1048576 },
    outcome: { type: 'string', enum: ['success', 'failure', 'timeout', 'cancelled', 'unknown'] },
    code: {
      type: 'string',
      enum: [
        'success',
        'connection-failure',
        'authentication-failure',
        'host-key-failure',
        'remote-failure',
        'integrity-failure',
        'timeout',
        'cancelled',
        'execution-limit',
        'execution-audit-unavailable',
        'outcome-unknown',
        'invalid-input',
        'provider-failure',
      ],
    },
    integrity: { type: 'string', enum: ['verified', 'unknown'] },
  },
  required: ['operationId', 'profileId', 'remotePath', 'sha256', 'sizeBytes', 'outcome', 'code', 'integrity'],
  additionalProperties: false,
};

const ACTION_APPROVAL_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    approved: { type: 'boolean' },
    code: { type: 'string' },
    capability: { type: 'string', maxLength: 256 },
    summary: { type: 'object', additionalProperties: true },
  },
  required: ['approved', 'code'],
  additionalProperties: false,
};

export interface ServerOptions {
  /** Trusted provider that exposes only minimized, approved profile summaries. */
  readonly approvedProfileListingProvider?: ApprovedProfileListingProvider;
  /** Trusted provider composed from the connection policy and SSH readiness adapter. */
  readonly connectionValidationProvider?: ConnectionValidationProvider;
  /** Internal sink for already-allowlisted validation audit records. */
  readonly auditSink?: (serializedEvent: string) => void;
  /** Local-only, redacted Windows prerequisite status provider. */
  readonly windowsReadinessStatusProvider?: WindowsReadinessStatusProvider;
  /** Trusted remote execution boundary. */
  readonly remoteCommandExecutionProvider?: RemoteCommandExecutionProvider;
  /** Trusted upload provider. It is absent until a platform transport is composed. */
  readonly remoteFileUploadProvider?: RemoteFileUploadProvider;
}

export interface StdioServerOptions {
  input?: Readable;
  output?: Writable;
  errorOutput?: Writable;
  installSignalHandlers?: boolean;
  approvedProfileListingProvider?: ApprovedProfileListingProvider;
  connectionValidationProvider?: ConnectionValidationProvider;
  windowsReadinessStatusProvider?: WindowsReadinessStatusProvider;
  remoteCommandExecutionProvider?: RemoteCommandExecutionProvider;
  remoteFileUploadProvider?: RemoteFileUploadProvider;
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
  structuredContent?: Readonly<Record<string, unknown>>,
): {
  readonly content: readonly [{ readonly type: 'text'; readonly text: string }];
  readonly structuredContent?: Readonly<Record<string, unknown>>;
  readonly isError?: boolean;
} {
  return {
    content: [{ type: 'text', text }],
    ...(structuredContent === undefined ? {} : { structuredContent }),
    ...(isError ? { isError: true } : {}),
  };
}

function jsonToolResult(value: object, isError = false): ReturnType<typeof textToolResult> {
  return textToolResult(JSON.stringify(value), isError, value as Readonly<Record<string, unknown>>);
}

function unavailableDiscoveryResult(): ReturnType<typeof textToolResult> {
  return textToolResult('Approved profile discovery is unavailable.', true);
}

function unavailableWindowsReadinessStatusResult(): ReturnType<typeof textToolResult> {
  return textToolResult('Windows readiness status is unavailable.', true);
}

function validationResult(outcome: object, isError = false): ReturnType<typeof textToolResult> {
  return jsonToolResult(outcome, isError);
}

function remoteResult(result: RemoteCommandResult): ReturnType<typeof textToolResult> {
  const structuredResult = { ...result, operationId: result.operationId };
  return textToolResult(JSON.stringify(result), result.outcome !== 'success' && result.outcome !== 'approval-required', structuredResult);
}

function fileUploadResult(result: FileUploadResult): ReturnType<typeof textToolResult> {
  return jsonToolResult(result, result.outcome !== 'success');
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

function statusField(value: unknown, allowed: readonly string[]): string {
  if (typeof value !== 'string' || !allowed.includes(value)) throw new TypeError('Trusted Windows readiness provider returned an invalid result');
  return value;
}

/** Project the Windows status through a fixed response schema with no dynamic fields. */
function safeWindowsReadinessStatus(value: unknown): WindowsReadinessStatus {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new TypeError('Trusted Windows readiness provider returned an invalid result');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Trusted Windows readiness provider returned an invalid result');
  const keys = Reflect.ownKeys(value);
  const expected = [
    'kind',
    'version',
    'runtime',
    'registry',
    'filesystem',
    'configuration',
    'knownHosts',
    'credentials',
    'validationProvider',
    'remoteAuthentication',
  ];
  if (keys.length !== expected.length || !expected.every((key) => keys.includes(key))) {
    throw new TypeError('Trusted Windows readiness provider returned an invalid result');
  }
  const fields = Object.fromEntries(
    expected.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        throw new TypeError('Trusted Windows readiness provider returned an invalid result');
      }
      return [key, descriptor.value];
    }),
  ) as Record<string, unknown>;
  if (fields.kind !== WINDOWS_READINESS_STATUS_KIND || fields.version !== WINDOWS_READINESS_STATUS_VERSION) {
    throw new TypeError('Trusted Windows readiness provider returned an invalid result');
  }
  const checkValues = ['ready', 'unavailable', 'invalid', 'not-checked'];
  const runtime = statusField(fields.runtime, ['ready', 'unsupported']) as WindowsReadinessStatus['runtime'];
  const credentials = statusField(fields.credentials, ['ready', 'unavailable', 'not-checked']);
  const remoteAuthentication = statusField(fields.remoteAuthentication, ['not-checked']);
  return {
    kind: WINDOWS_READINESS_STATUS_KIND,
    version: WINDOWS_READINESS_STATUS_VERSION,
    runtime,
    registry: statusField(fields.registry, checkValues) as WindowsReadinessStatus['registry'],
    filesystem: statusField(fields.filesystem, checkValues) as WindowsReadinessStatus['filesystem'],
    configuration: statusField(fields.configuration, checkValues) as WindowsReadinessStatus['configuration'],
    knownHosts: statusField(fields.knownHosts, checkValues) as WindowsReadinessStatus['knownHosts'],
    credentials: credentials as WindowsReadinessStatus['credentials'],
    validationProvider: statusField(fields.validationProvider, checkValues) as WindowsReadinessStatus['validationProvider'],
    remoteAuthentication: remoteAuthentication as 'not-checked',
  };
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
  windowsReadinessStatusProvider: WindowsReadinessStatusProvider | undefined,
  remoteCommandExecutionProvider: RemoteCommandExecutionProvider | undefined,
  remoteFileUploadProvider: RemoteFileUploadProvider | undefined,
  auditSink: ((serializedEvent: string) => void) | undefined,
): void {
  const configuredRemoteCommandExecutionProvider =
    remoteCommandExecutionProvider === undefined
      ? undefined
      : auditSink === undefined
        ? remoteCommandExecutionProvider
        : remoteCommandExecutionProvider.withAuditSink(auditSink);
  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [
      ...(approvedProfileListingProvider === undefined
        ? []
        : [
            {
              name: listApprovedProfilesToolName,
              description: LIST_APPROVED_PROFILES_DESCRIPTION,
              outputSchema: LIST_APPROVED_PROFILES_OUTPUT_SCHEMA,
              annotations: { readOnlyHint: true, openWorldHint: false },
              inputSchema: {
                type: 'object',
                properties: {},
                additionalProperties: false,
              },
            },
          ]),
      ...(connectionValidationProvider === undefined
        ? []
        : [
            {
              name: validateConnectionToolName,
              description: VALIDATE_CONNECTION_DESCRIPTION,
              outputSchema: VALIDATE_CONNECTION_OUTPUT_SCHEMA,
              annotations: { readOnlyHint: true, openWorldHint: true },
              inputSchema: {
                type: 'object',
                properties: { profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' } },
                required: ['profileId'],
                additionalProperties: false,
              },
            },
          ]),
      ...(windowsReadinessStatusProvider === undefined
        ? []
        : [
            {
              name: getWindowsReadinessStatusToolName,
              description: WINDOWS_READINESS_STATUS_DESCRIPTION,
              outputSchema: WINDOWS_READINESS_STATUS_OUTPUT_SCHEMA,
              annotations: { readOnlyHint: true, openWorldHint: false },
              inputSchema: {
                type: 'object',
                properties: {},
                additionalProperties: false,
              },
            },
          ]),
      ...(configuredRemoteCommandExecutionProvider === undefined && remoteFileUploadProvider === undefined
        ? []
        : [
            {
              name: requestActionApprovalToolName,
              description:
                'Requests a one-use approval capability for one exact sensitive action. The MCP client must obtain explicit user consent for this mutating call in the conversation. The capability is bound to the action and execution does not prompt again.',
              outputSchema: ACTION_APPROVAL_OUTPUT_SCHEMA,
              annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
              inputSchema: {
                type: 'object',
                properties: {
                  action: { type: 'string', enum: ['file-upload', 'remote-command'] },
                  profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
                  remotePath: { type: 'string', minLength: 1, maxLength: 4096 },
                  contentBase64: { type: 'string', minLength: 1, maxLength: 1398108 },
                  command: { type: 'string', minLength: 1, maxLength: 256 },
                  args: { type: 'array', items: { type: 'string', maxLength: 4096 }, maxItems: 64 },
                  timeoutMs: { type: 'integer', minimum: 1, maximum: 60000 },
                  maxOutputBytes: { type: 'integer', minimum: 1, maximum: 1048576 },
                },
                required: ['action', 'profileId'],
                additionalProperties: false,
              },
            },
          ]),
      ...(configuredRemoteCommandExecutionProvider === undefined
        ? []
        : [
            {
              name: remoteCommandToolName,
              description: REMOTE_COMMAND_DESCRIPTION,
              outputSchema: REMOTE_COMMAND_OUTPUT_SCHEMA,
              annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
              inputSchema: {
                type: 'object',
                properties: {
                  profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
                  command: { type: 'string', minLength: 1, maxLength: 256 },
                  args: { type: 'array', items: { type: 'string', maxLength: 4096 }, maxItems: 64 },
                  timeoutMs: { type: 'integer', minimum: 1, maximum: 60000 },
                  maxOutputBytes: { type: 'integer', minimum: 1, maximum: 1048576 },
                  approvalCapability: { type: 'string', minLength: 1, maxLength: 256 },
                },
                required: ['profileId', 'command', 'args'],
                additionalProperties: false,
              },
            },
          ]),
      ...(remoteFileUploadProvider === undefined
        ? []
        : [
            {
              name: uploadRemoteFileToolName,
              description: FILE_UPLOAD_DESCRIPTION,
              outputSchema: FILE_UPLOAD_OUTPUT_SCHEMA,
              annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
              inputSchema: {
                type: 'object',
                properties: {
                  profileId: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
                  remotePath: { type: 'string', minLength: 1, maxLength: 4096 },
                  contentBase64: { type: 'string', minLength: 1, maxLength: 1398108 },
                  timeoutMs: { type: 'integer', minimum: 1, maximum: 60000 },
                  approvalCapability: { type: 'string', minLength: 1, maxLength: 256 },
                },
                required: ['profileId', 'remotePath', 'contentBase64'],
                additionalProperties: false,
              },
            },
          ]),
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    if (request.params.name === requestActionApprovalToolName) {
      const input = request.params.arguments;
      if (typeof input !== 'object' || input === null || Array.isArray(input))
        return jsonToolResult({ approved: false, code: 'invalid-input' }, true);
      const { action, ...payload } = input as Record<string, unknown>;
      if (action === 'file-upload' && remoteFileUploadProvider !== undefined) {
        const approval = await remoteFileUploadProvider.requestActionApproval(payload, extra.signal);
        return jsonToolResult(approval, approval.approved !== true);
      }
      if (action === 'remote-command' && configuredRemoteCommandExecutionProvider !== undefined) {
        const approval = await configuredRemoteCommandExecutionProvider.requestActionApproval(payload, extra.signal);
        return jsonToolResult(approval, approval.approved !== true);
      }
      return jsonToolResult({ approved: false, code: 'invalid-input' }, true);
    }
    if (request.params.name === listApprovedProfilesToolName) {
      if (!isEmptyDiscoveryInput(request.params.arguments) || approvedProfileListingProvider === undefined) {
        return unavailableDiscoveryResult();
      }
      try {
        const profiles = await approvedProfileListingProvider.listApprovedProfiles();
        return jsonToolResult(toSafeProfileResponse(profiles));
      } catch {
        // Provider failures and malformed provider output stay inside the trusted boundary.
        return unavailableDiscoveryResult();
      }
    }

    if (request.params.name === getWindowsReadinessStatusToolName) {
      if (!isEmptyDiscoveryInput(request.params.arguments) || windowsReadinessStatusProvider === undefined) {
        return unavailableWindowsReadinessStatusResult();
      }
      try {
        return jsonToolResult(safeWindowsReadinessStatus(await windowsReadinessStatusProvider.getWindowsReadinessStatus()));
      } catch {
        return unavailableWindowsReadinessStatusResult();
      }
    }

    if (request.params.name === uploadRemoteFileToolName) {
      if (remoteFileUploadProvider === undefined)
        return fileUploadResult({
          operationId: '0'.repeat(32),
          profileId: 'unknown',
          remotePath: '',
          sha256: '',
          sizeBytes: 0,
          outcome: 'failure',
          code: 'provider-failure',
          integrity: 'unknown',
        });
      return fileUploadResult(await remoteFileUploadProvider.upload(request.params.arguments, extra.signal));
    }

    if (request.params.name === remoteCommandToolName) {
      if (configuredRemoteCommandExecutionProvider === undefined) {
        return remoteResult({
          operationId: '00000000000000000000000000000000',
          profileId: 'unknown',
          outcome: 'failure',
          code: 'provider-failure',
          exitCode: null,
          stdout: '',
          stderr: '',
          outputTruncated: false,
        });
      }
      return remoteResult(await configuredRemoteCommandExecutionProvider.execute(request.params.arguments, extra.signal));
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
      const outcome = await connectionValidationProvider.validateConnection({ profileId: request.params.arguments.profileId }, extra.signal);
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

export function createServer({
  approvedProfileListingProvider,
  connectionValidationProvider,
  auditSink,
  windowsReadinessStatusProvider,
  remoteCommandExecutionProvider,
  remoteFileUploadProvider,
}: ServerOptions = {}): Server {
  const server = new Server({ name: serverName, version: serverVersion }, { capabilities: { tools: {} } });
  registerTools(
    server,
    approvedProfileListingProvider,
    connectionValidationProvider,
    windowsReadinessStatusProvider,
    remoteCommandExecutionProvider,
    remoteFileUploadProvider,
    auditSink,
  );
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
  windowsReadinessStatusProvider,
  remoteCommandExecutionProvider,
  remoteFileUploadProvider,
}: StdioServerOptions = {}): Promise<void> {
  const server = createServer({
    approvedProfileListingProvider,
    connectionValidationProvider,
    windowsReadinessStatusProvider,
    remoteCommandExecutionProvider,
    remoteFileUploadProvider,
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

export function createProductionRuntimeProviders(
  platform = process.platform,
  windowsSupported = supportsWindowsAlphaRuntime() &&
    (() => {
      try {
        new WindowsOpenSshResolver().paths();
        return true;
      } catch {
        return false;
      }
    })(),
  windowsRuntimeFactory: () => Pick<
    ServerOptions,
    | 'approvedProfileListingProvider'
    | 'connectionValidationProvider'
    | 'windowsReadinessStatusProvider'
    | 'remoteCommandExecutionProvider'
    | 'remoteFileUploadProvider'
  > = () => createWindowsRuntimeProviders(),
): Pick<
  ServerOptions,
  | 'approvedProfileListingProvider'
  | 'connectionValidationProvider'
  | 'windowsReadinessStatusProvider'
  | 'remoteCommandExecutionProvider'
  | 'remoteFileUploadProvider'
> {
  if (platform === 'win32') {
    if (!windowsSupported) return { windowsReadinessStatusProvider: createWindowsReadinessStatusProvider(false) };
    try {
      return windowsRuntimeFactory();
    } catch {
      return { windowsReadinessStatusProvider: createWindowsReadinessStatusProvider(true) };
    }
  }
  if (platform === 'linux' || platform === 'darwin') {
    const connectionValidationProvider = createRuntimeConnectionValidationProvider();
    const remoteFileUploadProvider = createRuntimeRemoteFileUploadProvider({ connectionValidationProvider });
    return {
      approvedProfileListingProvider: createRuntimeApprovedProfileListingProvider(),
      connectionValidationProvider,
      remoteCommandExecutionProvider: createRuntimeRemoteCommandExecutionProvider({ connectionValidationProvider }),
      ...(remoteFileUploadProvider === undefined ? {} : { remoteFileUploadProvider }),
    };
  }
  return {};
}

if (isEntrypoint) {
  const runProductionServer = async (): Promise<void> => {
    await runStdioServer(createProductionRuntimeProviders());
  };

  runProductionServer().catch((error: unknown) => {
    reportEntrypointFailure(process.stderr, error);
    process.exitCode = 1;
  });
}
