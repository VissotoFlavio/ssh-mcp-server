import { createHash, randomBytes } from 'node:crypto';

import { Client, type AuthHandlerMiddleware, type ClientChannel, type ConnectConfig, type NextAuthHandler } from 'ssh2';

import { serializeAuditEvent } from '../diagnostics/redacted-diagnostics-audit.js';
import type { ConnectionProfile } from '../profiles/connection-profile.js';
import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

export const remoteCommandToolName = 'execute_remote_command';
export const requestSudoApprovalToolName = 'request_sudo_approval';

export const REMOTE_COMMAND_DEFAULT_TIMEOUT_MS = 30_000;
export const REMOTE_COMMAND_MAX_TIMEOUT_MS = 60_000;
export const REMOTE_COMMAND_DEFAULT_OUTPUT_LIMIT = 64 * 1024;
export const REMOTE_COMMAND_MAX_OUTPUT_LIMIT = 1024 * 1024;
const APPROVAL_TTL_MS = 60_000;
const MAX_COMMAND_LENGTH = 256;
const MAX_ARGUMENTS = 128;
const MAX_ARGUMENT_LENGTH = 4096;
// eslint-disable-next-line no-control-regex -- reject control characters at the MCP trust boundary
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const COMMAND_DELIMITERS = /\s/u;
const PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const REJECTED_EXECUTABLES = new Set([
  'sh',
  'bash',
  'dash',
  'zsh',
  'ksh',
  'csh',
  'tcsh',
  'fish',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
  'python',
  'python3',
  'python.exe',
  'perl',
  'ruby',
  'node',
  'env',
  'nohup',
  'setsid',
  'daemonize',
  'disown',
]);
const REJECTED_SHELL_FLAGS = new Set(['-c', '-ccommand', '--command', '-command', '-encodedcommand', '--eval', '-e', '/c', '/k']);
const SHELL_METACHARACTERS = /[;&|<>`$(){}]/u;

export type RemoteExecutionOutcome = 'success' | 'failure' | 'timeout' | 'cancelled' | 'approval-required';
export type RemoteExecutionCode =
  | 'success'
  | 'remote-failure'
  | 'connection-failure'
  | 'authentication-failure'
  | 'host-key-failure'
  | 'windows-agent-key-unsupported'
  | 'timeout'
  | 'cancelled'
  | 'approval-required'
  | 'approval-expired'
  | 'approval-altered'
  | 'approval-reused'
  | 'invalid-input'
  | 'provider-failure';

export interface RemoteCommandRequest {
  readonly profileId: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  readonly approvalToken?: string;
}

export interface RemoteCommandResult {
  readonly profileId: string;
  readonly outcome: RemoteExecutionOutcome;
  readonly code: RemoteExecutionCode;
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly outputTruncated: boolean;
}

export interface RemoteCommandTransportRequest {
  readonly profile: ConnectionProfile;
  readonly command: string;
  readonly args: readonly string[];
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export interface RemoteCommandTransportResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly outputTruncated: boolean;
}

export interface RemoteCommandTransport {
  execute(request: RemoteCommandTransportRequest, signal?: AbortSignal): Promise<RemoteCommandTransportResult>;
}

export interface RemoteCommandProfileProvider {
  getProfile(profileId: string, signal?: AbortSignal): ConnectionProfile | undefined | Promise<ConnectionProfile | undefined>;
}

export interface SudoApprovalRequest {
  readonly profileId: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export interface HumanSudoApprovalProvider {
  /** This callback is a trusted human/UI boundary, never MCP caller input. */
  approve(request: SudoApprovalRequest, signal?: AbortSignal): Promise<boolean>;
}

export interface SudoApprovalRecord {
  readonly token: string;
  readonly request: SudoApprovalRequest;
  readonly expiresAt: number;
}

export interface ApprovedProfileIdentity {
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly expectedHostFingerprint: string;
  readonly authMode: ConnectionProfile['authMode'];
  readonly credentialReference?: string;
  readonly approvedKnownHostsReference: string;
}

export type SudoApprovalState = 'not-required' | 'blocked' | 'approved' | 'expired' | 'altered' | 'reused' | 'rejected';

export class RemoteExecutionError extends Error {
  readonly code: RemoteExecutionCode;

  constructor(code: RemoteExecutionCode, message: string) {
    super(message);
    this.name = 'RemoteExecutionError';
    this.code = code;
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function own(value: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined;
}

function boundedTimeout(value: unknown): number {
  if (value === undefined) return REMOTE_COMMAND_DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > REMOTE_COMMAND_MAX_TIMEOUT_MS) {
    throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  }
  return value as number;
}

function boundedOutputLimit(value: unknown): number {
  if (value === undefined) return REMOTE_COMMAND_DEFAULT_OUTPUT_LIMIT;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > REMOTE_COMMAND_MAX_OUTPUT_LIMIT) {
    throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  }
  return value as number;
}

function validateProfileId(value: unknown): string {
  if (typeof value !== 'string' || !PROFILE_ID.test(value) || value === '__proto__' || value === 'constructor' || value === 'prototype') {
    throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  }
  return value;
}

function validateText(value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || CONTROL_CHARACTERS.test(value)) {
    throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  }
  return value;
}

function validateCommand(value: unknown): string {
  const command = validateText(value, MAX_COMMAND_LENGTH);
  if (COMMAND_DELIMITERS.test(command)) throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  const executable = command.slice(Math.max(command.lastIndexOf('/'), command.lastIndexOf('\\')) + 1).toLowerCase();
  if (REJECTED_EXECUTABLES.has(executable)) throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  if (SHELL_METACHARACTERS.test(command)) throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  return command;
}

function validateArgs(value: unknown): readonly string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > MAX_ARGUMENTS) {
    throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  }
  return value.map((argument) => {
    const validated = validateText(argument, MAX_ARGUMENT_LENGTH);
    if (SHELL_METACHARACTERS.test(validated) || REJECTED_SHELL_FLAGS.has(validated.toLowerCase())) {
      throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
    }
    return validated;
  });
}

function validateApprovalToken(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  return validateText(value, 256);
}

function parseRequest(input: unknown): RemoteCommandRequest {
  if (!isPlainRecord(input)) throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  const keys = Reflect.ownKeys(input);
  const allowed = new Set(['profileId', 'command', 'args', 'timeoutMs', 'maxOutputBytes', 'approvalToken']);
  if (keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    throw new RemoteExecutionError('invalid-input', 'Remote command input is invalid');
  }
  const profileId = validateProfileId(own(input, 'profileId'));
  const command = validateCommand(own(input, 'command'));
  const args = validateArgs(own(input, 'args'));
  const timeoutMs = boundedTimeout(own(input, 'timeoutMs'));
  const maxOutputBytes = boundedOutputLimit(own(input, 'maxOutputBytes'));
  const approvalToken = validateApprovalToken(own(input, 'approvalToken'));
  return Object.freeze({
    profileId,
    command,
    args: Object.freeze([...args]),
    timeoutMs,
    maxOutputBytes,
    ...(approvalToken === undefined ? {} : { approvalToken }),
  });
}

function profileIdentity(profile: ConnectionProfile): ApprovedProfileIdentity {
  return Object.freeze({
    host: profile.host,
    port: profile.port,
    user: profile.user,
    expectedHostFingerprint: profile.expectedHostFingerprint,
    authMode: profile.authMode,
    ...(profile.credentialReference === undefined ? {} : { credentialReference: profile.credentialReference }),
    approvedKnownHostsReference: profile.approvedKnownHostsReference,
  });
}

function sameProfileIdentity(left: ApprovedProfileIdentity, right: ApprovedProfileIdentity): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function canonicalRequest(request: SudoApprovalRequest, identity: ApprovedProfileIdentity): string {
  return JSON.stringify([identity, request.profileId, request.command, request.args, request.timeoutMs, request.maxOutputBytes]);
}

function requiresSudo(command: string, args: readonly string[]): boolean {
  const isSudo = (value: string): boolean => value === 'sudo' || value.endsWith('/sudo') || value.endsWith('\\sudo.exe');
  return isSudo(command) || args.some(isSudo);
}

function approvalToken(): string {
  return `${Date.now().toString(36)}-${cryptoRandomToken()}`;
}

function cryptoRandomToken(): string {
  return randomBytes(32).toString('hex');
}

/** In-memory, request-bound, expiring and one-shot approval capability. */
export class SudoApprovalStore {
  private readonly approvals = new Map<string, { readonly requestHash: string; readonly expiresAt: number; used: boolean }>();

  issue(request: SudoApprovalRequest, identity: ApprovedProfileIdentity, now = Date.now()): SudoApprovalRecord {
    const token = approvalToken();
    const expiresAt = now + APPROVAL_TTL_MS;
    this.approvals.set(token, { requestHash: canonicalRequest(request, identity), expiresAt, used: false });
    return Object.freeze({ token, request: Object.freeze({ ...request, args: Object.freeze([...request.args]) }), expiresAt });
  }

  consume(
    token: string,
    request: SudoApprovalRequest,
    identity: ApprovedProfileIdentity,
    now = Date.now(),
  ): 'approved' | 'expired' | 'altered' | 'reused' {
    const record = this.approvals.get(token);
    if (record === undefined || record.used) return 'reused';
    if (record.expiresAt <= now) {
      this.approvals.delete(token);
      return 'expired';
    }
    if (record.requestHash !== canonicalRequest(request, identity)) return 'altered';
    record.used = true;
    this.approvals.delete(token);
    return 'approved';
  }
}

export interface RemoteCommandExecutionDependencies {
  readonly profiles: RemoteCommandProfileProvider;
  readonly connectionValidation: ConnectionValidationProvider;
  readonly transport: RemoteCommandTransport;
  readonly sudoApprovals?: SudoApprovalStore;
  readonly humanApproval?: HumanSudoApprovalProvider;
  readonly auditSink?: (serializedEvent: string) => void;
  readonly now?: () => number;
}

function safeResult(
  profileId: string,
  outcome: RemoteExecutionOutcome,
  code: RemoteExecutionCode,
  result?: Partial<RemoteCommandResult>,
): RemoteCommandResult {
  return {
    profileId,
    outcome,
    code,
    exitCode: result?.exitCode ?? null,
    stdout: result?.stdout ?? '',
    stderr: result?.stderr ?? '',
    outputTruncated: result?.outputTruncated ?? false,
  };
}

function boundedTransportResult(result: RemoteCommandTransportResult, maxOutputBytes: number): RemoteCommandTransportResult {
  const stdout = typeof result.stdout === 'string' ? result.stdout : '';
  const stderr = typeof result.stderr === 'string' ? result.stderr : '';
  const stdoutBytes = Buffer.from(stdout, 'utf8');
  const stderrBytes = Buffer.from(stderr, 'utf8');
  const combined = Buffer.concat([stdoutBytes, stderrBytes]);
  const truncate = (value: Buffer, limit: number): string => {
    let text = value.subarray(0, limit).toString('utf8');
    while (Buffer.byteLength(text, 'utf8') > limit) text = text.slice(0, -1);
    return text;
  };
  const limitedStdout = truncate(stdoutBytes, maxOutputBytes);
  const limitedStderr = truncate(stderrBytes, Math.max(0, maxOutputBytes - Buffer.byteLength(limitedStdout, 'utf8')));
  const exitCode =
    result.exitCode === null || (typeof result.exitCode === 'number' && Number.isSafeInteger(result.exitCode)) ? result.exitCode : null;
  return {
    exitCode,
    stdout: limitedStdout,
    stderr: limitedStderr,
    outputTruncated: result.outputTruncated === true || combined.byteLength > maxOutputBytes,
  };
}

async function boundedOperation<T>(operation: (signal: AbortSignal) => Promise<T>, timeoutMs: number, signal: AbortSignal | undefined): Promise<T> {
  const controller = new AbortController();
  let settled = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  return new Promise((resolve, reject) => {
    const cleanup = (): void => {
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    };
    const settle = (action: () => void): void => {
      if (settled) return;
      settled = true;
      cleanup();
      action();
    };
    const abort = (): void => {
      controller.abort();
      settle(() => reject(new RemoteExecutionError('cancelled', 'Remote command cancelled')));
    };
    timer = setTimeout(() => {
      controller.abort();
      settle(() => reject(new RemoteExecutionError('timeout', 'Remote command timed out')));
    }, timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) return abort();
    void operation(controller.signal).then(
      (result) => settle(() => resolve(result)),
      (error: unknown) => settle(() => reject(error)),
    );
  });
}

function remainingTimeout(startedAt: number, timeoutMs: number): number {
  return Math.max(1, timeoutMs - (Date.now() - startedAt));
}

async function boundedTransportExecute(
  transport: RemoteCommandTransport,
  request: RemoteCommandTransportRequest,
  signal: AbortSignal | undefined,
): Promise<RemoteCommandTransportResult> {
  return boundedOperation((operationSignal) => transport.execute(request, operationSignal), request.timeoutMs, signal);
}

function mapTransportError(error: unknown): RemoteExecutionCode {
  const code = error instanceof RemoteExecutionError ? error.code : (error as { code?: unknown })?.code;
  if (code === 'authentication-failure' || code === 'authentication' || code === 'unsupported-authentication' || code === 'credential-unavailable')
    return 'authentication-failure';
  if (code === 'host-key-failure' || code === 'known-hosts-fingerprint-mismatch' || code === 'known-hosts-unavailable') return 'host-key-failure';
  if (code === 'connection-failure' || code === 'connection' || code === 'ssh-connection-failed') return 'connection-failure';
  if (code === 'windows-agent-key-unsupported') return 'windows-agent-key-unsupported';
  if (code === 'timeout' || code === 'ssh-timeout') return 'timeout';
  if (code === 'cancelled' || code === 'AbortError') return 'cancelled';
  return 'remote-failure';
}

function writeRemoteAudit(
  sink: ((serializedEvent: string) => void) | undefined,
  request: RemoteCommandRequest,
  approvalState: SudoApprovalState,
  result: RemoteCommandResult,
  durationMs: number,
): boolean {
  if (sink === undefined) return true;
  try {
    sink(
      serializeRemoteAuditEvent({
        profileId: request.profileId,
        command: request.command,
        args: request.args,
        approvalState,
        durationMs,
        exitCode: result.exitCode,
        outcome: result.outcome,
        code: result.code,
      }),
    );
    return true;
  } catch {
    // A remote attempt without a durable local audit is not reported as success.
    return false;
  }
}

function auditedResult(
  sink: ((serializedEvent: string) => void) | undefined,
  request: RemoteCommandRequest,
  approvalState: SudoApprovalState,
  result: RemoteCommandResult,
  durationMs: number,
): RemoteCommandResult {
  return writeRemoteAudit(sink, request, approvalState, result, durationMs) ? result : safeResult(request.profileId, 'failure', 'provider-failure');
}

export class RemoteCommandExecutionProvider {
  private readonly approvals: SudoApprovalStore;
  private readonly now: () => number;

  constructor(private readonly dependencies: RemoteCommandExecutionDependencies) {
    this.approvals = dependencies.sudoApprovals ?? new SudoApprovalStore();
    this.now = dependencies.now ?? Date.now;
  }

  withHumanSudoApprovalProvider(humanApproval: HumanSudoApprovalProvider): RemoteCommandExecutionProvider {
    return new RemoteCommandExecutionProvider({ ...this.dependencies, humanApproval });
  }

  withAuditSink(auditSink: (serializedEvent: string) => void): RemoteCommandExecutionProvider {
    return new RemoteCommandExecutionProvider({ ...this.dependencies, auditSink });
  }

  async requestSudoApproval(
    input: unknown,
    signal?: AbortSignal,
  ): Promise<{ readonly approved: boolean; readonly token?: string; readonly expiresAt?: number }> {
    const request = parseRequest(input);
    const startedAt = this.now();
    const rejected = (): { readonly approved: boolean } => {
      const result = safeResult(request.profileId, 'approval-required', 'approval-required');
      writeRemoteAudit(this.dependencies.auditSink, request, 'rejected', result, Math.max(0, this.now() - startedAt));
      return { approved: false };
    };
    if (request.approvalToken !== undefined) return rejected();
    const sudoRequest: SudoApprovalRequest = {
      profileId: request.profileId,
      command: request.command,
      args: request.args,
      timeoutMs: request.timeoutMs!,
      maxOutputBytes: request.maxOutputBytes!,
    };
    if (!requiresSudo(request.command, request.args) || this.dependencies.humanApproval === undefined) return rejected();
    let profile: ConnectionProfile | undefined;
    try {
      profile = await this.dependencies.profiles.getProfile(request.profileId, signal);
    } catch {
      return rejected();
    }
    if (profile === undefined) return rejected();
    let approved = false;
    try {
      approved = (await this.dependencies.humanApproval.approve(sudoRequest, signal)) === true;
    } catch {
      approved = false;
    }
    if (!approved) return rejected();
    const approvalResult = safeResult(request.profileId, 'success', 'success');
    if (!writeRemoteAudit(this.dependencies.auditSink, request, 'approved', approvalResult, Math.max(0, this.now() - startedAt))) {
      return { approved: false };
    }
    const record = this.approvals.issue(sudoRequest, profileIdentity(profile), this.now());
    return { approved: true, token: record.token, expiresAt: record.expiresAt };
  }

  async execute(input: unknown, signal?: AbortSignal): Promise<RemoteCommandResult> {
    let request: RemoteCommandRequest;
    try {
      request = parseRequest(input);
    } catch {
      const invalid = safeResult('unknown', 'failure', 'invalid-input');
      writeRemoteAudit(this.dependencies.auditSink, { profileId: 'unknown', command: '[invalid]', args: [] }, 'rejected', invalid, 0);
      return invalid;
    }
    const startedAt = this.now();
    let approvalState: SudoApprovalState = 'not-required';
    const sudoRequest: SudoApprovalRequest = {
      profileId: request.profileId,
      command: request.command,
      args: request.args,
      timeoutMs: request.timeoutMs!,
      maxOutputBytes: request.maxOutputBytes!,
    };
    let approvedProfile: ConnectionProfile | undefined;
    if (requiresSudo(request.command, request.args)) {
      try {
        approvedProfile = await boundedOperation(
          (profileSignal) => Promise.resolve(this.dependencies.profiles.getProfile(request.profileId, profileSignal)),
          remainingTimeout(startedAt, request.timeoutMs!),
          signal,
        );
      } catch (error) {
        const code = signal?.aborted ? 'cancelled' : mapTransportError(error);
        const failed = safeResult(request.profileId, code === 'timeout' ? 'timeout' : code === 'cancelled' ? 'cancelled' : 'failure', code);
        return auditedResult(this.dependencies.auditSink, request, 'rejected', failed, Math.max(0, this.now() - startedAt));
      }
      if (approvedProfile === undefined) {
        const result = safeResult(request.profileId, 'failure', 'provider-failure');
        return auditedResult(this.dependencies.auditSink, request, 'rejected', result, Math.max(0, this.now() - startedAt));
      }
      if (request.approvalToken === undefined) {
        approvalState = 'blocked';
        const result = safeResult(request.profileId, 'approval-required', 'approval-required');
        return auditedResult(this.dependencies.auditSink, request, approvalState, result, Math.max(0, this.now() - startedAt));
      }
      const consumed = this.approvals.consume(request.approvalToken, sudoRequest, profileIdentity(approvedProfile), this.now());
      approvalState = consumed;
      if (consumed !== 'approved') {
        const code = consumed === 'expired' ? 'approval-expired' : consumed === 'altered' ? 'approval-altered' : 'approval-reused';
        const result = safeResult(request.profileId, 'approval-required', code);
        return auditedResult(this.dependencies.auditSink, request, approvalState, result, Math.max(0, this.now() - startedAt));
      }
    }
    if (signal?.aborted) {
      const result = safeResult(request.profileId, 'cancelled', 'cancelled');
      return auditedResult(this.dependencies.auditSink, request, approvalState, result, Math.max(0, this.now() - startedAt));
    }
    try {
      const validation = await boundedOperation(
        (validationSignal) => this.dependencies.connectionValidation.validateConnection({ profileId: request.profileId }, validationSignal),
        remainingTimeout(startedAt, request.timeoutMs!),
        signal,
      );
      if (validation.profileId !== request.profileId || validation.ready !== true) {
        throw new RemoteExecutionError('provider-failure', 'Remote profile validation failed');
      }
      const profile = await boundedOperation(
        (profileSignal) => Promise.resolve(this.dependencies.profiles.getProfile(request.profileId, profileSignal)),
        remainingTimeout(startedAt, request.timeoutMs!),
        signal,
      );
      if (profile === undefined) throw new RemoteExecutionError('provider-failure', 'Remote profile is unavailable');
      if (approvedProfile !== undefined && !sameProfileIdentity(profileIdentity(approvedProfile), profileIdentity(profile))) {
        const altered = safeResult(request.profileId, 'approval-required', 'approval-altered');
        return auditedResult(this.dependencies.auditSink, request, 'altered', altered, Math.max(0, this.now() - startedAt));
      }
      const result = boundedTransportResult(
        await boundedTransportExecute(
          this.dependencies.transport,
          {
            profile,
            command: request.command,
            args: request.args,
            timeoutMs: remainingTimeout(startedAt, request.timeoutMs!),
            maxOutputBytes: request.maxOutputBytes!,
          },
          signal,
        ),
        request.maxOutputBytes!,
      );
      const outcome: RemoteExecutionOutcome = result.exitCode === 0 ? 'success' : 'failure';
      const safe = safeResult(request.profileId, outcome, outcome === 'success' ? 'success' : 'remote-failure', result);
      return auditedResult(this.dependencies.auditSink, request, approvalState, safe, Math.max(0, this.now() - startedAt));
    } catch (error) {
      const code = signal?.aborted ? 'cancelled' : mapTransportError(error);
      const outcome: RemoteExecutionOutcome = code === 'timeout' ? 'timeout' : code === 'cancelled' ? 'cancelled' : 'failure';
      const safe = safeResult(request.profileId, outcome, code);
      return auditedResult(this.dependencies.auditSink, request, approvalState, safe, Math.max(0, this.now() - startedAt));
    }
  }
}

export interface Ssh2ClientLike {
  on(event: 'ready' | 'error' | 'end' | 'close', listener: (...args: readonly unknown[]) => void): this;
  connect(config: ConnectConfig): this;
  exec(command: string, callback: (error: Error | undefined, channel: ClientChannel) => void): void;
  end(): void;
  destroy(): void;
}

export type Ssh2ClientFactory = () => Ssh2ClientLike;

function fingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function remoteCommand(command: string, args: readonly string[]): string {
  return [command, ...args].map(shellQuote).join(' ');
}

/** SSH2 transport: no local shell, host verification before password lookup, bounded streams and cleanup. */
export class Ssh2RemoteCommandTransport implements RemoteCommandTransport {
  constructor(
    private readonly credentials?: { getPassword(reference: string): Promise<{ readonly password: string }> },
    private readonly agent?: string,
    private readonly clients: Ssh2ClientFactory = () => new Client(),
  ) {}

  execute(request: RemoteCommandTransportRequest, signal?: AbortSignal): Promise<RemoteCommandTransportResult> {
    if (signal?.aborted) return Promise.reject(new RemoteExecutionError('cancelled', 'Remote command cancelled'));
    return new Promise((resolve, reject) => {
      const client = this.clients();
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let outputBytes = 0;
      let finished = false;
      let hostVerified = false;
      let hostKeyRejected = false;
      let authenticationStarted = false;
      let ready = false;
      let channel: ClientChannel | undefined;
      let timedOut = false;
      const finish = (error?: RemoteExecutionError, exitCode: number | null = null) => {
        if (finished) return;
        finished = true;
        if (timer !== undefined) clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        try {
          if (channel !== undefined) channel.close();
          client.end();
        } catch {
          try {
            client.destroy();
          } catch {
            // Cleanup is best effort after the bounded connection ended.
          }
        }
        if (error !== undefined) reject(error);
        else
          resolve({
            exitCode,
            stdout: Buffer.concat(stdout).toString('utf8'),
            stderr: Buffer.concat(stderr).toString('utf8'),
            outputTruncated: outputBytes > request.maxOutputBytes,
          });
      };
      const abort = () => {
        try {
          channel?.close();
          client.destroy();
        } finally {
          finish(new RemoteExecutionError('cancelled', 'Remote command cancelled'));
        }
      };
      const timeout = () => {
        timedOut = true;
        try {
          channel?.close();
          client.destroy();
        } finally {
          finish(new RemoteExecutionError('timeout', 'Remote command timed out'));
        }
      };
      const timer = setTimeout(timeout, request.timeoutMs);
      signal?.addEventListener('abort', abort, { once: true });
      client.on('error', () => {
        const code = ready
          ? 'connection-failure'
          : hostKeyRejected
            ? 'host-key-failure'
            : authenticationStarted
              ? 'authentication-failure'
              : 'connection-failure';
        finish(new RemoteExecutionError(code, 'Remote SSH connection failed'));
      });
      client.on('close', () => {
        if (!finished && timedOut) finish(new RemoteExecutionError('timeout', 'Remote command timed out'));
      });
      try {
        const authHandler: AuthHandlerMiddleware = (_methodsLeft, _partialSuccess, callback: NextAuthHandler) => {
          authenticationStarted = true;
          if (!hostVerified || this.credentials === undefined) return callback('none');
          void this.credentials
            .getPassword(request.profile.credentialReference!)
            .then((credential) => callback({ type: 'password', username: request.profile.user, password: credential.password }))
            .catch(() => callback('none'));
        };
        const config: ConnectConfig = {
          host: request.profile.host,
          port: request.profile.port,
          username: request.profile.user,
          readyTimeout: request.timeoutMs,
          hostVerifier: (key: Buffer) => {
            hostVerified = fingerprint(key) === request.profile.expectedHostFingerprint;
            hostKeyRejected = !hostVerified;
            return hostVerified;
          },
          ...(request.profile.authMode === 'agent-key' ? { agent: this.agent ?? process.env.SSH_AUTH_SOCK } : {}),
          ...(request.profile.authMode === 'password' ? { authHandler } : {}),
        };
        client.on('ready', () => {
          ready = true;
          client.exec(remoteCommand(request.command, request.args), (error, execChannel) => {
            if (error !== undefined) return finish(new RemoteExecutionError('remote-failure', 'Remote command failed'));
            channel = execChannel;
            execChannel.on('data', (chunk: Buffer | string) => {
              const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              outputBytes += data.byteLength;
              if (outputBytes <= request.maxOutputBytes) stdout.push(data);
              else if (outputBytes - data.byteLength < request.maxOutputBytes)
                stdout.push(data.subarray(0, request.maxOutputBytes - (outputBytes - data.byteLength)));
              if (outputBytes > request.maxOutputBytes) {
                try {
                  execChannel.close();
                } catch {
                  // The close path below still owns cleanup.
                }
              }
            });
            execChannel.stderr.on('data', (chunk: Buffer | string) => {
              const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              outputBytes += data.byteLength;
              if (outputBytes <= request.maxOutputBytes) stderr.push(data);
              else if (outputBytes - data.byteLength < request.maxOutputBytes)
                stderr.push(data.subarray(0, request.maxOutputBytes - (outputBytes - data.byteLength)));
            });
            execChannel.on('close', (code: number | null) => finish(undefined, code));
          });
        });
        client.connect(config);
      } catch {
        finish(new RemoteExecutionError('remote-failure', 'Remote SSH connection failed'));
      }
    });
  }
}

/**
 * Windows deliberately does not use an ambient ssh2 agent for command
 * execution. The existing native verified OpenSSH/identity boundary remains
 * readiness-only until a command-capable native path is available.
 */
export class WindowsRemoteCommandTransport implements RemoteCommandTransport {
  constructor(private readonly passwordTransport: RemoteCommandTransport) {}

  execute(request: RemoteCommandTransportRequest, signal?: AbortSignal): Promise<RemoteCommandTransportResult> {
    if (request.profile.authMode === 'agent-key') {
      return Promise.reject(
        new RemoteExecutionError('windows-agent-key-unsupported', 'Windows agent-key command execution requires the native trust boundary'),
      );
    }
    return this.passwordTransport.execute(request, signal);
  }
}

function redactAuditText(value: string): string {
  return value
    .replace(
      /(\b(?:password|passphrase|token|secret|private(?:[_-]?key)?|api[_-]?key|access[_-]?token|authorization|cookie)\b\s*[=:]\s*)[^\s]+/giu,
      '$1[REDACTED]',
    )
    .replace(/(\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+)[^\s]+/giu, '$1[REDACTED]')
    .replace(/(\b(?:bearer|basic)\s+)[^\s]+/giu, '$1[REDACTED]')
    .replace(/(\b(?:cookie|set-cookie)\s*:\s*)[^,]*/giu, '$1[REDACTED]')
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/giu, '$1[REDACTED]@')
    .replace(/-----begin[^\s]*/giu, '[REDACTED]');
}

function safeAuditCommand(value: unknown): string {
  return typeof value === 'string' ? redactAuditText(value).slice(0, MAX_COMMAND_LENGTH) : '[REDACTED]';
}

function isSensitiveAuditFlag(value: string): boolean {
  return (
    /^-{1,2}(?:password|passphrase|token|secret|private[-_]?key|api[-_]?key|access[-_]?token|authorization|cookie|header)$/iu.test(value) ||
    value === '-H'
  );
}

export function serializeRemoteAuditEvent(input: unknown): string {
  if (!isPlainRecord(input)) return serializeAuditEvent({ code: 'unknown', outcome: 'failure', stage: 'unknown' });
  const profileId = validateProfileIdForAudit(own(input, 'profileId'));
  const command = safeAuditCommand(own(input, 'command'));
  const rawArgs = Array.isArray(own(input, 'args')) ? own(input, 'args') : [];
  const args: string[] = [];
  let redactNext = false;
  for (const value of (rawArgs as unknown[]).slice(0, MAX_ARGUMENTS)) {
    const text = typeof value === 'string' ? value : '[REDACTED]';
    args.push(redactNext ? '[REDACTED]' : safeAuditCommand(text));
    redactNext = isSensitiveAuditFlag(text);
  }
  const approvalState = own(input, 'approvalState');
  const state = ['not-required', 'blocked', 'approved', 'expired', 'altered', 'reused', 'rejected'].includes(String(approvalState))
    ? String(approvalState)
    : 'rejected';
  const allowedCodes = new Set<RemoteExecutionCode>([
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
    'invalid-input',
    'provider-failure',
  ]);
  const requestedCode = own(input, 'code');
  const code = typeof requestedCode === 'string' && allowedCodes.has(requestedCode as RemoteExecutionCode) ? requestedCode : 'provider-failure';
  const requestedOutcome = own(input, 'outcome');
  const outcome: RemoteExecutionOutcome =
    requestedOutcome === 'success' || requestedOutcome === 'timeout' || requestedOutcome === 'cancelled' || requestedOutcome === 'approval-required'
      ? requestedOutcome
      : 'failure';
  const durationValue = own(input, 'durationMs');
  const durationMs = typeof durationValue === 'number' && Number.isSafeInteger(durationValue) ? Math.max(0, Math.min(300_000, durationValue)) : 0;
  return JSON.stringify({
    kind: 'remote-command-audit-event',
    version: 1,
    profileId,
    command,
    args,
    approvalState: state,
    durationMs,
    exitCode: typeof own(input, 'exitCode') === 'number' && Number.isSafeInteger(own(input, 'exitCode')) ? own(input, 'exitCode') : null,
    outcome,
    code,
  });
}

function validateProfileIdForAudit(value: unknown): string {
  return typeof value === 'string' && PROFILE_ID.test(value) ? value : 'unknown';
}
