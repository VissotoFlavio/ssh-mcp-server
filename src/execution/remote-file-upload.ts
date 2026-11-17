import { createHash, randomBytes } from 'node:crypto';

import { Client, type AuthHandlerMiddleware, type ConnectConfig, type NextAuthHandler, type SFTPWrapper } from 'ssh2';

import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { ActionApprovalStore } from './action-approval.js';
import { UnavailableExecutionAuditJournal, type ExecutionAuditHandle, type ExecutionAuditJournal } from './execution-audit-journal.js';
import {
  RemoteCommandConcurrencyLimiter,
  RemoteExecutionError,
  createProfileExecutionAuthorizationProvider,
  type ExecutionAuthorization,
  type ExecutionAuthorizationProvider,
} from './remote-command-execution.js';

export const uploadRemoteFileToolName = 'upload_remote_file';

export const FILE_UPLOAD_DEFAULT_TIMEOUT_MS = 30_000;
export const FILE_UPLOAD_MAX_TIMEOUT_MS = 60_000;
export const FILE_UPLOAD_MAX_BYTES = 1024 * 1024;
const MAX_REMOTE_PATH_LENGTH = 4096;
const PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
// eslint-disable-next-line no-control-regex -- control characters make an approval presentation ambiguous.
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;

export type FileUploadOutcome = 'success' | 'failure' | 'timeout' | 'cancelled' | 'approval-required' | 'unknown';
export type FileUploadCode =
  | 'success'
  | 'connection-failure'
  | 'authentication-failure'
  | 'host-key-failure'
  | 'remote-failure'
  | 'integrity-failure'
  | 'timeout'
  | 'cancelled'
  | 'approval-required'
  | 'approval-expired'
  | 'approval-altered'
  | 'approval-reused'
  | 'execution-limit'
  | 'execution-audit-unavailable'
  | 'outcome-unknown'
  | 'invalid-input'
  | 'provider-failure';

export interface FileUploadRequest {
  readonly profileId: string;
  /** A complete POSIX destination path selected by the caller and presented by the MCP client for approval. */
  readonly remotePath: string;
  readonly content: Buffer;
  readonly sha256: string;
  readonly timeoutMs: number;
  readonly approvalCapability?: string;
}

export interface RemoteFileUploadTransportRequest {
  readonly authorization: ExecutionAuthorization;
  readonly remotePath: string;
  readonly content: Buffer;
  readonly sha256: string;
  readonly timeoutMs: number;
  /** Called durably immediately before the first irreversible remote action. */
  readonly onUploadHandoff?: () => Promise<void> | void;
  /** Called once the transport has handed bytes to the remote session. */
  readonly onUploadStarted?: () => void;
}

export interface RemoteFileUploadTransportResult {
  readonly uploadedBytes: number;
  /** The digest read or otherwise confirmed by the transport after upload. */
  readonly sha256: string;
}

export interface RemoteFileUploadTransport {
  upload(request: RemoteFileUploadTransportRequest, signal?: AbortSignal): Promise<RemoteFileUploadTransportResult>;
}

interface Ssh2ClientLike {
  on(event: 'ready' | 'error' | 'close', listener: (...args: readonly unknown[]) => void): this;
  connect(config: ConnectConfig): this;
  sftp(callback: (error: Error | undefined, sftp: SFTPWrapper) => void): void;
  end(): void;
  destroy(): void;
}

export type Ssh2FileUploadClientFactory = () => Ssh2ClientLike;

export interface RemoteFileUploadDependencies {
  readonly connectionValidation: ConnectionValidationProvider;
  readonly transport: RemoteFileUploadTransport;
  readonly auditJournal?: ExecutionAuditJournal;
  readonly authorizationProvider?: ExecutionAuthorizationProvider;
  readonly concurrency?: RemoteCommandConcurrencyLimiter;
  readonly actionApprovals?: ActionApprovalStore;
}

export interface FileUploadResult {
  readonly operationId: string;
  readonly profileId: string;
  /** Echoes the caller-provided destination; the audit journal never stores it in plaintext. */
  readonly remotePath: string;
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly outcome: FileUploadOutcome;
  readonly code: FileUploadCode;
  readonly integrity: 'verified' | 'unknown';
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function own(value: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined;
}

function inputError(): never {
  throw new RemoteExecutionError('invalid-input', 'Remote file upload input is invalid');
}

function profileId(value: unknown): string {
  if (typeof value !== 'string' || !PROFILE_ID.test(value) || ['__proto__', 'constructor', 'prototype'].includes(value)) inputError();
  return value;
}

function remotePath(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_REMOTE_PATH_LENGTH ||
    !value.startsWith('/') ||
    CONTROL_CHARACTERS.test(value)
  )
    inputError();
  return value;
}

function timeout(value: unknown): number {
  if (value === undefined) return FILE_UPLOAD_DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > FILE_UPLOAD_MAX_TIMEOUT_MS) inputError();
  return value as number;
}

function decodeContent(value: unknown): Buffer {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(FILE_UPLOAD_MAX_BYTES / 3) * 4 + 4) inputError();
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) inputError();
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.length > FILE_UPLOAD_MAX_BYTES || decoded.toString('base64') !== value) inputError();
  return decoded;
}

function approvalCapability(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || CONTROL_CHARACTERS.test(value)) inputError();
  return value;
}

function parse(input: unknown, allowApprovalCapability = false): FileUploadRequest {
  if (!isPlainRecord(input)) inputError();
  const allowed = new Set(['profileId', 'remotePath', 'contentBase64', 'timeoutMs', ...(allowApprovalCapability ? ['approvalCapability'] : [])]);
  if (Reflect.ownKeys(input).some((key) => typeof key !== 'string' || !allowed.has(key))) inputError();
  const content = decodeContent(own(input, 'contentBase64'));
  const capability = allowApprovalCapability ? approvalCapability(own(input, 'approvalCapability')) : undefined;
  return Object.freeze({
    profileId: profileId(own(input, 'profileId')),
    remotePath: remotePath(own(input, 'remotePath')),
    content,
    sha256: createHash('sha256').update(content).digest('hex'),
    timeoutMs: timeout(own(input, 'timeoutMs')),
    ...(capability === undefined ? {} : { approvalCapability: capability }),
  });
}

function approvalBinding(request: FileUploadRequest): string {
  return JSON.stringify([request.profileId, request.remotePath, request.content.length, request.sha256, request.timeoutMs]);
}

function operationId(): string {
  return randomBytes(16).toString('hex');
}

function unknownResult(request: FileUploadRequest, id: string, code: FileUploadCode = 'outcome-unknown'): FileUploadResult {
  return {
    operationId: id,
    profileId: request.profileId,
    remotePath: request.remotePath,
    sha256: request.sha256,
    sizeBytes: request.content.length,
    outcome: 'unknown',
    code,
    integrity: 'unknown',
  };
}

function result(
  request: FileUploadRequest,
  id: string,
  outcome: FileUploadOutcome,
  code: FileUploadCode,
  integrity: 'verified' | 'unknown' = 'unknown',
): FileUploadResult {
  return {
    operationId: id,
    profileId: request.profileId,
    remotePath: request.remotePath,
    sha256: request.sha256,
    sizeBytes: request.content.length,
    outcome,
    code,
    integrity,
  };
}

function mapError(error: unknown): FileUploadCode {
  const code = error instanceof RemoteExecutionError ? error.code : (error as { code?: unknown })?.code;
  if (code === 'authentication-failure' || code === 'authentication' || code === 'credential-unavailable') return 'authentication-failure';
  if (code === 'host-key-failure' || code === 'known-hosts-fingerprint-mismatch') return 'host-key-failure';
  if (code === 'connection-failure' || code === 'connection') return 'connection-failure';
  if (code === 'timeout') return 'timeout';
  if (code === 'cancelled') return 'cancelled';
  if (code === 'execution-audit-unavailable') return 'execution-audit-unavailable';
  if (code === 'outcome-unknown') return 'outcome-unknown';
  return 'remote-failure';
}

function hostFingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`;
}

function sftpCallback(operation: (done: (error?: Error | null) => void) => void): Promise<void> {
  return new Promise<void>((resolve, reject) => operation((error) => (error === undefined ? resolve() : reject(error))));
}

/**
 * Direct SSH2 SFTP upload transport. It receives only a validated immutable
 * authorization and never starts a local shell or child process.
 */
export class Ssh2RemoteFileUploadTransport implements RemoteFileUploadTransport {
  constructor(
    private readonly credentials?: { getPassword(reference: string): Promise<{ readonly password: string }> },
    private readonly agent?: string,
    private readonly clients: Ssh2FileUploadClientFactory = () => new Client(),
  ) {}

  upload(request: RemoteFileUploadTransportRequest, signal?: AbortSignal): Promise<RemoteFileUploadTransportResult> {
    if (signal?.aborted) return Promise.reject(new RemoteExecutionError('cancelled', 'Remote file upload cancelled'));
    return new Promise((resolve, reject) => {
      const client = this.clients();
      let finished = false;
      let ready = false;
      let hostVerified = false;
      let hostKeyRejected = false;
      let authenticationStarted = false;
      let started = false;
      let temporaryPath: string | undefined;
      let sftp: SFTPWrapper | undefined;
      const cleanup = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        try {
          client.end();
        } catch {
          client.destroy();
        }
      };
      const finish = (error?: RemoteExecutionError, value?: RemoteFileUploadTransportResult): void => {
        if (finished) return;
        finished = true;
        cleanup();
        if (error === undefined && value !== undefined) resolve(value);
        else reject(error ?? new RemoteExecutionError('remote-failure', 'Remote file upload failed'));
      };
      const abort = (): void => {
        try {
          client.destroy();
        } finally {
          finish(new RemoteExecutionError(started ? 'outcome-unknown' : 'cancelled', 'Remote file upload cancelled'));
        }
      };
      const timer = setTimeout(() => {
        try {
          client.destroy();
        } finally {
          finish(new RemoteExecutionError(started ? 'outcome-unknown' : 'timeout', 'Remote file upload timed out'));
        }
      }, request.timeoutMs);
      const cleanupTemporary = (): void => {
        if (sftp === undefined || temporaryPath === undefined) return;
        sftp.unlink(temporaryPath, () => undefined);
      };
      signal?.addEventListener('abort', abort, { once: true });
      client.on('error', () => {
        cleanupTemporary();
        const code = started
          ? 'outcome-unknown'
          : hostKeyRejected
            ? 'host-key-failure'
            : authenticationStarted
              ? 'authentication-failure'
              : ready
                ? 'connection-failure'
                : 'connection-failure';
        finish(new RemoteExecutionError(code, 'Remote SSH connection failed'));
      });
      client.on('close', () => {
        if (!finished) finish(new RemoteExecutionError(started ? 'outcome-unknown' : 'connection-failure', 'Remote SSH connection closed'));
      });
      const rename = async (): Promise<void> => {
        if (sftp === undefined || temporaryPath === undefined) throw new Error('SFTP unavailable');
        try {
          await sftpCallback((done) => sftp!.ext_openssh_rename(temporaryPath!, request.remotePath, done));
        } catch {
          await sftpCallback((done) => sftp!.rename(temporaryPath!, request.remotePath, done));
        }
      };
      const startSftp = (): void => {
        client.sftp((error, session) => {
          if (error !== undefined) return finish(new RemoteExecutionError('remote-failure', 'Remote SFTP session failed'));
          sftp = session;
          void (async () => {
            try {
              temporaryPath = `${request.remotePath}.ssh-mcp-upload-${randomBytes(12).toString('hex')}`;
              await request.onUploadHandoff?.();
              started = true;
              request.onUploadStarted?.();
              await new Promise<void>((resolveWrite, rejectWrite) => {
                session.writeFile(temporaryPath!, request.content, { flag: 'w', mode: 0o600 }, (writeError) =>
                  writeError === undefined ? resolveWrite() : rejectWrite(writeError),
                );
              });
              await rename();
              temporaryPath = undefined;
              finish(undefined, { uploadedBytes: request.content.length, sha256: request.sha256 });
            } catch {
              cleanupTemporary();
              finish(new RemoteExecutionError(started ? 'outcome-unknown' : 'remote-failure', 'Remote file upload failed'));
            }
          })();
        });
      };
      try {
        const authHandler: AuthHandlerMiddleware = (_methodsLeft, _partialSuccess, callback: NextAuthHandler) => {
          authenticationStarted = true;
          if (!hostVerified || this.credentials === undefined) return callback('none');
          void this.credentials
            .getPassword(request.authorization.profile.credentialReference!)
            .then((credential) => callback({ type: 'password', username: request.authorization.profile.user, password: credential.password }))
            .catch(() => callback('none'));
        };
        client.on('ready', () => {
          ready = true;
          startSftp();
        });
        client.connect({
          host: request.authorization.profile.host,
          port: request.authorization.profile.port,
          username: request.authorization.profile.user,
          readyTimeout: request.timeoutMs,
          hostVerifier: (key: Buffer) => {
            hostVerified = hostFingerprint(key) === request.authorization.profile.expectedHostFingerprint;
            hostKeyRejected = !hostVerified;
            return hostVerified;
          },
          ...(request.authorization.profile.authMode === 'agent-key' ? { agent: this.agent ?? process.env.SSH_AUTH_SOCK } : {}),
          ...(request.authorization.profile.authMode === 'password' ? { authHandler } : {}),
        });
      } catch {
        finish(new RemoteExecutionError('connection-failure', 'Remote SSH connection failed'));
      }
    });
  }
}

/** Windows may use the SSH2 transport only for the approved password profile path. */
export class WindowsPasswordFileUploadTransport implements RemoteFileUploadTransport {
  constructor(private readonly passwordTransport: RemoteFileUploadTransport) {}

  upload(request: RemoteFileUploadTransportRequest, signal?: AbortSignal): Promise<RemoteFileUploadTransportResult> {
    if (request.authorization.profile.authMode !== 'password')
      return Promise.reject(new RemoteExecutionError('windows-agent-key-unsupported', 'Windows agent-key upload requires the native trust boundary'));
    return this.passwordTransport.upload(request, signal);
  }
}

export class RemoteFileUploadProvider {
  private readonly auditJournal: ExecutionAuditJournal;
  private readonly concurrency: RemoteCommandConcurrencyLimiter;
  private readonly actionApprovals: ActionApprovalStore;

  constructor(private readonly dependencies: RemoteFileUploadDependencies) {
    this.concurrency = dependencies.concurrency ?? new RemoteCommandConcurrencyLimiter();
    this.auditJournal = dependencies.auditJournal ?? new UnavailableExecutionAuditJournal();
    this.actionApprovals = dependencies.actionApprovals ?? new ActionApprovalStore();
  }

  async requestActionApproval(
    input: unknown,
    signal?: AbortSignal,
  ): Promise<{ readonly approved: boolean; readonly code: string; readonly capability?: string; readonly summary?: object }> {
    let request: FileUploadRequest;
    try {
      request = parse(input);
      const authorization = await (
        this.dependencies.authorizationProvider ?? createProfileExecutionAuthorizationProvider(this.dependencies.connectionValidation)
      ).authorize(request.profileId, signal);
      return {
        approved: true,
        code: 'approved',
        capability: this.actionApprovals.issue('file-upload', approvalBinding(request), authorization),
        summary: {
          action: 'file-upload',
          profileId: request.profileId,
          remotePath: request.remotePath,
          sizeBytes: request.content.length,
          sha256: request.sha256,
        },
      };
    } catch {
      return { approved: false, code: signal?.aborted ? 'cancelled' : 'approval-unavailable' };
    }
  }

  async upload(input: unknown, signal?: AbortSignal): Promise<FileUploadResult> {
    let request: FileUploadRequest;
    try {
      request = parse(input, true);
    } catch {
      return {
        operationId: operationId(),
        profileId: 'unknown',
        remotePath: '',
        sha256: '',
        sizeBytes: 0,
        outcome: 'failure',
        code: 'invalid-input',
        integrity: 'unknown',
      };
    }
    const id = operationId();
    const release = this.concurrency.tryAcquire();
    if (release === undefined) return result(request, id, 'failure', 'execution-limit');
    let journal: ExecutionAuditHandle | undefined;
    let handedOff = false;
    let authorization: ExecutionAuthorization | undefined;
    const finish = async (value: FileUploadResult): Promise<FileUploadResult> => {
      try {
        await journal?.finish({ outcome: value.outcome, code: value.code, exitCode: null, durationMs: 0 });
        return value;
      } catch {
        return unknownResult(request, id);
      } finally {
        release();
      }
    };
    try {
      const consumed = this.actionApprovals.consume('file-upload', approvalBinding(request), request.approvalCapability);
      if (consumed.status !== 'approved' || consumed.authorization === undefined) {
        const code: FileUploadCode =
          consumed.status === 'expired' ? 'approval-expired' : consumed.status === 'altered' ? 'approval-altered' : 'approval-reused';
        return await finish(result(request, id, 'approval-required', code));
      }
      try {
        authorization = consumed.authorization;
      } catch {
        await consumed.authorization.release?.();
        return await finish(result(request, id, 'approval-required', 'approval-expired'));
      }
      try {
        const args = [request.remotePath, request.sha256, String(request.content.length)];
        journal = await this.auditJournal.begin({
          operationId: id,
          profileId: request.profileId,
          command: '[file-upload]',
          args: ['[redacted]', request.sha256, String(request.content.length)],
          argsHmac: await this.auditJournal.digestArguments(args),
          approvalState: 'intent',
        });
      } catch {
        await authorization.release?.();
        authorization = undefined;
        return await finish(result(request, id, 'failure', 'execution-audit-unavailable'));
      }
      const uploaded = await this.dependencies.transport.upload(
        {
          authorization,
          remotePath: request.remotePath,
          content: request.content,
          sha256: request.sha256,
          timeoutMs: request.timeoutMs,
          onUploadHandoff: async () => {
            await journal?.handoff?.();
            handedOff = true;
          },
        },
        signal,
      );
      await authorization.release?.();
      authorization = undefined;
      if (uploaded.uploadedBytes !== request.content.length || uploaded.sha256 !== request.sha256)
        return await finish(result(request, id, 'failure', 'integrity-failure'));
      return await finish(result(request, id, 'success', 'success', 'verified'));
    } catch (error) {
      const code = mapError(error);
      await authorization?.release?.();
      if (handedOff) return await finish(unknownResult(request, id));
      if (code === 'timeout') return await finish(result(request, id, 'timeout', code));
      if (code === 'cancelled') return await finish(result(request, id, 'cancelled', code));
      return await finish(result(request, id, 'failure', code));
    }
  }
}
