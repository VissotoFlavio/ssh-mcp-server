import { createHash, randomBytes } from 'node:crypto';

import type { ConnectionValidationProvider } from '../validation/trusted-connection-validation.js';

import { UnavailableExecutionAuditJournal, type ExecutionAuditHandle, type ExecutionAuditJournal } from './execution-audit-journal.js';
import {
  RemoteCommandConcurrencyLimiter,
  RemoteExecutionError,
  createProfileExecutionAuthorizationProvider,
  type ExecutionAuthorization,
  type ExecutionAuthorizationProvider,
  type HumanSudoApprovalDecision,
} from './remote-command-execution.js';

export const requestFileUploadApprovalToolName = 'request_file_upload_approval';
export const uploadRemoteFileToolName = 'upload_remote_file';

export const FILE_UPLOAD_DEFAULT_TIMEOUT_MS = 30_000;
export const FILE_UPLOAD_MAX_TIMEOUT_MS = 60_000;
export const FILE_UPLOAD_MAX_BYTES = 1024 * 1024;
const APPROVAL_TTL_MS = 60_000;
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
  | 'approval-unavailable'
  | 'approval-busy'
  | 'approval-rejected'
  | 'execution-limit'
  | 'execution-audit-unavailable'
  | 'outcome-unknown'
  | 'invalid-input'
  | 'provider-failure';

export interface FileUploadRequest {
  readonly profileId: string;
  /** A complete POSIX destination path selected by the caller and shown to the human approver. */
  readonly remotePath: string;
  readonly content: Buffer;
  readonly sha256: string;
  readonly timeoutMs: number;
  readonly approvalToken?: string;
}

export interface FileUploadApprovalRequest {
  readonly profileId: string;
  readonly remotePath: string;
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly timeoutMs: number;
  /** Trusted binding values for a local-only human approval provider. */
  readonly operationId?: string;
  readonly leaseIdentityDigest?: string;
}

export interface HumanFileUploadApprovalProvider {
  /** The provider must render destination, size, and digest without rendering content. */
  approve(request: FileUploadApprovalRequest, signal?: AbortSignal): Promise<HumanSudoApprovalDecision>;
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

export interface RemoteFileUploadDependencies {
  readonly connectionValidation: ConnectionValidationProvider;
  readonly transport: RemoteFileUploadTransport;
  readonly humanApproval?: HumanFileUploadApprovalProvider;
  readonly auditJournal?: ExecutionAuditJournal;
  readonly authorizationProvider?: ExecutionAuthorizationProvider;
  readonly concurrency?: RemoteCommandConcurrencyLimiter;
  readonly now?: () => number;
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

function approvalToken(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || CONTROL_CHARACTERS.test(value)) inputError();
  return value;
}

function parse(input: unknown): FileUploadRequest {
  if (!isPlainRecord(input)) inputError();
  const allowed = new Set(['profileId', 'remotePath', 'contentBase64', 'timeoutMs', 'approvalToken']);
  if (Reflect.ownKeys(input).some((key) => typeof key !== 'string' || !allowed.has(key))) inputError();
  const content = decodeContent(own(input, 'contentBase64'));
  const token = approvalToken(own(input, 'approvalToken'));
  return Object.freeze({
    profileId: profileId(own(input, 'profileId')),
    remotePath: remotePath(own(input, 'remotePath')),
    content,
    sha256: createHash('sha256').update(content).digest('hex'),
    timeoutMs: timeout(own(input, 'timeoutMs')),
    ...(token === undefined ? {} : { approvalToken: token }),
  });
}

function operationId(): string {
  return randomBytes(16).toString('hex');
}

function requestHash(request: FileUploadRequest, identityDigest: string): string {
  return createHash('sha256')
    .update(JSON.stringify([identityDigest, request.profileId, request.remotePath, request.content.length, request.sha256, request.timeoutMs]))
    .digest('hex');
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
  if (code === 'approval-expired') return 'approval-expired';
  if (code === 'approval-altered') return 'approval-altered';
  if (code === 'approval-reused') return 'approval-reused';
  return 'remote-failure';
}

class UploadApprovalStore {
  private pending = false;
  private readonly approvals = new Map<
    string,
    { readonly requestHash: string; readonly authorization: ExecutionAuthorization; readonly expiresAt: number; used: boolean }
  >();

  tryBeginPending(): boolean {
    if (this.pending) return false;
    this.pending = true;
    return true;
  }

  endPending(): void {
    this.pending = false;
  }

  issue(request: FileUploadRequest, authorization: ExecutionAuthorization, now: number): string {
    const token = `${now.toString(36)}-${randomBytes(32).toString('hex')}`;
    const expiresAt = now + APPROVAL_TTL_MS;
    this.approvals.set(token, { requestHash: requestHash(request, authorization.identityDigest), authorization, expiresAt, used: false });
    const expiry = setTimeout(() => {
      const current = this.approvals.get(token);
      if (current?.used !== true && current?.expiresAt === expiresAt) {
        this.approvals.delete(token);
        void current.authorization.release?.().catch(() => undefined);
      }
    }, APPROVAL_TTL_MS);
    expiry.unref?.();
    return token;
  }

  consume(
    token: string,
    request: FileUploadRequest,
    now: number,
  ): { readonly state: 'approved' | 'expired' | 'altered' | 'reused'; readonly authorization?: ExecutionAuthorization } {
    const approval = this.approvals.get(token);
    if (approval === undefined || approval.used) return { state: 'reused' };
    if (approval.expiresAt <= now) {
      this.approvals.delete(token);
      void approval.authorization.release?.().catch(() => undefined);
      return { state: 'expired' };
    }
    if (approval.requestHash !== requestHash(request, approval.authorization.identityDigest)) return { state: 'altered' };
    approval.used = true;
    this.approvals.delete(token);
    return { state: 'approved', authorization: approval.authorization };
  }
}

export class RemoteFileUploadProvider {
  private readonly approvals = new UploadApprovalStore();
  private readonly auditJournal: ExecutionAuditJournal;
  private readonly concurrency: RemoteCommandConcurrencyLimiter;
  private readonly now: () => number;

  constructor(private readonly dependencies: RemoteFileUploadDependencies) {
    this.concurrency = dependencies.concurrency ?? new RemoteCommandConcurrencyLimiter();
    this.auditJournal = dependencies.auditJournal ?? new UnavailableExecutionAuditJournal();
    this.now = dependencies.now ?? Date.now;
  }

  async requestApproval(
    input: unknown,
    signal?: AbortSignal,
  ): Promise<{
    readonly approved: boolean;
    readonly code: 'approved' | 'approval-unavailable' | 'approval-rejected' | 'approval-busy' | 'cancelled' | 'invalid-input';
    readonly operationId: string;
    readonly capability?: string;
  }> {
    const id = operationId();
    let request: FileUploadRequest;
    try {
      request = parse(input);
      if (request.approvalToken !== undefined) return { approved: false, code: 'invalid-input', operationId: id };
    } catch {
      return { approved: false, code: 'invalid-input', operationId: id };
    }
    if (!this.approvals.tryBeginPending()) return { approved: false, code: 'approval-busy', operationId: id };
    try {
      if (this.dependencies.humanApproval === undefined) return { approved: false, code: 'approval-unavailable', operationId: id };
      let authorization: ExecutionAuthorization;
      try {
        authorization = await (
          this.dependencies.authorizationProvider ?? createProfileExecutionAuthorizationProvider(this.dependencies.connectionValidation, this.now)
        ).authorize(request.profileId, signal);
      } catch {
        return { approved: false, code: signal?.aborted ? 'cancelled' : 'approval-unavailable', operationId: id };
      }
      try {
        const approved = await this.dependencies.humanApproval.approve(
          {
            profileId: request.profileId,
            remotePath: request.remotePath,
            sizeBytes: request.content.length,
            sha256: request.sha256,
            timeoutMs: request.timeoutMs,
            operationId: id,
            leaseIdentityDigest: authorization.identityDigest,
          },
          signal,
        );
        if (approved !== true) {
          await authorization.release?.();
          return {
            approved: false,
            code: approved === 'unavailable' ? 'approval-unavailable' : signal?.aborted ? 'cancelled' : 'approval-rejected',
            operationId: id,
          };
        }
        return { approved: true, code: 'approved', operationId: id, capability: this.approvals.issue(request, authorization, this.now()) };
      } catch {
        await authorization.release?.();
        return { approved: false, code: signal?.aborted ? 'cancelled' : 'approval-unavailable', operationId: id };
      }
    } finally {
      this.approvals.endPending();
    }
  }

  async upload(input: unknown, signal?: AbortSignal): Promise<FileUploadResult> {
    let request: FileUploadRequest;
    try {
      request = parse(input);
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
      if (request.approvalToken === undefined) return await finish(result(request, id, 'approval-required', 'approval-required'));
      const consumed = this.approvals.consume(request.approvalToken, request, this.now());
      if (consumed.state !== 'approved' || consumed.authorization === undefined) {
        const code: FileUploadCode =
          consumed.state === 'expired' ? 'approval-expired' : consumed.state === 'altered' ? 'approval-altered' : 'approval-reused';
        return await finish(result(request, id, 'approval-required', code));
      }
      try {
        authorization = consumed.authorization.consume();
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
          approvalState: 'approved',
        });
        await journal.approval?.('approval-approved');
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
