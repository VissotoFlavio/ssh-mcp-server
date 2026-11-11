import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { createRequire } from 'node:module';
import { createConnection, type Socket } from 'node:net';
import { dirname } from 'node:path';
import process from 'node:process';

import type {
  ApprovedProfileIdentity,
  HumanSudoApprovalDecision,
  HumanSudoApprovalProvider,
  SudoApprovalRequest,
} from './remote-command-execution.js';

export type HumanApproverIpcPlatform = 'posix' | 'windows';

const IPC_VERSION = 1 as const;
const MAX_FRAME_BYTES = 64 * 1024;
const MAX_UNIX_SOCKET_PATH_BYTES = 107;
const MAX_IPC_TIMEOUT_MS = 60_000;
const APPROVER_SOCKET_ENV = 'SSH_MCP_APPROVER_SOCKET';
const APPROVER_SECRET_FILE_ENV = 'SSH_MCP_APPROVER_SECRET_FILE';
const APPROVER_PIPE_ENV = 'SSH_MCP_APPROVER_PIPE';
const APPROVER_SECRET_ENV = 'SSH_MCP_APPROVER_SECRET';
const APPROVER_SECRET_BYTES = 32;
const HEX_64 = /^[a-f0-9]{64}$/u;
const require = createRequire(import.meta.url);

interface PosixPeerCredentialsBinding {
  getPeerCredentials(descriptor: number): { readonly uid: number; readonly pid?: number };
}

function loadPosixPeerCredentialsBinding(): PosixPeerCredentialsBinding | undefined {
  if (process.platform !== 'linux' && process.platform !== 'darwin') return undefined;
  try {
    const binding = require('../../build/Release/posix_peer_credentials.node') as unknown;
    if (typeof binding !== 'object' || binding === null || typeof (binding as { getPeerCredentials?: unknown }).getPeerCredentials !== 'function')
      return undefined;
    return binding as PosixPeerCredentialsBinding;
  } catch {
    return undefined;
  }
}

const posixPeerCredentialsBinding = loadPosixPeerCredentialsBinding();

export interface HumanApproverIpcRequest {
  readonly version: typeof IPC_VERSION;
  readonly type: 'approval-request';
  readonly nonce: string;
  readonly requestDigest: string;
  readonly operationId: string;
  readonly leaseIdentityDigest: string;
  /** Contains only the immutable destination presentation needed by the local approver. */
  readonly request: Readonly<{
    readonly profileId: string;
    readonly command: string;
    readonly args: readonly string[];
    readonly timeoutMs: number;
    readonly maxOutputBytes: number;
    readonly presentation: Readonly<{
      readonly host: string;
      readonly port: number;
      readonly user: string;
      readonly expectedHostFingerprint: string;
      readonly authMode: ApprovedProfileIdentity['authMode'];
      readonly approvedKnownHostsReference: string;
    }>;
  }>;
}

export interface HumanApproverIpcResponse {
  readonly version: typeof IPC_VERSION;
  readonly type: 'approval-response';
  readonly nonce: string;
  readonly requestDigest: string;
  readonly approved: boolean;
}

export interface HumanApproverIpcChannel {
  /** Boolean is retained only for already-injected in-process test/host channels. */
  approve(request: HumanApproverIpcRequest, signal?: AbortSignal): Promise<HumanApproverIpcResponse | boolean>;
}

export interface WindowsNamedPipeSecurityBoundary {
  /** Must be implemented by a native boundary that authenticates the peer SID and ACL. */
  approve(request: HumanApproverIpcRequest, signal?: AbortSignal): Promise<HumanApproverIpcResponse>;
}

function windowsNativeMac(secret: Buffer, domain: string, fields: readonly unknown[]): string {
  return createHmac('sha256', secret)
    .update(`${domain}\0${JSON.stringify(fields)}`, 'utf8')
    .digest('hex');
}

function readWindowsSecret(environment: NodeJS.ProcessEnv): Buffer | undefined {
  const value = environment[APPROVER_SECRET_ENV];
  if (typeof value !== 'string' || !HEX_64.test(value)) return undefined;
  return Buffer.from(value, 'hex');
}

/** Client side of the packaged native broker. The broker owns the pipe ACL and peer SID check. */
export class EnvironmentWindowsNamedPipeSecurityBoundary implements WindowsNamedPipeSecurityBoundary {
  constructor(
    private readonly pipePath: string,
    private readonly secret: Buffer,
    private readonly timeoutMs = MAX_IPC_TIMEOUT_MS,
  ) {}

  approve(request: HumanApproverIpcRequest, signal?: AbortSignal): Promise<HumanApproverIpcResponse> {
    if (!this.pipePath.startsWith('\\\\.\\pipe\\') || signal?.aborted) return Promise.reject(new Error('approver unavailable'));
    return new Promise<HumanApproverIpcResponse>((resolve, reject) => {
      let settled = false;
      let data = Buffer.alloc(0);
      const socket = createConnection({ path: this.pipePath });
      const cleanup = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
      };
      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        cleanup();
        closeSocket(socket);
        reject(error);
      };
      const finish = (value: HumanApproverIpcResponse): void => {
        if (settled) return;
        settled = true;
        cleanup();
        closeSocket(socket);
        resolve(value);
      };
      const abort = (): void => fail(new Error('approver cancelled'));
      const timer = setTimeout(() => fail(new Error('approver timeout')), Math.min(Math.max(1, this.timeoutMs), MAX_IPC_TIMEOUT_MS));
      signal?.addEventListener('abort', abort, { once: true });
      socket.on('connect', () => {
        try {
          const requestMac = windowsNativeMac(this.secret, 'ssh-mcp-approver/native-request/v1', [
            request.nonce,
            request.requestDigest,
            request.operationId,
            request.leaseIdentityDigest,
          ]);
          socket.end(encodeFrame({ ...request, requestMac }));
        } catch (error) {
          fail(error);
        }
      });
      socket.on('data', (chunk: Buffer) => {
        data = Buffer.concat([data, chunk]);
        if (data.length > MAX_FRAME_BYTES + 4) fail(new Error('approver protocol invalid'));
      });
      socket.on('end', () => {
        try {
          const value = decodeSingleFrame(data);
          if (!isRecord(value) || !hasExactKeys(value, ['version', 'type', 'nonce', 'requestDigest', 'approved', 'responseMac']))
            throw new Error('approver protocol invalid');
          const response = validateResponse(
            { version: value.version, type: value.type, nonce: value.nonce, requestDigest: value.requestDigest, approved: value.approved },
            request,
          );
          if (
            response === undefined ||
            typeof value.responseMac !== 'string' ||
            !equalMac(
              value.responseMac,
              windowsNativeMac(this.secret, 'ssh-mcp-approver/native-response/v1', [response.nonce, response.requestDigest, response.approved]),
            )
          )
            throw new Error('approver authentication failed');
          finish(response);
        } catch (error) {
          fail(error);
        }
      });
      socket.on('error', fail);
      socket.on('close', () => {
        if (!settled) fail(new Error('approver unavailable'));
      });
    });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.length && keys.every((key) => ownKeys.includes(key));
}

function isSafeText(value: unknown, maxLength: number): value is string {
  // eslint-disable-next-line no-control-regex -- reject protocol control characters
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength && !/[\u0000-\u001F\u007F]/u.test(value);
}

function canonicalRequest(request: Pick<HumanApproverIpcRequest, 'operationId' | 'leaseIdentityDigest' | 'request'>): string {
  return JSON.stringify([
    request.operationId,
    request.leaseIdentityDigest,
    request.request.profileId,
    request.request.command,
    request.request.args,
    request.request.timeoutMs,
    request.request.maxOutputBytes,
    request.request.presentation,
  ]);
}

function digestRequest(request: Pick<HumanApproverIpcRequest, 'operationId' | 'leaseIdentityDigest' | 'request'>): string {
  return createHash('sha256').update(canonicalRequest(request)).digest('hex');
}

function equalDigest(left: string, right: string): boolean {
  if (!HEX_64.test(left) || !HEX_64.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function macPayload(domain: string, fields: readonly unknown[]): string {
  return `${domain}\0${JSON.stringify(fields)}`;
}

function mac(secret: Buffer, domain: string, fields: readonly unknown[]): string {
  return createHmac('sha256', secret).update(macPayload(domain, fields), 'utf8').digest('hex');
}

function equalMac(left: string, right: string): boolean {
  return equalDigest(left, right);
}

function requestMacPayload(request: HumanApproverIpcRequest): readonly unknown[] {
  return [
    request.version,
    request.type,
    request.nonce,
    request.requestDigest,
    request.operationId,
    request.leaseIdentityDigest,
    request.request.profileId,
    request.request.command,
    request.request.args,
    request.request.timeoutMs,
    request.request.maxOutputBytes,
    request.request.presentation,
  ];
}

function responseMacPayload(
  response: Pick<HumanApproverIpcResponse, 'version' | 'type' | 'nonce' | 'requestDigest' | 'approved'>,
): readonly unknown[] {
  return [response.version, response.type, response.nonce, response.requestDigest, response.approved];
}

function encodeFrame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  if (payload.length === 0 || payload.length > MAX_FRAME_BYTES) throw new TypeError('IPC frame is too large');
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function decodeSingleFrame(data: Buffer): unknown {
  if (data.length < 4) throw new TypeError('IPC frame is incomplete');
  const length = data.readUInt32BE(0);
  if (length === 0 || length > MAX_FRAME_BYTES || data.length !== length + 4) throw new TypeError('IPC frame is invalid');
  return JSON.parse(data.subarray(4).toString('utf8')) as unknown;
}

function validateResponse(value: unknown, request: HumanApproverIpcRequest): HumanApproverIpcResponse | undefined {
  if (!isRecord(value) || !hasExactKeys(value, ['version', 'type', 'nonce', 'requestDigest', 'approved'])) return undefined;
  if (
    value.version !== IPC_VERSION ||
    value.type !== 'approval-response' ||
    value.nonce !== request.nonce ||
    typeof value.requestDigest !== 'string' ||
    !equalDigest(value.requestDigest, request.requestDigest) ||
    typeof value.approved !== 'boolean'
  ) {
    return undefined;
  }
  return Object.freeze({
    version: IPC_VERSION,
    type: 'approval-response',
    nonce: request.nonce,
    requestDigest: request.requestDigest,
    approved: value.approved,
  });
}

function validateAbsolutePath(path: string, maxBytes: number): string | undefined {
  if (!isSafeText(path, 4096) || !path.startsWith('/')) return undefined;
  return Buffer.byteLength(path, 'utf8') > maxBytes ? undefined : path;
}

function validateSocketPath(socketPath: string): string | undefined {
  return validateAbsolutePath(socketPath, MAX_UNIX_SOCKET_PATH_BYTES);
}

function isTrustedUnixDirectory(stat: { readonly uid: number; readonly mode: number; isDirectory(): boolean }, uid: number | undefined): boolean {
  if (!stat.isDirectory()) return false;
  const writableByOtherUsers = (stat.mode & 0o022) !== 0;
  const isTrustedStickyDirectory = (stat.mode & 0o1000) !== 0 && (stat.uid === 0 || stat.uid === uid);
  if (writableByOtherUsers && !isTrustedStickyDirectory) return false;
  return uid === undefined || stat.uid === uid || stat.uid === 0;
}

async function isPrivateUnixSocket(socketPath: string): Promise<boolean> {
  try {
    const stat = await fs.lstat(socketPath);
    if (!stat.isSocket() || (stat.mode & 0o077) !== 0) return false;
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid) return false;
    let directory = dirname(socketPath);
    while (true) {
      const directoryStat = await fs.lstat(directory);
      if (!isTrustedUnixDirectory(directoryStat, uid)) return false;
      const parent = dirname(directory);
      if (parent === directory) return true;
      directory = parent;
    }
  } catch {
    return false;
  }
}

async function readPrivateSecret(secretFile: string | undefined): Promise<Buffer | undefined> {
  const path = secretFile === undefined ? undefined : validateAbsolutePath(secretFile, 4096);
  if (path === undefined) return undefined;
  try {
    const stat = await fs.lstat(path);
    const uid = process.getuid?.();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || (uid !== undefined && stat.uid !== uid)) return undefined;
    let directory = dirname(path);
    while (true) {
      const directoryStat = await fs.lstat(directory);
      if (!isTrustedUnixDirectory(directoryStat, uid)) return undefined;
      const parent = dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
    const secret = await fs.readFile(path);
    return secret.length === APPROVER_SECRET_BYTES ? secret : undefined;
  } catch {
    return undefined;
  }
}

function closeSocket(socket: Socket): void {
  socket.removeAllListeners();
  socket.destroy();
}

function hasTrustedUnixPeer(socket: Socket): boolean {
  const descriptor = (socket as unknown as { readonly _handle?: { readonly fd?: unknown } })._handle?.fd;
  const uid = process.getuid?.();
  if (posixPeerCredentialsBinding === undefined || typeof descriptor !== 'number' || uid === undefined) return false;
  try {
    const credentials = posixPeerCredentialsBinding.getPeerCredentials(descriptor);
    return (
      credentials !== null &&
      typeof credentials === 'object' &&
      credentials.uid === uid &&
      (process.platform === 'darwin' || (typeof credentials.pid === 'number' && credentials.pid > 0))
    );
  } catch {
    return false;
  }
}

/** Real POSIX client. The server must create the socket with owner-only permissions. */
export class UnixSocketHumanApproverChannel implements HumanApproverIpcChannel {
  constructor(
    private readonly socketPath: string,
    private readonly secretFile?: string,
    private readonly timeoutMs = MAX_IPC_TIMEOUT_MS,
  ) {}

  async approve(request: HumanApproverIpcRequest, signal?: AbortSignal): Promise<HumanApproverIpcResponse> {
    const socketPath = validateSocketPath(this.socketPath);
    const secret = await readPrivateSecret(this.secretFile);
    if (socketPath === undefined || secret === undefined || !(await isPrivateUnixSocket(socketPath))) throw new Error('approver unavailable');
    if (signal?.aborted) throw new Error('approver cancelled');

    const timeoutMs = Math.min(Math.max(1, this.timeoutMs), MAX_IPC_TIMEOUT_MS);
    return new Promise<HumanApproverIpcResponse>((resolve, reject) => {
      let settled = false;
      let data = Buffer.alloc(0);
      const socket = createConnection({ path: socketPath });
      const cleanup = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
      };
      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        cleanup();
        closeSocket(socket);
        reject(error);
      };
      const finish = (value: HumanApproverIpcResponse): void => {
        if (settled) return;
        settled = true;
        cleanup();
        closeSocket(socket);
        resolve(value);
      };
      const abort = (): void => fail(new Error('approver cancelled'));
      const timer = setTimeout(() => fail(new Error('approver timeout')), timeoutMs);
      signal?.addEventListener('abort', abort, { once: true });
      socket.on('connect', () => {
        try {
          if (!hasTrustedUnixPeer(socket)) throw new Error('approver peer credentials unavailable');
          socket.end(
            encodeFrame({
              ...request,
              requestMac: mac(secret, 'ssh-mcp-approver/request/v1', requestMacPayload(request)),
            }),
          );
        } catch (error) {
          fail(error);
        }
      });
      socket.on('data', (chunk: Buffer) => {
        data = Buffer.concat([data, chunk]);
        if (data.length > MAX_FRAME_BYTES + 4) fail(new Error('approver protocol invalid'));
      });
      socket.on('end', () => {
        try {
          const value = decodeSingleFrame(data);
          if (!isRecord(value) || !hasExactKeys(value, ['version', 'type', 'nonce', 'requestDigest', 'approved', 'responseMac']))
            throw new Error('approver protocol invalid');
          if (typeof value.responseMac !== 'string' || !HEX_64.test(value.responseMac)) throw new Error('approver protocol invalid');
          const response = validateResponse(
            {
              version: value.version,
              type: value.type,
              nonce: value.nonce,
              requestDigest: value.requestDigest,
              approved: value.approved,
            },
            request,
          );
          if (response === undefined) throw new Error('approver protocol invalid');
          if (!equalMac(value.responseMac, mac(secret, 'ssh-mcp-approver/response/v1', responseMacPayload(response))))
            throw new Error('approver authentication failed');
          finish(response);
        } catch (error) {
          fail(error);
        }
      });
      socket.on('error', fail);
      socket.on('close', () => {
        if (!settled) fail(new Error('approver unavailable'));
      });
    });
  }
}

/** Windows adapter intentionally requires a native authenticated boundary. */
export class WindowsNamedPipeHumanApproverChannel implements HumanApproverIpcChannel {
  constructor(private readonly boundary?: WindowsNamedPipeSecurityBoundary) {}

  async approve(request: HumanApproverIpcRequest, signal?: AbortSignal): Promise<HumanApproverIpcResponse> {
    if (this.boundary === undefined || signal?.aborted) throw new Error('Windows approver boundary unavailable');
    return this.boundary.approve(request, signal);
  }
}

/** Typed boundary for the local ssh-mcp-approver. MCP never receives local details. */
export class IpcHumanSudoApprovalProvider implements HumanSudoApprovalProvider {
  constructor(
    private readonly channel: HumanApproverIpcChannel,
    private readonly platform: HumanApproverIpcPlatform,
    private readonly identityForRequest?: (request: SudoApprovalRequest) => {
      readonly operationId: string;
      readonly identity: ApprovedProfileIdentity;
      readonly leaseIdentityDigest: string;
    },
  ) {}

  async approve(request: SudoApprovalRequest, signal?: AbortSignal): Promise<HumanSudoApprovalDecision> {
    if (signal?.aborted || (this.platform !== 'posix' && this.platform !== 'windows')) return false;
    const bound =
      request.operationId !== undefined && request.leaseIdentityDigest !== undefined
        ? { operationId: request.operationId, leaseIdentityDigest: request.leaseIdentityDigest, identity: request.approvedIdentity }
        : this.identityForRequest === undefined
          ? undefined
          : this.identityForRequest(request);
    if (
      bound === undefined ||
      bound.identity === undefined ||
      !isSafeText(bound.operationId, 128) ||
      !isSafeText(bound.leaseIdentityDigest, 128) ||
      !isSafeText(bound.identity.host, 4096) ||
      !Number.isSafeInteger(bound.identity.port) ||
      bound.identity.port < 1 ||
      bound.identity.port > 65535 ||
      !isSafeText(bound.identity.user, 256) ||
      !isSafeText(bound.identity.expectedHostFingerprint, 4096) ||
      !isSafeText(bound.identity.approvedKnownHostsReference, 4096)
    )
      return false;
    const wireRequest = Object.freeze({
      profileId: request.profileId,
      command: request.command,
      args: Object.freeze([...request.args]),
      timeoutMs: request.timeoutMs,
      maxOutputBytes: request.maxOutputBytes,
      presentation: Object.freeze({
        host: bound.identity.host,
        port: bound.identity.port,
        user: bound.identity.user,
        expectedHostFingerprint: bound.identity.expectedHostFingerprint,
        authMode: bound.identity.authMode,
        approvedKnownHostsReference: bound.identity.approvedKnownHostsReference,
      }),
    });
    const nonce = randomBytes(32).toString('hex');
    const requestDigest = digestRequest({ operationId: bound.operationId, leaseIdentityDigest: bound.leaseIdentityDigest, request: wireRequest });
    const ipcRequest: HumanApproverIpcRequest = Object.freeze({
      version: IPC_VERSION,
      type: 'approval-request',
      nonce,
      requestDigest,
      operationId: bound.operationId,
      leaseIdentityDigest: bound.leaseIdentityDigest,
      request: wireRequest,
    });
    try {
      const response = await this.channel.approve(ipcRequest, signal);
      if (typeof response === 'boolean') return response;
      const validated = validateResponse(response, ipcRequest);
      return validated === undefined ? 'unavailable' : validated.approved;
    } catch {
      return signal?.aborted ? false : 'unavailable';
    }
  }
}

export class UnavailableHumanApproverChannel implements HumanApproverIpcChannel {
  async approve(): Promise<boolean> {
    return false;
  }
}

/** Creates the production-local approver without accepting any MCP value. */
export function createLocalHumanSudoApprovalProvider(
  platform = process.platform,
  environment: NodeJS.ProcessEnv = process.env,
  windowsBoundary?: WindowsNamedPipeSecurityBoundary,
): HumanSudoApprovalProvider | undefined {
  if (platform === 'linux' || platform === 'darwin') {
    const socketPath = environment[APPROVER_SOCKET_ENV];
    const secretFile = environment[APPROVER_SECRET_FILE_ENV];
    if (socketPath === undefined || secretFile === undefined || !socketPath.startsWith('/') || !secretFile.startsWith('/')) return undefined;
    return new IpcHumanSudoApprovalProvider(new UnixSocketHumanApproverChannel(socketPath, secretFile), 'posix');
  }
  if (platform === 'win32' && windowsBoundary !== undefined) {
    return new IpcHumanSudoApprovalProvider(new WindowsNamedPipeHumanApproverChannel(windowsBoundary), 'windows');
  }
  if (platform === 'win32') {
    const pipe = environment[APPROVER_PIPE_ENV];
    const secret = readWindowsSecret(environment);
    if (pipe !== undefined && secret !== undefined) {
      return new IpcHumanSudoApprovalProvider(
        new WindowsNamedPipeHumanApproverChannel(new EnvironmentWindowsNamedPipeSecurityBoundary(pipe, secret)),
        'windows',
      );
    }
  }
  return undefined;
}

export const humanApproverIpc = Object.freeze({
  version: IPC_VERSION,
  maxFrameBytes: MAX_FRAME_BYTES,
  approverSocketEnvironmentVariable: APPROVER_SOCKET_ENV,
  approverSecretFileEnvironmentVariable: APPROVER_SECRET_FILE_ENV,
});
