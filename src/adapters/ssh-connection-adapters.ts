import { spawn, type ChildProcess } from 'node:child_process';
import { realpath as fsRealpath } from 'node:fs/promises';
import { isIP } from 'node:net';
import { posix as posixPath, win32 as win32Path } from 'node:path';

/**
 * The only value accepted from an untrusted caller.  All connection details
 * are resolved by a trusted provider after this selection has been checked.
 */
export interface ProfileSelection {
  readonly profileId: string;
}

export type SshAuthenticationMode = 'agent-key' | 'password';

/**
 * Internal, operator-owned connection data.  This descriptor must never be
 * constructed from an MCP request; it is returned by a trusted provider.
 */
export interface TrustedConnectionDescriptor {
  readonly profileId: string;
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly authMode: SshAuthenticationMode;
  readonly knownHostsReference: string;
  readonly expectedHostFingerprint: string;
  readonly credentialReference?: string;
}

export interface TrustedConnectionProvider {
  getConnection(profileId: string): TrustedConnectionDescriptor | undefined | Promise<TrustedConnectionDescriptor | undefined>;
}

export interface TrustedKnownHostsResolution {
  readonly path: string;
  readonly fingerprint: string;
}

export interface TrustedKnownHostsPathResolver {
  resolve(reference: string): TrustedKnownHostsResolution | undefined | Promise<TrustedKnownHostsResolution | undefined>;
}

export interface SshProcessResult {
  readonly exitCode: number | null;
  /** True only after the process has reached the authenticated readiness boundary. */
  readonly ready: boolean;
}

export interface SshProcessRunner {
  run(executable: string, args: readonly string[], options: { readonly timeoutMs: number; readonly shell: false }): Promise<SshProcessResult>;
}

/** Trusted local/structured readiness signal; never infer readiness from SSH output. */
export interface OpenSshReadinessProbe {
  waitUntilReady(context: { readonly child: ChildProcess; readonly signal: AbortSignal }): Promise<boolean>;
}

export interface OpenSshExecutableResolver {
  resolve(): string;
}

export interface PasswordCredential {
  readonly password: string;
}

export interface InMemoryPasswordCredentialProvider {
  getPassword(reference: string, signal?: AbortSignal): PasswordCredential | string | Promise<PasswordCredential | string>;
}

/**
 * A password transport is deliberately not a process runner.  Its only
 * implementation boundary receives the password in memory, so passwords do
 * not enter argv, environment variables, shell commands, or log messages.
 */
export interface InMemoryPasswordTransport {
  connect(request: PasswordTransportRequest, signal?: AbortSignal): Promise<void>;
}

export interface PasswordTransportRequest {
  readonly profileId: string;
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly password: string;
  readonly knownHostsPath: string;
  readonly expectedHostFingerprint: string;
  readonly timeoutMs: number;
  readonly strictHostKeyChecking: 'yes';
}

export type SshAdapterErrorCode =
  | 'invalid-selection'
  | 'trusted-profile-unavailable'
  | 'trusted-profile-not-found'
  | 'invalid-trusted-profile'
  | 'known-hosts-unavailable'
  | 'known-hosts-fingerprint-mismatch'
  | 'invalid-executable'
  | 'ssh-connection-failed'
  | 'ssh-timeout'
  | 'password-transport-unavailable'
  | 'password-unavailable'
  | 'unsupported-authentication';

/** Public errors contain stable text only; child-process and secret errors are never propagated. */
export class SshAdapterError extends Error {
  readonly code: SshAdapterErrorCode;

  constructor(code: SshAdapterErrorCode, message: string) {
    super(message);
    this.name = 'SshAdapterError';
    this.code = code;
  }
}

const PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
// eslint-disable-next-line no-control-regex -- control characters are rejected at this trust boundary
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const ABSOLUTE_POSIX_PATH = /^\//u;
const ABSOLUTE_WINDOWS_PATH = /^[A-Za-z]:[\\/]/u;
const HOST_WILDCARD_CHARACTERS = /[*?]/u;
const TARGET_DELIMITER_CHARACTERS = /[\s@:/\\]/u;
const OPENSSH_SHA256_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/u;
const MAX_OUTPUT_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;
const CLEANUP_GRACE_MS = 100;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function own(value: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined;
}

function fail(code: SshAdapterErrorCode, message: string): never {
  throw new SshAdapterError(code, message);
}

function validateProfileId(value: unknown): string {
  if (typeof value !== 'string' || !PROFILE_ID.test(value) || value === 'constructor' || value === 'prototype' || value === '__proto__') {
    fail('invalid-selection', 'Connection selection is invalid');
  }
  return value;
}

/** Validate the intentionally tiny public input surface. */
export function validateProfileSelection(input: unknown): ProfileSelection {
  if (!isPlainRecord(input)) fail('invalid-selection', 'Connection selection is invalid');
  const keys = Reflect.ownKeys(input);
  if (keys.length !== 1 || keys[0] !== 'profileId') {
    fail('invalid-selection', 'Connection selection is invalid');
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== null && Reflect.ownKeys(prototype).some((key) => key === 'profileId')) {
    fail('invalid-selection', 'Connection selection is invalid');
  }
  return { profileId: validateProfileId(own(input, 'profileId')) };
}

function validText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !CONTROL_CHARACTERS.test(value);
}

function isAbsolutePath(value: string, targetPlatform: string): boolean {
  return targetPlatform === 'win32' ? ABSOLUTE_WINDOWS_PATH.test(value) : ABSOLUTE_POSIX_PATH.test(value);
}

function validTrustedHost(value: unknown): value is string {
  if (!validText(value) || HOST_WILDCARD_CHARACTERS.test(value) || value.startsWith('-')) return false;
  if (value.startsWith('[') || value.endsWith(']')) {
    return /^\[[0-9A-Fa-f:.]+\]$/u.test(value) && isIP(value.slice(1, -1)) === 6;
  }
  return !TARGET_DELIMITER_CHARACTERS.test(value);
}

function isWithinDirectory(value: string, directory: string, targetPlatform: string): boolean {
  const pathApi = targetPlatform === 'win32' ? win32Path : posixPath;
  const root = pathApi.resolve(directory);
  const candidate = pathApi.resolve(value);
  const relative = pathApi.relative(root, candidate);
  return relative.length > 0 && relative !== '..' && !relative.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(relative);
}

type TrustedRealpath = (path: string) => Promise<string>;

function validateTrustedDescriptor(value: unknown, selectedProfileId: string): TrustedConnectionDescriptor {
  if (!isPlainRecord(value)) fail('invalid-trusted-profile', 'Trusted connection profile is invalid');
  const allowed = new Set(['profileId', 'host', 'port', 'user', 'authMode', 'knownHostsReference', 'expectedHostFingerprint', 'credentialReference']);
  if (Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !allowed.has(key))) {
    fail('invalid-trusted-profile', 'Trusted connection profile is invalid');
  }
  const profileId = own(value, 'profileId');
  const host = own(value, 'host');
  const user = own(value, 'user');
  const port = own(value, 'port');
  const authMode = own(value, 'authMode');
  const knownHostsReference = own(value, 'knownHostsReference');
  const expectedHostFingerprint = own(value, 'expectedHostFingerprint');
  if (
    typeof profileId !== 'string' ||
    !PROFILE_ID.test(profileId) ||
    profileId !== selectedProfileId ||
    !validTrustedHost(host) ||
    !validText(user) ||
    TARGET_DELIMITER_CHARACTERS.test(user) ||
    user.startsWith('-') ||
    !Number.isInteger(port) ||
    (port as number) < 1 ||
    (port as number) > 65535 ||
    (authMode !== 'agent-key' && authMode !== 'password') ||
    !validText(knownHostsReference) ||
    typeof expectedHostFingerprint !== 'string' ||
    !OPENSSH_SHA256_FINGERPRINT.test(expectedHostFingerprint)
  ) {
    fail('invalid-trusted-profile', 'Trusted connection profile is invalid');
  }
  const credentialReference = own(value, 'credentialReference');
  if (credentialReference !== undefined && !validText(credentialReference)) {
    fail('invalid-trusted-profile', 'Trusted connection profile is invalid');
  }
  if (authMode === 'password' && credentialReference === undefined) {
    fail('invalid-trusted-profile', 'Trusted connection profile is invalid');
  }
  return {
    profileId,
    host,
    port: port as number,
    user,
    authMode,
    knownHostsReference,
    expectedHostFingerprint,
    ...(credentialReference === undefined ? {} : { credentialReference }),
  };
}

function boundedTimeout(value: number | undefined): number {
  return Number.isInteger(value) && value !== undefined && value > 0 && value <= MAX_TIMEOUT_MS ? value : DEFAULT_TIMEOUT_MS;
}

/** Abort and await cooperative secret-bearing work before reporting timeout. */
async function withAbortTimeout<T>(start: (signal: AbortSignal) => Promise<T>, timeoutMs: number): Promise<T> {
  const controller = new AbortController();
  let timedOut = false;
  const operation = Promise.resolve(start(controller.signal));
  return new Promise((resolve, reject) => {
    let settled = false;
    let graceTimer: ReturnType<typeof setTimeout> | undefined;
    const timeout = () => {
      if (settled) return;
      timedOut = true;
      controller.abort();
      graceTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        // Residual risk: a non-cooperative provider may still hold secret
        // material after this bounded grace period; its contract must erase it.
        reject(new SshAdapterError('ssh-timeout', 'SSH connection timed out'));
      }, CLEANUP_GRACE_MS);
    };
    const timer = setTimeout(timeout, timeoutMs);
    operation.then(
      (result) => {
        if (settled) return;
        clearTimeout(timer);
        if (graceTimer !== undefined) clearTimeout(graceTimer);
        settled = true;
        if (timedOut) reject(new SshAdapterError('ssh-timeout', 'SSH connection timed out'));
        else resolve(result);
      },
      (error) => {
        if (settled) return;
        clearTimeout(timer);
        if (graceTimer !== undefined) clearTimeout(graceTimer);
        settled = true;
        if (timedOut) reject(new SshAdapterError('ssh-timeout', 'SSH connection timed out'));
        else reject(error);
      },
    );
  });
}

async function resolveTrustedConnection(input: unknown, provider: TrustedConnectionProvider): Promise<TrustedConnectionDescriptor> {
  const selection = validateProfileSelection(input);
  let descriptor: unknown;
  try {
    descriptor = await provider.getConnection(selection.profileId);
  } catch {
    fail('trusted-profile-unavailable', 'Trusted connection profile is unavailable');
  }
  if (descriptor === undefined) fail('trusted-profile-not-found', 'Trusted connection profile was not found');
  return validateTrustedDescriptor(descriptor, selection.profileId);
}

async function resolveKnownHostsPath(
  descriptor: TrustedConnectionDescriptor,
  resolver: TrustedKnownHostsPathResolver,
  targetPlatform: string,
  trustedKnownHostsDirectory: string,
  realpath: TrustedRealpath,
): Promise<TrustedKnownHostsResolution> {
  let resolution: unknown;
  try {
    resolution = await resolver.resolve(descriptor.knownHostsReference);
  } catch {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  if (!isPlainRecord(resolution)) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  const path = own(resolution, 'path');
  const fingerprint = own(resolution, 'fingerprint');
  if (
    typeof path !== 'string' ||
    !isAbsolutePath(path, targetPlatform) ||
    CONTROL_CHARACTERS.test(path) ||
    path.includes('%') ||
    typeof fingerprint !== 'string' ||
    !OPENSSH_SHA256_FINGERPRINT.test(fingerprint) ||
    CONTROL_CHARACTERS.test(trustedKnownHostsDirectory) ||
    trustedKnownHostsDirectory.includes('%') ||
    !isAbsolutePath(trustedKnownHostsDirectory, targetPlatform) ||
    !isWithinDirectory(path, trustedKnownHostsDirectory, targetPlatform)
  ) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  if (fingerprint !== descriptor.expectedHostFingerprint) {
    fail('known-hosts-fingerprint-mismatch', 'Approved known-hosts fingerprint does not match');
  }
  let canonicalRoot: string;
  let canonicalPath: string;
  try {
    [canonicalRoot, canonicalPath] = await Promise.all([realpath(trustedKnownHostsDirectory), realpath(path)]);
  } catch {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  if (!isWithinDirectory(canonicalPath, canonicalRoot, targetPlatform)) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  return { path: canonicalPath, fingerprint };
}

export interface SshAdapterDependencies {
  readonly profiles: TrustedConnectionProvider;
  readonly knownHosts: TrustedKnownHostsPathResolver;
  readonly trustedKnownHostsDirectory: string;
  readonly realpath?: TrustedRealpath;
  readonly targetPlatform?: string;
  readonly timeoutMs?: number;
}

export interface OpenSshAgentAdapterDependencies extends SshAdapterDependencies {
  readonly executable?: OpenSshExecutableResolver;
  /** A runner with a trusted local readiness probe. */
  readonly runner: SshProcessRunner;
}

function buildAgentArguments(
  descriptor: TrustedConnectionDescriptor,
  knownHostsPath: string,
  timeoutMs: number,
  targetPlatform: string,
): readonly string[] {
  const connectTimeoutSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const globalKnownHosts = targetPlatform === 'win32' ? 'NUL' : '/dev/null';
  return [
    '-N',
    '-T',
    '-n',
    '-o',
    'BatchMode=yes',
    '-o',
    'StrictHostKeyChecking=yes',
    '-o',
    `UserKnownHostsFile=${knownHostsPath}`,
    '-o',
    `GlobalKnownHostsFile=${globalKnownHosts}`,
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    '-o',
    'NumberOfPasswordPrompts=0',
    '-o',
    'IdentitiesOnly=yes',
    '-o',
    `ConnectTimeout=${connectTimeoutSeconds}`,
    '-p',
    String(descriptor.port),
    '--',
    `${descriptor.user}@${descriptor.host}`,
  ];
}

export class OpenSshAgentAdapter {
  private readonly timeoutMs: number;
  private readonly profiles: TrustedConnectionProvider;
  private readonly knownHosts: TrustedKnownHostsPathResolver;
  private readonly trustedKnownHostsDirectory: string;
  private readonly realpath: TrustedRealpath;
  private readonly targetPlatform: string;
  private readonly executable: OpenSshExecutableResolver;
  private readonly runner: SshProcessRunner;

  constructor(dependencies: OpenSshAgentAdapterDependencies) {
    this.profiles = dependencies.profiles;
    this.knownHosts = dependencies.knownHosts;
    this.trustedKnownHostsDirectory = dependencies.trustedKnownHostsDirectory;
    this.realpath = dependencies.realpath ?? fsRealpath;
    this.targetPlatform = dependencies.targetPlatform ?? (typeof process === 'undefined' ? 'unknown' : process.platform);
    this.executable = dependencies.executable ?? new PlatformOpenSshExecutableResolver();
    this.runner = dependencies.runner;
    this.timeoutMs = boundedTimeout(dependencies.timeoutMs);
  }

  async connect(input: unknown): Promise<void> {
    const descriptor = await resolveTrustedConnection(input, this.profiles);
    if (descriptor.authMode !== 'agent-key') fail('unsupported-authentication', 'Connection authentication mode is unsupported');
    const knownHosts = await resolveKnownHostsPath(descriptor, this.knownHosts, this.targetPlatform, this.trustedKnownHostsDirectory, this.realpath);
    let executable: unknown;
    try {
      executable = this.executable.resolve();
    } catch {
      fail('invalid-executable', 'OpenSSH executable is unavailable');
    }
    if (typeof executable !== 'string' || !isAbsolutePath(executable, this.targetPlatform) || CONTROL_CHARACTERS.test(executable)) {
      fail('invalid-executable', 'OpenSSH executable is unavailable');
    }
    const args = buildAgentArguments(descriptor, knownHosts.path, this.timeoutMs, this.targetPlatform);
    let result: SshProcessResult;
    try {
      result = await this.runner.run(executable, args, { timeoutMs: this.timeoutMs, shell: false });
    } catch (error) {
      if (error instanceof SshAdapterError && error.code === 'ssh-timeout') throw error;
      fail('ssh-connection-failed', 'SSH connection failed');
    }
    if (result.ready !== true) {
      if (result.exitCode === null) fail('ssh-timeout', 'SSH connection timed out');
      fail('ssh-connection-failed', 'SSH connection failed');
    }
    if (result.exitCode !== 0) fail('ssh-connection-failed', 'SSH connection failed');
  }
}

export interface PasswordSshAdapterDependencies extends SshAdapterDependencies {
  readonly credentials?: InMemoryPasswordCredentialProvider;
  readonly transport?: InMemoryPasswordTransport;
}

export class PasswordSshAdapter {
  private readonly timeoutMs: number;
  private readonly dependencies: PasswordSshAdapterDependencies;

  constructor(dependencies: PasswordSshAdapterDependencies) {
    this.dependencies = dependencies;
    this.timeoutMs = boundedTimeout(dependencies.timeoutMs);
  }

  async connect(input: unknown): Promise<void> {
    const descriptor = await resolveTrustedConnection(input, this.dependencies.profiles);
    if (descriptor.authMode !== 'password') fail('unsupported-authentication', 'Connection authentication mode is unsupported');
    const targetPlatform = this.dependencies.targetPlatform ?? (typeof process === 'undefined' ? 'unknown' : process.platform);
    const knownHosts = await resolveKnownHostsPath(
      descriptor,
      this.dependencies.knownHosts,
      targetPlatform,
      this.dependencies.trustedKnownHostsDirectory,
      this.dependencies.realpath ?? fsRealpath,
    );
    if (this.dependencies.credentials === undefined || this.dependencies.transport === undefined) {
      fail('password-transport-unavailable', 'Password transport is unavailable');
    }
    if (descriptor.credentialReference === undefined) fail('password-unavailable', 'Password is unavailable');
    let credential: PasswordCredential | string;
    try {
      credential = await withAbortTimeout(
        (signal) => Promise.resolve(this.dependencies.credentials!.getPassword(descriptor.credentialReference!, signal)),
        this.timeoutMs,
      );
    } catch (error) {
      if (error instanceof SshAdapterError && error.code === 'ssh-timeout') throw error;
      fail('password-unavailable', 'Password is unavailable');
    }
    const password = typeof credential === 'string' ? credential : credential?.password;
    if (typeof password !== 'string' || password.length === 0 || password.includes('\u0000')) {
      fail('password-unavailable', 'Password is unavailable');
    }
    try {
      await withAbortTimeout(
        (signal) =>
          this.dependencies.transport!.connect(
            {
              profileId: descriptor.profileId,
              host: descriptor.host,
              port: descriptor.port,
              user: descriptor.user,
              password,
              knownHostsPath: knownHosts.path,
              expectedHostFingerprint: knownHosts.fingerprint,
              timeoutMs: this.timeoutMs,
              strictHostKeyChecking: 'yes',
            },
            signal,
          ),
        this.timeoutMs,
      );
    } catch (error) {
      if (error instanceof SshAdapterError && error.code === 'ssh-timeout') throw error;
      fail('ssh-connection-failed', 'SSH connection failed');
    }
  }
}

/** Direct native process runner used only by the agent adapter. */
export class NativeOpenSshProcessRunner implements SshProcessRunner {
  private readonly readinessProbe: OpenSshReadinessProbe | undefined;

  constructor(readinessProbe?: OpenSshReadinessProbe) {
    this.readinessProbe = readinessProbe;
  }

  run(executable: string, args: readonly string[], options: { readonly timeoutMs: number; readonly shell: false }): Promise<SshProcessResult> {
    return new Promise((resolve, reject) => {
      if (this.readinessProbe === undefined) {
        reject(new SshAdapterError('ssh-connection-failed', 'SSH readiness probe is unavailable'));
        return;
      }
      const child = spawn(executable, [...args], {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'] as const,
      });
      let outputBytes = 0;
      let finalized = false;
      let closeSeen = false;
      let forceFinalize = false;
      let outcome: { readonly result?: SshProcessResult; readonly error?: Error } | undefined;
      let closeGraceTimer: ReturnType<typeof setTimeout> | undefined;
      let escalationTimer: ReturnType<typeof setTimeout> | undefined;
      const readinessController = new AbortController();
      const finalize = () => {
        if (finalized || !outcome || (!closeSeen && !forceFinalize)) return;
        finalized = true;
        clearTimeout(deadlineTimer);
        if (closeGraceTimer !== undefined) clearTimeout(closeGraceTimer);
        if (escalationTimer !== undefined) clearTimeout(escalationTimer);
        if (outcome.error !== undefined) reject(outcome.error);
        else resolve(outcome.result!);
      };
      const terminate = (nextOutcome: { readonly result?: SshProcessResult; readonly error?: Error }) => {
        if (outcome !== undefined) return;
        outcome = nextOutcome;
        clearTimeout(deadlineTimer);
        readinessController.abort();
        try {
          child.kill();
        } catch {
          /* process may have exited */
        }
        closeGraceTimer = setTimeout(() => {
          if (closeSeen || finalized) return;
          try {
            child.kill('SIGKILL');
          } catch {
            /* best effort escalation */
          }
          escalationTimer = setTimeout(() => {
            if (!closeSeen) {
              forceFinalize = true;
              finalize();
            }
          }, CLEANUP_GRACE_MS);
        }, CLEANUP_GRACE_MS);
        finalize();
      };
      const deadlineTimer = setTimeout(() => terminate({ result: { exitCode: null, ready: false } }), options.timeoutMs);
      const drain = (chunk: Buffer | string) => {
        outputBytes += Buffer.byteLength(chunk);
        if (outputBytes > MAX_OUTPUT_BYTES) terminate({ error: new SshAdapterError('ssh-connection-failed', 'SSH connection failed') });
      };
      child.stdout.on('data', drain);
      child.stderr.on('data', (chunk) => {
        drain(chunk);
      });
      child.once('error', () => terminate({ error: new SshAdapterError('ssh-connection-failed', 'SSH connection failed') }));
      child.once('close', (code) => {
        closeSeen = true;
        readinessController.abort();
        if (outcome === undefined) outcome = { result: { exitCode: code, ready: false } };
        finalize();
      });
      let readiness: Promise<boolean>;
      try {
        readiness = Promise.resolve(this.readinessProbe.waitUntilReady({ child, signal: readinessController.signal }));
      } catch {
        terminate({ error: new SshAdapterError('ssh-connection-failed', 'SSH readiness probe failed') });
        return;
      }
      readiness.then(
        (ready) => {
          if (ready === true) terminate({ result: { exitCode: 0, ready: true } });
          else terminate({ error: new SshAdapterError('ssh-connection-failed', 'SSH readiness probe failed') });
        },
        () => terminate({ error: new SshAdapterError('ssh-connection-failed', 'SSH readiness probe failed') }),
      );
    });
  }
}

export class PlatformOpenSshExecutableResolver implements OpenSshExecutableResolver {
  private readonly platform: string;

  constructor(platform = typeof process === 'undefined' ? 'unknown' : process.platform) {
    this.platform = platform;
  }

  resolve(): string {
    if (this.platform === 'win32') return 'C:\\Windows\\System32\\OpenSSH\\ssh.exe';
    if (this.platform === 'darwin' || this.platform === 'linux') return '/usr/bin/ssh';
    throw new SshAdapterError('invalid-executable', 'OpenSSH executable is unavailable');
  }
}
