import { spawn } from 'node:child_process';

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
  readonly credentialReference?: string;
}

export interface TrustedConnectionProvider {
  getConnection(profileId: string): TrustedConnectionDescriptor | undefined | Promise<TrustedConnectionDescriptor | undefined>;
}

export interface TrustedKnownHostsPathResolver {
  resolve(reference: string): string | undefined | Promise<string | undefined>;
}

export interface SshProcessResult {
  readonly exitCode: number | null;
}

export interface SshProcessRunner {
  run(
    executable: string,
    args: readonly string[],
    options: { readonly timeoutMs: number; readonly shell: false },
  ): Promise<SshProcessResult>;
}

export interface OpenSshExecutableResolver {
  resolve(): string;
}

export interface PasswordCredential {
  readonly password: string;
}

export interface InMemoryPasswordCredentialProvider {
  getPassword(reference: string): PasswordCredential | string | Promise<PasswordCredential | string>;
}

/**
 * A password transport is deliberately not a process runner.  Its only
 * implementation boundary receives the password in memory, so passwords do
 * not enter argv, environment variables, shell commands, or log messages.
 */
export interface InMemoryPasswordTransport {
  connect(request: PasswordTransportRequest): Promise<void>;
}

export interface PasswordTransportRequest {
  readonly profileId: string;
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly password: string;
  readonly knownHostsPath: string;
  readonly timeoutMs: number;
  readonly strictHostKeyChecking: 'yes';
}

export type SshAdapterErrorCode =
  | 'invalid-selection'
  | 'trusted-profile-unavailable'
  | 'trusted-profile-not-found'
  | 'invalid-trusted-profile'
  | 'known-hosts-unavailable'
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
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const ABSOLUTE_POSIX_PATH = /^\//u;
const ABSOLUTE_WINDOWS_PATH = /^[A-Za-z]:[\\/]/u;
const WILDCARD_CHARACTERS = /[*?\[\]]/u;
const MAX_OUTPUT_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;

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
  if (prototype !== null && Reflect.ownKeys(prototype).some(key => key === 'profileId')) {
    fail('invalid-selection', 'Connection selection is invalid');
  }
  return { profileId: validateProfileId(own(input, 'profileId')) };
}

function validText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !CONTROL_CHARACTERS.test(value);
}

function isAbsolutePath(value: string): boolean {
  return ABSOLUTE_POSIX_PATH.test(value) || ABSOLUTE_WINDOWS_PATH.test(value);
}

function validateTrustedDescriptor(value: unknown, selectedProfileId: string): TrustedConnectionDescriptor {
  if (!isPlainRecord(value)) fail('invalid-trusted-profile', 'Trusted connection profile is invalid');
  const allowed = new Set(['profileId', 'host', 'port', 'user', 'authMode', 'knownHostsReference', 'credentialReference']);
  if (Reflect.ownKeys(value).some(key => typeof key !== 'string' || !allowed.has(key))) {
    fail('invalid-trusted-profile', 'Trusted connection profile is invalid');
  }
  const profileId = own(value, 'profileId');
  const host = own(value, 'host');
  const user = own(value, 'user');
  const port = own(value, 'port');
  const authMode = own(value, 'authMode');
  const knownHostsReference = own(value, 'knownHostsReference');
  if (
    typeof profileId !== 'string' || !PROFILE_ID.test(profileId) || profileId !== selectedProfileId ||
    !validText(host) || WILDCARD_CHARACTERS.test(host) || host.startsWith('-') || /\s/u.test(host) ||
    !validText(user) || user.startsWith('-') ||
    !Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535 ||
    (authMode !== 'agent-key' && authMode !== 'password') || !validText(knownHostsReference)
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
    port,
    user,
    authMode,
    knownHostsReference,
    ...(credentialReference === undefined ? {} : { credentialReference }),
  };
}

function boundedTimeout(value: number | undefined): number {
  return Number.isInteger(value) && value !== undefined && value > 0 && value <= MAX_TIMEOUT_MS ? value : DEFAULT_TIMEOUT_MS;
}

function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new SshAdapterError('ssh-timeout', 'SSH connection timed out')), timeoutMs);
    operation.then(
      value => {
        clearTimeout(timer);
        resolve(value);
      },
      error => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function resolveTrustedConnection(
  input: unknown,
  provider: TrustedConnectionProvider,
): Promise<TrustedConnectionDescriptor> {
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
): Promise<string> {
  let path: unknown;
  try {
    path = await resolver.resolve(descriptor.knownHostsReference);
  } catch {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  if (typeof path !== 'string' || !isAbsolutePath(path) || CONTROL_CHARACTERS.test(path)) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  return path;
}

export interface SshAdapterDependencies {
  readonly profiles: TrustedConnectionProvider;
  readonly knownHosts: TrustedKnownHostsPathResolver;
  readonly timeoutMs?: number;
}

export interface OpenSshAgentAdapterDependencies extends SshAdapterDependencies {
  readonly executable?: OpenSshExecutableResolver;
  readonly runner?: SshProcessRunner;
}

function buildAgentArguments(descriptor: TrustedConnectionDescriptor, knownHostsPath: string, timeoutMs: number): readonly string[] {
  const connectTimeoutSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const globalKnownHosts = process.platform === 'win32' ? 'NUL' : '/dev/null';
  return [
    '-N',
    '-T',
    '-n',
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    '-o', `GlobalKnownHostsFile=${globalKnownHosts}`,
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'NumberOfPasswordPrompts=0',
    '-o', 'IdentitiesOnly=yes',
    '-o', `ConnectTimeout=${connectTimeoutSeconds}`,
    '-p', String(descriptor.port),
    `${descriptor.user}@${descriptor.host}`,
  ];
}

export class OpenSshAgentAdapter {
  private readonly timeoutMs: number;
  private readonly profiles: TrustedConnectionProvider;
  private readonly knownHosts: TrustedKnownHostsPathResolver;
  private readonly executable: OpenSshExecutableResolver;
  private readonly runner: SshProcessRunner;

  constructor(dependencies: OpenSshAgentAdapterDependencies) {
    this.profiles = dependencies.profiles;
    this.knownHosts = dependencies.knownHosts;
    this.executable = dependencies.executable ?? new PlatformOpenSshExecutableResolver();
    this.runner = dependencies.runner ?? new NativeOpenSshProcessRunner();
    this.timeoutMs = boundedTimeout(dependencies.timeoutMs);
  }

  async connect(input: unknown): Promise<void> {
    const descriptor = await resolveTrustedConnection(input, this.profiles);
    if (descriptor.authMode !== 'agent-key') fail('unsupported-authentication', 'Connection authentication mode is unsupported');
    const knownHostsPath = await resolveKnownHostsPath(descriptor, this.knownHosts);
    let executable: unknown;
    try {
      executable = this.executable.resolve();
    } catch {
      fail('invalid-executable', 'OpenSSH executable is unavailable');
    }
    if (typeof executable !== 'string' || !isAbsolutePath(executable) || CONTROL_CHARACTERS.test(executable)) {
      fail('invalid-executable', 'OpenSSH executable is unavailable');
    }
    const args = buildAgentArguments(descriptor, knownHostsPath, this.timeoutMs);
    let result: SshProcessResult;
    try {
      result = await this.runner.run(executable, args, { timeoutMs: this.timeoutMs, shell: false });
    } catch (error) {
      if (error instanceof SshAdapterError && error.code === 'ssh-timeout') throw error;
      fail('ssh-connection-failed', 'SSH connection failed');
    }
    if (result.exitCode === null) fail('ssh-timeout', 'SSH connection timed out');
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
    const knownHostsPath = await resolveKnownHostsPath(descriptor, this.dependencies.knownHosts);
    if (this.dependencies.credentials === undefined || this.dependencies.transport === undefined) {
      fail('password-transport-unavailable', 'Password transport is unavailable');
    }
    if (descriptor.credentialReference === undefined) fail('password-unavailable', 'Password is unavailable');
    let credential: PasswordCredential | string;
    try {
      credential = await withTimeout(Promise.resolve(this.dependencies.credentials.getPassword(descriptor.credentialReference)), this.timeoutMs);
    } catch (error) {
      if (error instanceof SshAdapterError && error.code === 'ssh-timeout') throw error;
      fail('password-unavailable', 'Password is unavailable');
    }
    const password = typeof credential === 'string' ? credential : credential?.password;
    if (typeof password !== 'string' || password.length === 0 || password.includes('\u0000')) {
      fail('password-unavailable', 'Password is unavailable');
    }
    try {
      await withTimeout(this.dependencies.transport.connect({
        profileId: descriptor.profileId,
        host: descriptor.host,
        port: descriptor.port,
        user: descriptor.user,
        password,
        knownHostsPath,
        timeoutMs: this.timeoutMs,
        strictHostKeyChecking: 'yes',
      }), this.timeoutMs);
    } catch (error) {
      if (error instanceof SshAdapterError && error.code === 'ssh-timeout') throw error;
      fail('ssh-connection-failed', 'SSH connection failed');
    }
  }
}

/** Direct native process runner used only by the agent adapter. */
export class NativeOpenSshProcessRunner implements SshProcessRunner {
  run(executable: string, args: readonly string[], options: { readonly timeoutMs: number; readonly shell: false }): Promise<SshProcessResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, [...args], {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'] as const,
      });
      let outputBytes = 0;
      let settled = false;
      const finish = (callback: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        callback();
      };
      const timer = setTimeout(() => finish(() => { child.kill(); resolve({ exitCode: null }); }), options.timeoutMs);
      const drain = (chunk: Buffer | string) => {
        outputBytes += Buffer.byteLength(chunk);
        if (outputBytes > MAX_OUTPUT_BYTES) finish(() => { child.kill(); reject(new SshAdapterError('ssh-connection-failed', 'SSH connection failed')); });
      };
      child.stdout.on('data', drain);
      child.stderr.on('data', drain);
      child.once('error', () => finish(() => reject(new SshAdapterError('ssh-connection-failed', 'SSH connection failed'))));
      child.once('close', code => finish(() => resolve({ exitCode: code })));
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
