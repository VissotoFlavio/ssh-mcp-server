import { AsyncLocalStorage } from 'node:async_hooks';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { posix as posixPath } from 'node:path';

import { createPlatformCredentialStoreResolver } from '../credentials/credential-store.js';
import { PosixExecutionAuditJournal, UnavailableExecutionAuditJournal } from '../execution/execution-audit-journal.js';
import { RemoteCommandExecutionProvider, Ssh2RemoteCommandTransport, type HumanSudoApprovalProvider } from '../execution/remote-command-execution.js';
import { HostIdentityCredentialPolicy, type AuthorizedConnection, type ConnectionProfile } from '../policy/host-identity-credential-policy.js';
import { LocalConnectionProfileRegistry, type LocalProfileRegistry } from '../profiles/local-profile-registry.js';
import {
  createTrustedConnectionValidationProvider,
  type ConnectionReadinessAdapter,
  type ConnectionValidationProvider,
  type ValidatedConnectionAuthorization,
} from '../validation/trusted-connection-validation.js';

export const SSH_MCP_KNOWN_HOSTS_ROOT_ENV = 'SSH_MCP_KNOWN_HOSTS_ROOT';
export const SSH_MCP_AUDIT_ROOT_ENV = 'SSH_MCP_AUDIT_ROOT';
export const SSH_MCP_AUDIT_KEY_FILE_ENV = 'SSH_MCP_AUDIT_KEY_FILE';

export interface PosixFileStats {
  readonly uid: number;
  readonly mode: number;
  readonly dev: number;
  readonly ino: number;
  isDirectory(): boolean;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

export interface PosixRuntimeFileSystem {
  lstat(path: string): Promise<PosixFileStats>;
  realpath(path: string): Promise<string>;
  readFile(path: string): Promise<string>;
  mkdtemp(prefix: string): Promise<string>;
  chmod(path: string, mode: number): Promise<void>;
  writeFile(path: string, data: string, options: { readonly encoding: 'utf8'; readonly flag: 'wx'; readonly mode: number }): Promise<void>;
  rm(path: string, options: { readonly recursive: true; readonly force: true }): Promise<void>;
}

export interface BoundedCommandRunner {
  run(executable: string, args: readonly string[], timeoutMs: number): Promise<number>;
}

/** Test seam for ControlMaster lifecycle; native implementation is the default. */
export interface PosixControlMaster {
  validate(authorized: AuthorizedConnection, knownHostsPath: string, timeoutMs: number, signal?: AbortSignal): Promise<void>;
}

/** Minimal child seam used only to prove native master cleanup behavior. */
export interface PosixControlMasterChild {
  once(event: 'close', listener: (code: number | null) => void): unknown;
  once(event: 'error', listener: () => void): unknown;
  kill(signal?: NodeJS.Signals): boolean;
}

export type PosixControlMasterSpawner = (args: readonly string[]) => PosixControlMasterChild;

export interface PosixRuntimeValidationDependencies {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly platform?: string;
  readonly uid?: number | undefined;
  readonly fileSystem?: PosixRuntimeFileSystem;
  readonly commandRunner?: BoundedCommandRunner;
  readonly controlMaster?: PosixControlMaster;
  readonly profileRegistry?: Pick<LocalProfileRegistry, 'getProfile'>;
  readonly timeoutMs?: number;
  readonly connectionValidationProvider?: ConnectionValidationProvider;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;
const UNSAFE_WRITE_BITS = 0o022;
const REFERENCE = /^known-hosts:\/\/([a-z0-9]+(?:-[a-z0-9]+)*)$/u;
const validationDeadline = new AsyncLocalStorage<number>();

const nodeFileSystem: PosixRuntimeFileSystem = {
  lstat: async (path) => lstat(path),
  realpath,
  readFile: async (path) => readFile(path, 'utf8'),
  mkdtemp,
  chmod,
  writeFile,
  rm,
};

function unavailable(): never {
  throw new TypeError('POSIX connection validation runtime is unavailable');
}

function boundedTimeout(value: number | undefined): number {
  return Number.isInteger(value) && value !== undefined && value > 0 && value <= MAX_TIMEOUT_MS ? value : DEFAULT_TIMEOUT_MS;
}

function remainingBudget(fallback: number): number {
  const deadline = validationDeadline.getStore();
  return deadline === undefined ? fallback : Math.max(0, Math.min(fallback, deadline - Date.now()));
}

function sameIdentity(left: PosixFileStats, right: PosixFileStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function beneath(root: string, value: string): boolean {
  const path = posixPath.relative(root, value);
  return path !== '' && path !== '..' && !path.startsWith('../') && !posixPath.isAbsolute(path);
}

function operatorOwned(stats: PosixFileStats, uid: number, directory: boolean): boolean {
  return stats.uid === uid && (stats.mode & UNSAFE_WRITE_BITS) === 0 && !stats.isSymbolicLink() && (directory ? stats.isDirectory() : stats.isFile());
}

class OperatorRoot {
  private readonly canonical: Promise<string>;

  constructor(
    private readonly configured: string,
    private readonly uid: number,
    private readonly fileSystem: PosixRuntimeFileSystem,
  ) {
    if (!posixPath.isAbsolute(configured)) unavailable();
    this.canonical = this.checkInitial();
    // The promise is consumed when the provider is called; attach a no-op
    // rejection observer so an invalid runtime cannot surface as an early
    // unhandled rejection during composition.
    void this.canonical.catch(() => undefined);
  }

  async verify(): Promise<string> {
    const root = await this.canonical;
    try {
      const stats = await this.fileSystem.lstat(root);
      if (!operatorOwned(stats, this.uid, true) || (await this.fileSystem.realpath(root)) !== root) unavailable();
      return root;
    } catch {
      return unavailable();
    }
  }

  private async checkInitial(): Promise<string> {
    try {
      const before = await this.fileSystem.lstat(this.configured);
      const canonical = await this.fileSystem.realpath(this.configured);
      const after = await this.fileSystem.lstat(this.configured);
      if (
        !operatorOwned(before, this.uid, true) ||
        !operatorOwned(after, this.uid, true) ||
        !sameIdentity(before, after) ||
        canonical !== this.configured
      )
        unavailable();
      return canonical;
    } catch {
      return unavailable();
    }
  }
}

function parseKnownHosts(contents: string): readonly { readonly host: string; readonly port: number; readonly fingerprint: string }[] {
  const entries: Array<{ readonly host: string; readonly port: number; readonly fingerprint: string }> = [];
  for (const line of contents.split(/\r?\n/u)) {
    const value = line.trim();
    if (value === '' || value.startsWith('#')) continue;
    const fields = value.split(/\s+/u);
    const endpoint = /^(?:\[([^\]]+)\]:(\d+)|([A-Za-z0-9.-]+))$/u.exec(fields[0] ?? '');
    if (fields.length < 3 || endpoint === null || !/^[A-Za-z0-9+/]+={0,2}$/u.test(fields[2])) unavailable();
    const port = endpoint[2] === undefined ? 22 : Number(endpoint[2]);
    const host = endpoint[1] ?? endpoint[3];
    const key = Buffer.from(fields[2], 'base64');
    if (host === undefined || key.length === 0 || !Number.isInteger(port) || port < 1 || port > 65535) unavailable();
    entries.push({ host, port, fingerprint: `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}` });
  }
  return entries;
}

class KnownHostsSource {
  constructor(
    private readonly root: OperatorRoot,
    private readonly uid: number,
    private readonly fileSystem: PosixRuntimeFileSystem,
  ) {}

  async getEntries(reference: string): Promise<readonly { readonly host: string; readonly port: number; readonly fingerprint: string }[]> {
    return parseKnownHosts(await this.read(reference));
  }

  async withSnapshot<T>(reference: string, work: (path: string, remainingMs: () => number) => Promise<T>, timeoutMs: number): Promise<T> {
    const snapshot = await this.acquireSnapshot(reference, timeoutMs);
    try {
      return await work(snapshot.path, () => Math.max(0, timeoutMs - (Date.now() - snapshot.startedAt)));
    } finally {
      await snapshot.release();
    }
  }

  async acquireSnapshot(
    reference: string,
    timeoutMs: number,
  ): Promise<{ readonly path: string; readonly startedAt: number; readonly release: () => Promise<void> }> {
    const startedAt = Date.now();
    const root = await this.root.verify();
    const directory = await this.fileSystem.mkdtemp(posixPath.join(root, '.ssh-mcp-'));
    try {
      await this.fileSystem.chmod(directory, 0o700);
      const dirStats = await this.fileSystem.lstat(directory);
      if (!operatorOwned(dirStats, this.uid, true) || !beneath(root, directory) || (await this.fileSystem.realpath(directory)) !== directory)
        unavailable();
      const path = posixPath.join(directory, 'known_hosts');
      await this.fileSystem.writeFile(path, await this.read(reference), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      const fileStats = await this.fileSystem.lstat(path);
      if (!operatorOwned(fileStats, this.uid, false) || (await this.fileSystem.realpath(path)) !== path) unavailable();
      if (timeoutMs - (Date.now() - startedAt) <= 0) unavailable();
      let released = false;
      return {
        path,
        startedAt,
        release: async () => {
          if (released) return;
          released = true;
          await this.fileSystem.rm(directory, { recursive: true, force: true });
        },
      };
    } catch (error) {
      await this.fileSystem.rm(directory, { recursive: true, force: true });
      throw error;
    }
  }

  private async read(reference: string): Promise<string> {
    const id = REFERENCE.exec(reference)?.[1];
    if (id === undefined) return unavailable();
    const root = await this.root.verify();
    const path = posixPath.join(root, `${id}.known_hosts`);
    if (!beneath(root, path)) return unavailable();
    try {
      const before = await this.fileSystem.lstat(path);
      const canonical = await this.fileSystem.realpath(path);
      if (!operatorOwned(before, this.uid, false) || !beneath(root, canonical) || !canonical.endsWith(`/${id}.known_hosts`)) unavailable();
      const contents = await this.fileSystem.readFile(canonical);
      const after = await this.fileSystem.lstat(path);
      if (!operatorOwned(after, this.uid, false) || !sameIdentity(before, after) || (await this.fileSystem.realpath(path)) !== canonical)
        unavailable();
      return contents;
    } catch {
      return unavailable();
    }
  }
}

class NativeBoundedCommandRunner implements BoundedCommandRunner {
  run(executable: string, args: readonly string[], timeoutMs: number): Promise<number> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const child = spawn(executable, [...args], { shell: false, windowsHide: true, stdio: 'ignore' });
      const finish = (code: number | null | undefined, failed = false): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (failed || code === undefined || code === null) reject(new Error('command failed'));
        else resolve(code);
      };
      const timer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          // The child may already have exited.
        }
        finish(undefined, true);
      }, timeoutMs);
      child.once('error', () => finish(undefined, true));
      child.once('close', (code) => finish(code));
    });
  }
}

class SshAddIdentity {
  constructor(
    private readonly commands: BoundedCommandRunner,
    private readonly timeoutMs: number,
  ) {}

  async isAvailable(): Promise<boolean> {
    try {
      const remaining = remainingBudget(this.timeoutMs);
      return remaining > 0 && (await this.commands.run('/usr/bin/ssh-add', ['-l'], remaining)) === 0;
    } catch {
      return false;
    }
  }
}

function masterArguments(authorized: AuthorizedConnection, knownHostsPath: string, socketPath: string): readonly string[] {
  const profile = authorized.profile;
  return [
    '-F',
    'none',
    '-N',
    '-T',
    '-n',
    '-M',
    '-S',
    socketPath,
    '-o',
    'ControlPersist=no',
    '-o',
    'CanonicalizeHostname=no',
    '-o',
    'ProxyCommand=none',
    '-o',
    'ProxyJump=none',
    '-o',
    `HostName=${profile.host}`,
    '-o',
    'BatchMode=yes',
    '-o',
    'StrictHostKeyChecking=yes',
    '-o',
    `UserKnownHostsFile=${knownHostsPath}`,
    '-o',
    'GlobalKnownHostsFile=/dev/null',
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    '-o',
    'NumberOfPasswordPrompts=0',
    '-o',
    'IdentitiesOnly=yes',
    '-p',
    String(profile.port),
    '--',
    `${profile.user}@${profile.host}`,
  ];
}

const nativeControlMasterSpawner: PosixControlMasterSpawner = (args) =>
  spawn('/usr/bin/ssh', [...args], {
    shell: false,
    windowsHide: true,
    stdio: 'ignore',
  });

export class NativePosixControlMaster implements PosixControlMaster {
  constructor(
    private readonly commands: BoundedCommandRunner,
    private readonly spawnMaster: PosixControlMasterSpawner = nativeControlMasterSpawner,
  ) {}

  async validate(authorized: AuthorizedConnection, knownHostsPath: string, timeoutMs: number, signal?: AbortSignal): Promise<void> {
    const started = Date.now();
    const remaining = (): number => Math.max(0, timeoutMs - (Date.now() - started));
    const socketPath = posixPath.join(posixPath.dirname(knownHostsPath), 'control.sock');
    const child = this.spawnMaster(masterArguments(authorized, knownHostsPath, socketPath));
    let closed = false;
    let failed = false;
    child.once('close', () => {
      closed = true;
    });
    child.once('error', () => {
      failed = true;
    });
    try {
      while (!closed && !failed && !signal?.aborted && remaining() > 0) {
        try {
          const status = await this.commands.run(
            '/usr/bin/ssh',
            ['-F', 'none', '-S', socketPath, '-O', 'check', '--', `${authorized.profile.user}@${authorized.profile.host}`],
            Math.max(1, Math.min(remaining(), 250)),
          );
          if (status === 0) return;
        } catch {
          // The master may still be negotiating; its deadline remains authoritative.
        }
      }
      if (signal?.aborted) unavailable();
      unavailable();
    } finally {
      const cleanup = Math.max(1, remaining());
      try {
        await this.commands.run(
          '/usr/bin/ssh',
          ['-F', 'none', '-S', socketPath, '-O', 'exit', '--', `${authorized.profile.user}@${authorized.profile.host}`],
          cleanup,
        );
      } catch {
        // Killing the direct child below is mandatory regardless of -O exit.
      }
      try {
        child.kill('SIGKILL');
      } catch {
        // The child has already stopped.
      }
      const confirmedClose =
        closed ||
        (await new Promise<boolean>((resolve) => {
          const wait = remaining();
          if (wait <= 0) {
            resolve(false);
            return;
          }
          const timer = setTimeout(() => resolve(false), Math.min(wait, 100));
          child.once('close', () => {
            clearTimeout(timer);
            resolve(true);
          });
        }));
      if (!confirmedClose || remaining() <= 0) unavailable();
    }
  }
}

class RuntimeReadinessAdapter implements ConnectionReadinessAdapter {
  constructor(
    private readonly knownHosts: KnownHostsSource,
    private readonly controlMaster: PosixControlMaster,
    private readonly timeoutMs: number,
  ) {}

  async connect(authorized: AuthorizedConnection, signal?: AbortSignal): Promise<void> {
    const authorization = await this.authorize(authorized, signal);
    await authorization.release?.();
  }

  async authorize(authorized: AuthorizedConnection, signal?: AbortSignal): Promise<ValidatedConnectionAuthorization> {
    if (signal?.aborted) unavailable();
    if (authorized.authentication.mode !== 'agent-key') unavailable();
    const lease = await this.knownHosts.acquireSnapshot(authorized.knownHostsReference, remainingBudget(this.timeoutMs));
    try {
      const remaining = Math.max(0, this.timeoutMs - (Date.now() - lease.startedAt));
      if (remaining <= 0) unavailable();
      await this.controlMaster.validate(authorized, lease.path, remaining, signal);
      return {
        profile: authorized.profile,
        withTransportContext: async <T>(work: (context: object) => Promise<T>): Promise<T> => work({ knownHostsPath: lease.path }),
        release: lease.release,
      };
    } catch (error) {
      await lease.release();
      throw error;
    }
  }
}

/**
 * Compose the only supported production validation flow. It deliberately
 * creates no password provider and rejects non-POSIX platforms before any
 * filesystem or process action.
 */
export function createRuntimeConnectionValidationProvider(dependencies: PosixRuntimeValidationDependencies = {}): ConnectionValidationProvider {
  const environment = dependencies.environment ?? process.env;
  const platform = dependencies.platform ?? process.platform;
  const uid = dependencies.uid ?? process.getuid?.();
  if ((platform !== 'linux' && platform !== 'darwin') || uid === undefined) unavailable();
  const stateRoot = environment.SSH_MCP_STATE_ROOT;
  const knownHostsRoot = environment[SSH_MCP_KNOWN_HOSTS_ROOT_ENV];
  if (stateRoot === undefined || knownHostsRoot === undefined) unavailable();

  const fileSystem = dependencies.fileSystem ?? nodeFileSystem;
  const duration = boundedTimeout(dependencies.timeoutMs);
  const state = new OperatorRoot(stateRoot, uid, fileSystem);
  const knownHosts = new KnownHostsSource(new OperatorRoot(knownHostsRoot, uid, fileSystem), uid, fileSystem);
  const registry = dependencies.profileRegistry ?? new LocalConnectionProfileRegistry({ stateRoot, operatorUid: uid });
  const profiles = {
    getProfile: async (profileId: string): Promise<ConnectionProfile | undefined> => {
      await state.verify();
      const profile = await registry.getProfile(profileId);
      await state.verify();
      return profile;
    },
  };
  const commands = dependencies.commandRunner ?? new NativeBoundedCommandRunner();
  const policy = new HostIdentityCredentialPolicy({
    profiles,
    knownHosts,
    agentIdentity: new SshAddIdentity(commands, duration),
    credentialResolver: { isApproved: async () => false },
  });
  const provider = createTrustedConnectionValidationProvider({
    policy,
    readinessAdapter: new RuntimeReadinessAdapter(knownHosts, dependencies.controlMaster ?? new NativePosixControlMaster(commands), duration),
  });
  return {
    validateConnection: async (input, signal) =>
      validationDeadline.run(Date.now() + duration, async () => {
        if (remainingBudget(duration) <= 0 || signal?.aborted) unavailable();
        const result = await provider.validateConnection(input, signal);
        if (signal?.aborted) unavailable();
        return result;
      }),
    authorizeExecution: async (input, signal) =>
      validationDeadline.run(Date.now() + duration, async () => {
        if (remainingBudget(duration) <= 0 || signal?.aborted) unavailable();
        const authorization = provider.authorizeExecution;
        if (authorization === undefined) unavailable();
        const result = await authorization(input, signal);
        if (signal?.aborted) unavailable();
        return result;
      }),
  };
}

/**
 * Production remote execution composition for POSIX. It reuses the same
 * profile registry and validation boundary as readiness checks; the SSH2
 * transport receives only the validated profile and never local shell input.
 */
export function createRuntimeRemoteCommandExecutionProvider(
  dependencies: PosixRuntimeValidationDependencies = {},
  humanApproval?: HumanSudoApprovalProvider,
): RemoteCommandExecutionProvider {
  const environment = dependencies.environment ?? process.env;
  const platform = dependencies.platform ?? process.platform;
  const uid = dependencies.uid ?? process.getuid?.();
  if ((platform !== 'linux' && platform !== 'darwin') || uid === undefined) unavailable();
  const stateRoot = environment.SSH_MCP_STATE_ROOT;
  if (stateRoot === undefined) unavailable();
  const registry = dependencies.profileRegistry ?? new LocalConnectionProfileRegistry({ stateRoot, operatorUid: uid });
  const validationProvider = dependencies.connectionValidationProvider ?? createRuntimeConnectionValidationProvider(dependencies);
  const credentials = {
    async getPassword(reference: string) {
      const resolver = createPlatformCredentialStoreResolver({ platform, approvedReferences: [reference] });
      const store = resolver.resolve(reference);
      return store.getPassword(reference as Parameters<typeof store.getPassword>[0]);
    },
  };
  const auditRoot = environment[SSH_MCP_AUDIT_ROOT_ENV];
  const auditKeyFile = environment[SSH_MCP_AUDIT_KEY_FILE_ENV];
  const auditJournal =
    auditRoot !== undefined && auditKeyFile !== undefined
      ? new PosixExecutionAuditJournal({ root: auditRoot, keyFile: auditKeyFile, uid })
      : new UnavailableExecutionAuditJournal();
  return new RemoteCommandExecutionProvider({
    profiles: registry,
    connectionValidation: validationProvider,
    transport: new Ssh2RemoteCommandTransport(credentials, environment.SSH_AUTH_SOCK),
    auditJournal,
    humanApproval,
  });
}
