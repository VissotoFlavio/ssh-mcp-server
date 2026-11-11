import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  NativePosixControlMaster,
  SSH_MCP_KNOWN_HOSTS_ROOT_ENV,
  createRuntimeConnectionValidationProvider,
  createRuntimeRemoteCommandExecutionProvider,
  type PosixControlMasterChild,
  type PosixFileStats,
  type PosixRuntimeFileSystem,
} from '../../src/runtime/posix-runtime-validation.js';
import { toConnectionValidationFailure } from '../../src/validation/trusted-connection-validation.js';

const key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const fingerprint = `SHA256:${createHash('sha256').update(Buffer.from(key, 'base64')).digest('base64').replace(/=+$/u, '')}`;
const profile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: fingerprint,
  authMode: 'agent-key' as const,
  approvedKnownHostsReference: 'known-hosts://production-api',
};

class NonClosingChild implements PosixControlMasterChild {
  kills = 0;

  once(event: 'close', listener: (code: number | null) => void): unknown;
  once(event: 'error', listener: () => void): unknown;
  once(_event: 'close' | 'error', _listener: ((code: number | null) => void) | (() => void)): unknown {
    return this;
  }

  kill(): boolean {
    this.kills += 1;
    return true;
  }
}

function stats(kind: 'directory' | 'file', ino: number, mode = kind === 'directory' ? 0o700 : 0o600): PosixFileStats {
  return {
    uid: 1000,
    mode,
    dev: 1,
    ino,
    isDirectory: () => kind === 'directory',
    isFile: () => kind === 'file',
    isSymbolicLink: () => false,
  };
}

class FakeFileSystem implements PosixRuntimeFileSystem {
  readonly removed: string[] = [];
  readonly written = new Map<string, string>();
  sourceIdentity = 3;
  sourceMode = 0o600;
  rootMode = 0o700;
  replaceAfterRead = false;
  rmFails = false;
  private nextDirectory = 10;

  async lstat(path: string): Promise<PosixFileStats> {
    if (path === '/state' || path === '/known') return stats('directory', path === '/state' ? 1 : 2, this.rootMode);
    if (path === '/known/production-api.known_hosts') return stats('file', this.sourceIdentity, this.sourceMode);
    if (path.endsWith('/known_hosts')) return stats('file', Number(path.match(/(\d+)/u)?.[1] ?? 99));
    return stats('directory', Number(path.match(/(\d+)/u)?.[1] ?? 99));
  }

  async realpath(path: string): Promise<string> {
    return path;
  }

  async readFile(path: string): Promise<string> {
    if (path === '/known/production-api.known_hosts') {
      if (this.replaceAfterRead) this.sourceIdentity += 1;
      return `api.internal.example ssh-ed25519 ${key}\n`;
    }
    return this.written.get(path) ?? '';
  }

  async mkdtemp(prefix: string): Promise<string> {
    return `${prefix}${this.nextDirectory++}`;
  }

  async chmod(): Promise<void> {}

  async writeFile(path: string, data: string): Promise<void> {
    this.written.set(path, data);
  }

  async rm(path: string): Promise<void> {
    this.removed.push(path);
    if (this.rmFails) throw new Error('cleanup failed');
  }
}

function runtime(
  fileSystem: FakeFileSystem,
  overrides: { agent?: () => Promise<number>; master?: (path: string) => Promise<void>; platform?: string; timeoutMs?: number } = {},
) {
  let agentCalls = 0;
  let masterCalls = 0;
  const provider = createRuntimeConnectionValidationProvider({
    environment: { SSH_MCP_STATE_ROOT: '/state', [SSH_MCP_KNOWN_HOSTS_ROOT_ENV]: '/known' },
    platform: overrides.platform ?? 'linux',
    uid: 1000,
    fileSystem,
    profileRegistry: { getProfile: async () => profile },
    commandRunner: {
      run: async () => {
        agentCalls += 1;
        return overrides.agent === undefined ? 0 : overrides.agent();
      },
    },
    controlMaster: {
      validate: async (_authorized, path) => {
        masterCalls += 1;
        await (overrides.master?.(path) ?? Promise.resolve());
      },
    },
    timeoutMs: overrides.timeoutMs ?? 100,
  });
  return { provider, agentCalls: () => agentCalls, masterCalls: () => masterCalls };
}

test('fails closed on an unsupported platform before any filesystem or process action', () => {
  const fileSystem = new FakeFileSystem();
  assert.throws(() => runtime(fileSystem, { platform: 'win32' }), /POSIX connection validation runtime is unavailable/);
  assert.deepEqual(fileSystem.removed, []);
});

test('production execution binds sudo approval to the validated POSIX authorization lease', async () => {
  let authorizationCalls = 0;
  let observedIdentity: unknown;
  const provider = createRuntimeRemoteCommandExecutionProvider(
    {
      environment: { SSH_MCP_STATE_ROOT: '/state' },
      platform: 'linux',
      uid: 1000,
      profileRegistry: { getProfile: async () => profile },
      connectionValidationProvider: {
        validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }),
        authorizeExecution: async (input) => {
          assert.deepEqual(input, { profileId: profile.profileId });
          authorizationCalls += 1;
          return { profile };
        },
      },
    },
    {
      approve: async (request) => {
        observedIdentity = request.approvedIdentity;
        return true;
      },
    },
  );

  const result = await provider.requestSudoApproval({ profileId: profile.profileId, command: 'sudo', args: ['id'] });
  assert.equal(result.approved, true);
  assert.equal(authorizationCalls, 1);
  assert.deepEqual(observedIdentity, {
    host: profile.host,
    port: profile.port,
    user: profile.user,
    expectedHostFingerprint: profile.expectedHostFingerprint,
    authMode: profile.authMode,
    approvedKnownHostsReference: profile.approvedKnownHostsReference,
  });
});

test('rejects an operator root with unsafe permissions before ssh-add or a master runs', async () => {
  const fileSystem = new FakeFileSystem();
  fileSystem.rootMode = 0o777;
  const candidate = runtime(fileSystem);
  await assert.rejects(candidate.provider.validateConnection({ profileId: profile.profileId }));
  assert.equal(candidate.agentCalls(), 0);
  assert.equal(candidate.masterCalls(), 0);
});

test('composes an agent-key validation with a private known-hosts snapshot and cleanup', async () => {
  const fileSystem = new FakeFileSystem();
  let observedSnapshot = '';
  const candidate = runtime(fileSystem, {
    master: async (path) => {
      observedSnapshot = path;
      assert.equal(fileSystem.written.get(path), `api.internal.example ssh-ed25519 ${key}\n`);
    },
  });

  assert.deepEqual(await candidate.provider.validateConnection({ profileId: profile.profileId }), { profileId: profile.profileId, ready: true });
  assert.equal(candidate.agentCalls(), 1);
  assert.equal(candidate.masterCalls(), 1);
  assert.equal(observedSnapshot.endsWith('/known_hosts'), true);
  assert.deepEqual(fileSystem.removed, [observedSnapshot.slice(0, observedSnapshot.lastIndexOf('/'))]);
});

test('detects known-hosts replacement before invoking ssh-add or the master', async () => {
  const fileSystem = new FakeFileSystem();
  fileSystem.replaceAfterRead = true;
  const candidate = runtime(fileSystem);
  await assert.rejects(candidate.provider.validateConnection({ profileId: profile.profileId }), (error) => {
    assert.deepEqual(toConnectionValidationFailure(error), { ready: false, outcome: 'failure', code: 'host-key-failure' });
    return true;
  });
  assert.equal(candidate.agentCalls(), 0);
  assert.equal(candidate.masterCalls(), 0);
});

test('bounds ssh-add failure and cleans the private snapshot after a master failure', async () => {
  const agentFileSystem = new FakeFileSystem();
  const agent = runtime(agentFileSystem, { agent: async () => Promise.reject(new Error('timeout')) });
  await assert.rejects(agent.provider.validateConnection({ profileId: profile.profileId }));
  assert.equal(agent.masterCalls(), 0);
  assert.deepEqual(agentFileSystem.removed, []);

  const masterFileSystem = new FakeFileSystem();
  const master = runtime(masterFileSystem, { master: async () => Promise.reject(new Error('master failure')) });
  await assert.rejects(master.provider.validateConnection({ profileId: profile.profileId }));
  assert.equal(master.masterCalls(), 1);
  assert.equal(masterFileSystem.removed.length, 1);
});

test('uses one validation budget after a delayed ssh-add and fails closed when snapshot cleanup fails', async () => {
  const deadlineFileSystem = new FakeFileSystem();
  const deadline = runtime(deadlineFileSystem, {
    agent: async () => new Promise((resolve) => setTimeout(() => resolve(0), 20)),
    timeoutMs: 5,
  });
  await assert.rejects(deadline.provider.validateConnection({ profileId: profile.profileId }));
  assert.equal(deadline.masterCalls(), 0);

  const cleanupFileSystem = new FakeFileSystem();
  cleanupFileSystem.rmFails = true;
  const cleanup = runtime(cleanupFileSystem);
  await assert.rejects(cleanup.provider.validateConnection({ profileId: profile.profileId }));
  assert.equal(cleanup.masterCalls(), 1);
  assert.equal(cleanupFileSystem.removed.length, 1);
});

test('native ControlMaster refuses success until its child close is confirmed within the deadline', async () => {
  const child = new NonClosingChild();
  const master = new NativePosixControlMaster({ run: async () => 0 }, () => child);
  await assert.rejects(
    master.validate(
      {
        profile,
        knownHostsReference: profile.approvedKnownHostsReference,
        hostIdentity: { host: profile.host, port: profile.port, fingerprint: profile.expectedHostFingerprint },
        authentication: { mode: 'agent-key' },
      },
      '/known/.ssh-mcp-1/known_hosts',
      20,
    ),
  );
  assert.equal(child.kills, 1);
});
