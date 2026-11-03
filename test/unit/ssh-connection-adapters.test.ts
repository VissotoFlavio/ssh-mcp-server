import { strict as assert } from 'node:assert';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  OpenSshAgentAdapter,
  NativeOpenSshProcessRunner,
  PasswordSshAdapter,
  SshAdapterError,
  type InMemoryPasswordTransport,
  type OpenSshExecutableResolver,
  type SshProcessRunner,
  type TrustedConnectionDescriptor,
} from '../../src/adapters/ssh-connection-adapters.js';

const agentProfile: TrustedConnectionDescriptor = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  authMode: 'agent-key',
  knownHostsReference: 'known-hosts://production-api',
  expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
};

const passwordProfile: TrustedConnectionDescriptor = {
  ...agentProfile,
  authMode: 'password',
  credentialReference: 'os://ssh/production-api',
};

class FakeRunner implements SshProcessRunner {
  executable = '';
  args: readonly string[] = [];
  options: { readonly timeoutMs: number; readonly shell: false } | undefined;
  result = { exitCode: 0, ready: true };

  run(executable: string, args: readonly string[], options: { readonly timeoutMs: number; readonly shell: false }) {
    this.executable = executable;
    this.args = args;
    this.options = options;
    return Promise.resolve(this.result);
  }
}

class FakeExecutable implements OpenSshExecutableResolver {
  resolve() {
    return '/usr/bin/ssh';
  }
}

function agentDependencies(runner: SshProcessRunner = new FakeRunner()) {
  return {
    profiles: { getConnection: async (profileId: string) => (profileId === agentProfile.profileId ? agentProfile : undefined) },
    knownHosts: {
      resolve: async (reference: string) =>
        reference === agentProfile.knownHostsReference
          ? {
              path: '/srv/ssh/approved/known_hosts',
              fingerprint: agentProfile.expectedHostFingerprint,
            }
          : undefined,
    },
    trustedKnownHostsDirectory: '/srv/ssh',
    targetPlatform: 'linux',
    realpath: async (path: string) => path,
    executable: new FakeExecutable(),
    runner,
    timeoutMs: 12_000,
  };
}

test('accepts only profileId and builds a fixed non-interactive agent command', async () => {
  const runner = new FakeRunner();
  await new OpenSshAgentAdapter(agentDependencies(runner)).connect({ profileId: 'production-api' });

  assert.equal(runner.executable, '/usr/bin/ssh');
  assert.equal(runner.options?.shell, false);
  assert.deepEqual(runner.args, [
    '-N',
    '-T',
    '-n',
    '-o',
    'BatchMode=yes',
    '-o',
    'StrictHostKeyChecking=yes',
    '-o',
    'UserKnownHostsFile=/srv/ssh/approved/known_hosts',
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
    '-o',
    'ConnectTimeout=12',
    '-p',
    '22',
    '--',
    'deploy@api.internal.example',
  ]);
});

test('rejects arbitrary connection fields before consulting the trusted provider', async () => {
  let calls = 0;
  const dependencies = agentDependencies();
  dependencies.profiles = {
    getConnection: async () => {
      calls += 1;
      return agentProfile;
    },
  };
  await assert.rejects(
    new OpenSshAgentAdapter(dependencies).connect({ profileId: 'production-api', host: 'attacker.example', command: 'rm -rf /' }),
    (error) => error instanceof SshAdapterError && error.code === 'invalid-selection' && error.message === 'Connection selection is invalid',
  );
  assert.equal(calls, 0);
});

test('fails closed when known-hosts resolution or OpenSSH execution fails', async () => {
  const dependencies = agentDependencies();
  dependencies.knownHosts = { resolve: async () => ({ path: 'relative/should-fail', fingerprint: agentProfile.expectedHostFingerprint }) };
  await assert.rejects(
    new OpenSshAgentAdapter(dependencies).connect({ profileId: 'production-api' }),
    (error) => error instanceof SshAdapterError && error.code === 'known-hosts-unavailable',
  );

  const runner = new FakeRunner();
  runner.result = { exitCode: 255, ready: false };
  await assert.rejects(
    new OpenSshAgentAdapter(agentDependencies(runner)).connect({ profileId: 'production-api' }),
    (error) => error instanceof SshAdapterError && error.code === 'ssh-connection-failed' && error.message === 'SSH connection failed',
  );
});

test('requires authenticated readiness before treating a native -N process as connected', async () => {
  const runner: SshProcessRunner = {
    run: async () => ({ exitCode: 0, ready: true }),
  };
  await new OpenSshAgentAdapter(agentDependencies(runner)).connect({ profileId: 'production-api' });
});

test('native runner uses the injected readiness probe and terminates the -N-style child', async () => {
  const runner = new NativeOpenSshProcessRunner({ waitUntilReady: async () => true });
  const result = await runner.run(
    process.execPath,
    ['-e', "process.stderr.write('debug1: Authentication succeeded (publickey).\\n'); setInterval(() => {}, 1000);"],
    { timeoutMs: 1_000, shell: false },
  );
  assert.deepEqual(result, { exitCode: 0, ready: true });
});

test('native runner never infers readiness from stderr and requires a trusted probe', async () => {
  const runner = new NativeOpenSshProcessRunner({ waitUntilReady: async () => false });
  await assert.rejects(
    runner.run(process.execPath, ['-e', "process.stderr.write('debug1: Authentication succeeded (publickey).\\n'); setInterval(() => {}, 1000);"], {
      timeoutMs: 100,
      shell: false,
    }),
    (error) => error instanceof SshAdapterError && error.code === 'ssh-connection-failed',
  );
  await assert.rejects(
    new NativeOpenSshProcessRunner().run(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { timeoutMs: 100, shell: false }),
    (error) => error instanceof SshAdapterError && error.message === 'SSH readiness probe is unavailable',
  );
});

test('rejects target delimiters and never turns them into an SSH destination', async () => {
  for (const field of ['host', 'user'] as const) {
    const profile = { ...agentProfile, [field]: field === 'host' ? 'api:22' : 'deploy@evil' };
    const adapter = new OpenSshAgentAdapter({
      ...agentDependencies(),
      profiles: { getConnection: async () => profile },
    });
    await assert.rejects(
      adapter.connect({ profileId: 'production-api' }),
      (error) => error instanceof SshAdapterError && error.code === 'invalid-trusted-profile',
    );
  }
});

test('requires the exact approved fingerprint and confines known-hosts paths', async () => {
  const mismatch = new OpenSshAgentAdapter({
    ...agentDependencies(),
    knownHosts: {
      resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint: 'SHA256:2222222222222222222222222222222222222222222' }),
    },
  });
  await assert.rejects(
    mismatch.connect({ profileId: 'production-api' }),
    (error) => error instanceof SshAdapterError && error.code === 'known-hosts-fingerprint-mismatch',
  );

  const broadPath = new OpenSshAgentAdapter({
    ...agentDependencies(),
    knownHosts: { resolve: async () => ({ path: '/etc/known_hosts', fingerprint: agentProfile.expectedHostFingerprint }) },
  });
  await assert.rejects(
    broadPath.connect({ profileId: 'production-api' }),
    (error) => error instanceof SshAdapterError && error.code === 'known-hosts-unavailable',
  );

  const windowsPathOnPosix = new OpenSshAgentAdapter({
    ...agentDependencies(),
    knownHosts: { resolve: async () => ({ path: 'C:\\srv\\ssh\\known_hosts', fingerprint: agentProfile.expectedHostFingerprint }) },
  });
  await assert.rejects(
    windowsPathOnPosix.connect({ profileId: 'production-api' }),
    (error) => error instanceof SshAdapterError && error.code === 'known-hosts-unavailable',
  );

  const windowsPath = new OpenSshAgentAdapter({
    ...agentDependencies(),
    targetPlatform: 'win32',
    trustedKnownHostsDirectory: 'C:\\trusted\\ssh',
    executable: { resolve: () => 'C:\\Windows\\System32\\OpenSSH\\ssh.exe' },
    knownHosts: { resolve: async () => ({ path: 'C:\\trusted\\ssh\\known_hosts', fingerprint: agentProfile.expectedHostFingerprint }) },
  });
  await windowsPath.connect({ profileId: 'production-api' });
});

test('supports only bracketed IPv6 literals in the trusted target', async () => {
  const runner = new FakeRunner();
  const profile = { ...agentProfile, host: '[2001:db8::1]' };
  await new OpenSshAgentAdapter({
    ...agentDependencies(runner),
    profiles: { getConnection: async () => profile },
  }).connect({ profileId: 'production-api' });
  assert.equal(runner.args.at(-1), 'deploy@[2001:db8::1]');

  for (const host of ['2001:db8::1', '[2001:db8:zz::1]', '[2001:db8::1']) {
    const invalid = host === '[2001:db8::1]' ? '[2001:db8::1' : host;
    await assert.rejects(
      new OpenSshAgentAdapter({
        ...agentDependencies(),
        profiles: { getConnection: async () => ({ ...agentProfile, host: invalid }) },
      }).connect({ profileId: 'production-api' }),
      (error) => error instanceof SshAdapterError && error.code === 'invalid-trusted-profile',
    );
  }
});

test('passes password only to the injected in-memory transport', async () => {
  const requests: Array<{ password: string; knownHostsPath: string }> = [];
  const transport: InMemoryPasswordTransport = {
    connect: async (request) => {
      requests.push({ password: request.password, knownHostsPath: request.knownHostsPath });
    },
  };
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint: passwordProfile.expectedHostFingerprint }) },
    trustedKnownHostsDirectory: '/srv/ssh',
    targetPlatform: 'linux',
    realpath: async (path: string) => path,
    credentials: { getPassword: async () => ({ password: 'do-not-log-me' }) },
    transport,
  });

  await adapter.connect({ profileId: 'production-api' });
  assert.deepEqual(requests, [{ password: 'do-not-log-me', knownHostsPath: '/srv/ssh/approved/known_hosts' }]);
});

test('does not use a shell workaround and fails closed without password transport', async () => {
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint: passwordProfile.expectedHostFingerprint }) },
    trustedKnownHostsDirectory: '/srv/ssh',
    targetPlatform: 'linux',
    realpath: async (path: string) => path,
    credentials: { getPassword: async () => ({ password: 'secret' }) },
  });
  await assert.rejects(
    adapter.connect({ profileId: 'production-api' }),
    (error) => error instanceof SshAdapterError && error.code === 'password-transport-unavailable' && !error.message.includes('secret'),
  );
});

test('bounds a password transport that never completes', async () => {
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint: passwordProfile.expectedHostFingerprint }) },
    trustedKnownHostsDirectory: '/srv/ssh',
    targetPlatform: 'linux',
    realpath: async (path: string) => path,
    credentials: { getPassword: async () => ({ password: 'secret' }) },
    transport: {
      connect: async (_request, signal) =>
        new Promise<void>((resolve) => {
          signal?.addEventListener('abort', () => setTimeout(resolve, 10), { once: true });
        }),
    },
    timeoutMs: 5,
  });
  await assert.rejects(
    adapter.connect({ profileId: 'production-api' }),
    (error) => error instanceof SshAdapterError && error.code === 'ssh-timeout' && error.message === 'SSH connection timed out',
  );
});

test('returns a hard timeout for a non-cooperative password transport', async () => {
  const started = Date.now();
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint: passwordProfile.expectedHostFingerprint }) },
    trustedKnownHostsDirectory: '/srv/ssh',
    targetPlatform: 'linux',
    realpath: async (path: string) => path,
    credentials: { getPassword: async () => ({ password: 'secret' }) },
    transport: { connect: async () => new Promise<void>((resolve) => setTimeout(resolve, 500)) },
    timeoutMs: 5,
  });
  await assert.rejects(adapter.connect({ profileId: 'production-api' }), (error) => error instanceof SshAdapterError && error.code === 'ssh-timeout');
  assert.ok(Date.now() - started < 300);
});

test('canonicalizes known-hosts files and rejects symlink escapes', async (t) => {
  const platform = process.platform === 'win32' ? 'win32' : 'linux';
  const root = await mkdtemp(join(tmpdir(), 'ssh-adapter-'));
  const approved = join(root, 'approved');
  const knownHosts = join(approved, 'known_hosts');
  const outside = join(root, '..', 'ssh-adapter-outside-known_hosts');
  const link = join(approved, 'linked_known_hosts');
  await mkdir(approved);
  await writeFile(knownHosts, 'approved');
  await writeFile(outside, 'outside');
  try {
    const base = {
      profiles: { getConnection: async () => agentProfile },
      trustedKnownHostsDirectory: root,
      targetPlatform: platform,
      knownHosts: { resolve: async () => ({ path: knownHosts, fingerprint: agentProfile.expectedHostFingerprint }) },
      executable: { resolve: () => process.execPath },
      runner: new FakeRunner(),
    };
    await new OpenSshAgentAdapter(base).connect({ profileId: 'production-api' });

    try {
      await symlink(outside, link);
    } catch {
      t.skip('symlink creation is unavailable on this host');
      return;
    }
    await assert.rejects(
      new OpenSshAgentAdapter({
        ...base,
        knownHosts: { resolve: async () => ({ path: link, fingerprint: agentProfile.expectedHostFingerprint }) },
      }).connect({ profileId: 'production-api' }),
      (error) => error instanceof SshAdapterError && error.code === 'known-hosts-unavailable',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { force: true });
  }
});

test('redacts credential and child-process failures', async () => {
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint: passwordProfile.expectedHostFingerprint }) },
    trustedKnownHostsDirectory: '/srv/ssh',
    targetPlatform: 'linux',
    realpath: async (path: string) => path,
    credentials: {
      getPassword: async () => {
        throw new Error('secret-password');
      },
    },
    transport: {
      connect: async () => {
        throw new Error('secret-password');
      },
    },
  });
  await assert.rejects(adapter.connect({ profileId: 'production-api' }), (error) => {
    assert.ok(error instanceof SshAdapterError);
    assert.equal(error.code, 'password-unavailable');
    assert.equal(error.message, 'Password is unavailable');
    assert.doesNotMatch(error.message, /secret-password/);
    return true;
  });
});
