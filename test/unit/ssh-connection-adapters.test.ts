import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  OpenSshAgentAdapter,
  PasswordSshAdapter,
  SshAdapterError,
  type InMemoryPasswordTransport,
  type OpenSshExecutableResolver,
  type SshProcessRunner,
  type TrustedConnectionDescriptor,
} from '../../src/adapters/ssh-connection-adapters.ts';

const agentProfile: TrustedConnectionDescriptor = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  authMode: 'agent-key',
  knownHostsReference: 'known-hosts://production-api',
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
  result = { exitCode: 0 };

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
    profiles: { getConnection: async (profileId: string) => profileId === agentProfile.profileId ? agentProfile : undefined },
    knownHosts: { resolve: async (reference: string) => reference === agentProfile.knownHostsReference ? '/srv/ssh/approved/known_hosts' : undefined },
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
    '-N', '-T', '-n',
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'UserKnownHostsFile=/srv/ssh/approved/known_hosts',
    '-o', `GlobalKnownHostsFile=${process.platform === 'win32' ? 'NUL' : '/dev/null'}`,
    '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'NumberOfPasswordPrompts=0',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'ConnectTimeout=12',
    '-p', '22',
    'deploy@api.internal.example',
  ]);
});

test('rejects arbitrary connection fields before consulting the trusted provider', async () => {
  let calls = 0;
  const dependencies = agentDependencies();
  dependencies.profiles = { getConnection: async () => { calls += 1; return agentProfile; } };
  await assert.rejects(
    new OpenSshAgentAdapter(dependencies).connect({ profileId: 'production-api', host: 'attacker.example', command: 'rm -rf /' }),
    error => error instanceof SshAdapterError && error.code === 'invalid-selection' && error.message === 'Connection selection is invalid',
  );
  assert.equal(calls, 0);
});

test('fails closed when known-hosts resolution or OpenSSH execution fails', async () => {
  const dependencies = agentDependencies();
  dependencies.knownHosts = { resolve: async () => 'relative/should-fail' };
  await assert.rejects(
    new OpenSshAgentAdapter(dependencies).connect({ profileId: 'production-api' }),
    error => error instanceof SshAdapterError && error.code === 'known-hosts-unavailable',
  );

  const runner = new FakeRunner();
  runner.result = { exitCode: 255 };
  await assert.rejects(
    new OpenSshAgentAdapter(agentDependencies(runner)).connect({ profileId: 'production-api' }),
    error => error instanceof SshAdapterError && error.code === 'ssh-connection-failed' && error.message === 'SSH connection failed',
  );
});

test('passes password only to the injected in-memory transport', async () => {
  const requests: Array<{ password: string; knownHostsPath: string }> = [];
  const transport: InMemoryPasswordTransport = {
    connect: async request => { requests.push({ password: request.password, knownHostsPath: request.knownHostsPath }); },
  };
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => 'C:\\approved\\known_hosts' },
    credentials: { getPassword: async () => ({ password: 'do-not-log-me' }) },
    transport,
  });

  await adapter.connect({ profileId: 'production-api' });
  assert.deepEqual(requests, [{ password: 'do-not-log-me', knownHostsPath: 'C:\\approved\\known_hosts' }]);
});

test('does not use a shell workaround and fails closed without password transport', async () => {
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => '/srv/ssh/approved/known_hosts' },
    credentials: { getPassword: async () => ({ password: 'secret' }) },
  });
  await assert.rejects(
    adapter.connect({ profileId: 'production-api' }),
    error => error instanceof SshAdapterError && error.code === 'password-transport-unavailable' && !error.message.includes('secret'),
  );
});

test('bounds a password transport that never completes', async () => {
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => '/srv/ssh/approved/known_hosts' },
    credentials: { getPassword: async () => ({ password: 'secret' }) },
    transport: { connect: async () => new Promise<void>(() => {}) },
    timeoutMs: 5,
  });
  await assert.rejects(
    adapter.connect({ profileId: 'production-api' }),
    error => error instanceof SshAdapterError && error.code === 'ssh-timeout' && error.message === 'SSH connection timed out',
  );
});

test('redacts credential and child-process failures', async () => {
  const adapter = new PasswordSshAdapter({
    profiles: { getConnection: async () => passwordProfile },
    knownHosts: { resolve: async () => '/srv/ssh/approved/known_hosts' },
    credentials: { getPassword: async () => { throw new Error('secret-password'); } },
    transport: { connect: async () => { throw new Error('secret-password'); } },
  });
  await assert.rejects(adapter.connect({ profileId: 'production-api' }), error => {
    assert.ok(error instanceof SshAdapterError);
    assert.equal(error.code, 'password-unavailable');
    assert.equal(error.message, 'Password is unavailable');
    assert.doesNotMatch(error.message, /secret-password/);
    return true;
  });
});
