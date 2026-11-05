import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  DirectWindowsOpenSshCommandRunner,
  WindowsOpenSshError,
  WindowsOpenSshResolver,
  WindowsSshAddIdentity,
  type WindowsOpenSshBinding,
  type WindowsOpenSshCommandRunner,
} from '../../src/windows/windows-openssh.js';

const paths = Object.freeze({
  ssh: 'C:\\Windows\\System32\\OpenSSH\\ssh.exe',
  sshAdd: 'C:\\Windows\\System32\\OpenSSH\\ssh-add.exe',
  version: '9.5.0.0',
});

function binding(value: unknown = paths): WindowsOpenSshBinding {
  return { resolveOpenSsh: () => value as { readonly ssh: string; readonly sshAdd: string; readonly version: string } };
}

test('uses only the pair returned by the native Windows trust boundary', () => {
  const resolver = new WindowsOpenSshResolver(binding());
  assert.equal(resolver.resolve(), paths.ssh);
  assert.deepEqual(resolver.paths(), paths);
});

test('fails closed when the native executable boundary is malformed or unavailable', () => {
  assert.throws(() => new WindowsOpenSshResolver(binding({ ssh: paths.ssh })).resolve(), WindowsOpenSshError);
  assert.throws(() => new WindowsOpenSshResolver(binding({ ...paths, version: '9.4.9.0' })).resolve(), WindowsOpenSshError);
  assert.equal(new WindowsOpenSshResolver(binding({ ...paths, version: '10.0.0.0' })).resolve(), paths.ssh);
  assert.throws(
    () =>
      new WindowsOpenSshResolver({
        resolveOpenSsh: () => {
          throw new Error('untrusted path');
        },
      }).resolve(),
    WindowsOpenSshError,
  );
});

test('probes an agent only with the native-verified ssh-add path and fixed arguments', async () => {
  const calls: Array<{ executable: string; args: readonly string[]; timeoutMs: number }> = [];
  const commands: WindowsOpenSshCommandRunner = {
    run: async (executable, args, timeoutMs) => {
      calls.push({ executable, args, timeoutMs });
      return 0;
    },
  };
  const identity = new WindowsSshAddIdentity(new WindowsOpenSshResolver(binding()), 10_000, commands);

  assert.equal(await identity.isAvailable(), true);
  assert.deepEqual(calls, [{ executable: paths.sshAdd, args: ['-l'], timeoutMs: 10_000 }]);
});

test('fails closed when agent probing throws or returns a non-zero status', async () => {
  const resolver = new WindowsOpenSshResolver(binding());
  assert.equal(await new WindowsSshAddIdentity(resolver, 1_000, { run: async () => 1 }).isAvailable(), false);
  assert.equal(
    await new WindowsSshAddIdentity(resolver, 1_000, {
      run: async () => {
        throw new Error('agent unavailable');
      },
    }).isAvailable(),
    false,
  );
});

test('bounds a direct ssh-add-style child and waits for its close', async () => {
  const runner = new DirectWindowsOpenSshCommandRunner();
  assert.notEqual(await runner.run(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], 25), 0);
});
