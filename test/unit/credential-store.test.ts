import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  CredentialStoreError,
  PlatformCredentialStoreResolver,
  type CredentialStoreCommandResult,
  type CredentialStoreCommandRunner,
  parseCredentialReference,
  validateCredentialReference,
} from '../../src/credentials/credential-store.js';

class FakeRunner implements CredentialStoreCommandRunner {
  public executable = '';
  public args: readonly string[] = [];
  public calls = 0;
  public result: CredentialStoreCommandResult = { stdout: 'approved-password\n' };

  run(executable: string, args: readonly string[]): Promise<CredentialStoreCommandResult> {
    this.calls += 1;
    this.executable = executable;
    this.args = args;
    return Promise.resolve(this.result);
  }
}

test('accepts only opaque OS credential references', () => {
  const parsed = parseCredentialReference('os://ssh/production-api');
  assert.equal(parsed.provider, 'ssh');
  assert.equal(parsed.locator, 'production-api');
  assert.equal(parsed.reference, 'os://ssh/production-api');
  assert.equal(validateCredentialReference('os://ssh/production-api'), parsed.reference);
});

test('rejects secret material, controls, and command-like reference values', () => {
  const invalidReferences = [
    'password=approved-password',
    'os://ssh/password=approved-password',
    'os://ssh/passphrase:secret',
    'os://ssh/private-key',
    'os://ssh/-----BEGIN PRIVATE KEY-----',
    'os://ssh/production-api\n--delete',
    'os://ssh/production-api?password=secret',
    'os://ssh/../production-api',
  ];

  for (const reference of invalidReferences) {
    assert.throws(() => validateCredentialReference(reference), error => {
      assert.ok(error instanceof CredentialStoreError);
      assert.equal(error.code, 'invalid-reference');
      assert.doesNotMatch(error.message, /approved-password|secret|private-key/iu);
      return true;
    });
  }
});

test('fails closed on unsupported platforms', () => {
  const resolver = new PlatformCredentialStoreResolver({
    platform: 'win32',
    approvedReferences: ['os://ssh/production-api'],
  });

  assert.throws(() => resolver.resolve('os://ssh/production-api'), error => {
    assert.ok(error instanceof CredentialStoreError);
    assert.equal(error.code, 'unsupported-platform');
    assert.equal(error.message, 'OS credential store is unavailable');
    return true;
  });
});

test('passes only validated argv to a direct platform provider and never logs its output', async () => {
  const runner = new FakeRunner();
  const resolver = new PlatformCredentialStoreResolver({
    platform: 'linux',
    runner,
    approvedReferences: ['os://ssh/production-api'],
  });
  const reference = validateCredentialReference('os://ssh/production-api');
  const store = resolver.resolve(reference);
  const credential = await store.getPassword(reference);

  assert.deepEqual(credential, { password: 'approved-password' });
  assert.equal(runner.executable, '/usr/bin/secret-tool');
  assert.deepEqual(runner.args, ['lookup', 'service', 'ssh', 'account', 'production-api']);
});

test('redacts provider failures and does not surface command stderr', async () => {
  const runner: CredentialStoreCommandRunner = {
    run: async () => {
      throw new Error('stderr contained approved-password');
    },
  };
  const resolver = new PlatformCredentialStoreResolver({
    platform: 'darwin',
    runner,
    approvedReferences: ['os://ssh/production-api'],
  });
  const reference = validateCredentialReference('os://ssh/production-api');

  await assert.rejects(resolver.resolve(reference).getPassword(reference), error => {
    assert.ok(error instanceof CredentialStoreError);
    assert.equal(error.code, 'credential-store-failure');
    assert.equal(error.message, 'Credential store lookup failed');
    assert.doesNotMatch(error.message, /approved-password/);
    return true;
  });
});

test('rejects unapproved references before invoking the runner', () => {
  const runner = new FakeRunner();
  const resolver = new PlatformCredentialStoreResolver({
    platform: 'linux',
    runner,
    approvedReferences: ['os://ssh/production-api'],
  });

  assert.throws(() => resolver.resolve('os://ssh/staging-api'), error => {
    assert.ok(error instanceof CredentialStoreError);
    assert.equal(error.code, 'unapproved-reference');
    assert.equal(error.message, 'Credential reference is not approved');
    return true;
  });
  assert.equal(runner.calls, 0);
});

test('allows only the ssh provider before invoking the runner', () => {
  const runner = new FakeRunner();
  const resolver = new PlatformCredentialStoreResolver({
    platform: 'linux',
    runner,
    approvedReferences: ['os://other/production-api'],
  });

  assert.throws(() => resolver.resolve('os://other/production-api'), error => {
    assert.ok(error instanceof CredentialStoreError);
    assert.equal(error.code, 'unsupported-provider');
    assert.equal(error.message, 'Credential store provider is unsupported');
    return true;
  });
  assert.equal(runner.calls, 0);
});

test('fails closed when no approved references are configured', () => {
  const runner = new FakeRunner();
  const resolver = new PlatformCredentialStoreResolver({ platform: 'linux', runner });

  assert.throws(() => resolver.resolve('os://ssh/production-api'), error => {
    assert.ok(error instanceof CredentialStoreError);
    assert.equal(error.code, 'unapproved-reference');
    return true;
  });
  assert.equal(runner.calls, 0);
});

test('rejects an overlong or malformed reference without echoing it', () => {
  const secretLikeReference = `os://ssh/${'x'.repeat(300)}password=approved-password`;
  assert.throws(() => validateCredentialReference(secretLikeReference), error => {
    assert.ok(error instanceof CredentialStoreError);
    assert.equal(error.message, 'Invalid credential reference');
    assert.doesNotMatch(error.message, /approved-password/);
    return true;
  });
});
