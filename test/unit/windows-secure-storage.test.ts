import { strict as assert } from 'node:assert';
import test from 'node:test';

import { WindowsSecureStorage, WindowsSecureStorageError, type WindowsTrustBinding } from '../../src/windows/windows-secure-storage.js';

const profile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  authMode: 'agent-key',
  approvedKnownHostsReference: 'known-hosts://production-api',
};

function binding(state: unknown = { profiles: [profile] }): WindowsTrustBinding {
  return {
    readProfileState: () => Buffer.from(JSON.stringify(state)),
    readKnownHosts: (profileId) => {
      assert.equal(profileId, 'production-api');
      return Buffer.from('[api.internal.example]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n');
    },
  };
}

test('reads profiles only through an injected trusted native boundary', () => {
  const storage = new WindowsSecureStorage(binding());
  assert.deepEqual(storage.listProfiles(), [profile]);
  assert.deepEqual(storage.getProfile('production-api'), profile);
  assert.equal(storage.getProfile('unknown-profile'), undefined);
});

test('does not turn a known-hosts reference into an arbitrary filename', () => {
  const storage = new WindowsSecureStorage(binding());
  assert.throws(() => storage.readKnownHosts('C:\\private\\known_hosts'), WindowsSecureStorageError);
  assert.throws(() => storage.readKnownHosts('known-hosts://../private'), WindowsSecureStorageError);
  assert.match(storage.readKnownHosts('known-hosts://production-api').toString('utf8'), /ssh-ed25519/u);
});

test('fails closed for malformed state or native failures', () => {
  assert.throws(
    () => new WindowsSecureStorage(binding({ profiles: [{ ...profile, password: 'secret' }] })).listProfiles(),
    WindowsSecureStorageError,
  );
  assert.throws(
    () =>
      new WindowsSecureStorage({
        readProfileState: () => {
          throw new Error('native path failure');
        },
        readKnownHosts: () => Buffer.from('unused'),
      }).listProfiles(),
    WindowsSecureStorageError,
  );
});
