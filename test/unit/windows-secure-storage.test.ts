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
  const capability = {};
  return {
    readProfileState: () => Buffer.from(JSON.stringify(state)),
    readKnownHosts: (profileId) => {
      assert.equal(profileId, 'production-api');
      return Buffer.from('[api.internal.example]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n');
    },
    captureKnownHostsSnapshot: (profileId) => {
      assert.equal(profileId, 'production-api');
      return { bytes: Buffer.from('[api.internal.example]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n'), capability };
    },
    disposeKnownHostsSnapshot: (value) => assert.equal(value, capability),
    isKnownHostsSnapshotBusy: () => false,
    readCredential: () => 'unused',
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

test('probes only an approved credential locator without reading password material', () => {
  let passwordReads = 0;
  let probeLocator: string | undefined;
  const storage = new WindowsSecureStorage({
    ...binding(),
    readCredential: () => ((passwordReads += 1), 'secret'),
    credentialAvailable: (locator) => {
      probeLocator = locator;
      return false;
    },
  });

  assert.equal(storage.credentialAvailable('os://ssh/production-api'), false);
  assert.equal(probeLocator, 'production-api');
  assert.equal(passwordReads, 0);
  assert.throws(() => storage.credentialAvailable('os://ssh/../private'), WindowsSecureStorageError);
  assert.equal(passwordReads, 0);
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
        captureKnownHostsSnapshot: () => ({ bytes: Buffer.from('unused'), capability: {} }),
        disposeKnownHostsSnapshot: () => undefined,
        isKnownHostsSnapshotBusy: () => false,
        readCredential: () => 'unused',
      }).listProfiles(),
    WindowsSecureStorageError,
  );
});

test('always disposes the opaque native snapshot after work succeeds or fails', async () => {
  const capability = {};
  let disposals = 0;
  const storage = new WindowsSecureStorage({
    ...binding(),
    captureKnownHostsSnapshot: () => ({ bytes: Buffer.from('approved'), capability }),
    disposeKnownHostsSnapshot: (value) => {
      assert.equal(value, capability);
      disposals += 1;
    },
  });
  await assert.rejects(storage.withKnownHostsSnapshot('known-hosts://production-api', async () => Promise.reject(new Error('transport failed'))));
  assert.equal(disposals, 1);
  await storage.withKnownHostsSnapshot('known-hosts://production-api', async (bytes) => assert.equal(bytes.toString('utf8'), 'approved'));
  assert.equal(disposals, 2);
});
