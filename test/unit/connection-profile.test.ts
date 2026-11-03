import { strict as assert } from 'node:assert';
import test from 'node:test';

import { validateConnectionProfile, validateProfileSelection } from '../../src/profiles/connection-profile.js';

const validProfile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:approved-fingerprint',
  authMode: 'agent-key',
  credentialReference: 'os://ssh/production-api',
  approvedKnownHostsReference: 'known-hosts://production-api',
};

test('validates an approved non-secret connection profile', () => {
  assert.deepEqual(validateConnectionProfile(validProfile), validProfile);
});

test('accepts only profileId as a connection capability input', () => {
  assert.deepEqual(validateProfileSelection({ profileId: 'production-api' }), {
    profileId: 'production-api',
  });
  assert.throws(() => validateProfileSelection({ profileId: 'production-api', host: 'attacker.example' }), /Unexpected/);
});

test('rejects arbitrary fields and secret material', () => {
  assert.throws(() => validateConnectionProfile({ ...validProfile, command: 'uname -a' }), /Unexpected/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, password: 'not-allowed' }), /secret material/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, privateKey: 'not-allowed' }), /secret material/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, passphrase: 'not-allowed' }), /secret material/);
});

test('requires strict authentication and host identity metadata', () => {
  assert.throws(() => validateConnectionProfile({ ...validProfile, authMode: 'private-key' }), /agent-key.*password/);
  assert.throws(
    () => validateConnectionProfile({ ...validProfile, approvedKnownHostsReference: undefined }),
    /known-hosts reference or path/,
  );
  assert.throws(
    () => validateConnectionProfile({ ...validProfile, approvedKnownHostsPath: 'hosts' }),
    /Exactly one/,
  );
});

test('rejects invalid profile identifiers and ports', () => {
  assert.throws(() => validateProfileSelection({}), /profileId/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, port: 0 }), /between 1 and 65535/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, port: 22.5 }), /between 1 and 65535/);
});
