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
  assert.throws(() => validateProfileSelection({ profileId: 'production-api', host: 'attacker.example' }), /unexpected field/);
});

test('rejects arbitrary fields and secret material', () => {
  assert.throws(() => validateConnectionProfile({ ...validProfile, command: 'uname -a' }), /unexpected field/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, password: 'not-allowed' }), /Secret material/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, privateKey: 'not-allowed' }), /Secret material/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, passphrase: 'not-allowed' }), /Secret material/);
});

test('requires strict authentication and host identity metadata', () => {
  assert.throws(() => validateConnectionProfile({ ...validProfile, authMode: 'private-key' }), /agent-key.*password/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, approvedKnownHostsReference: undefined }), /non-empty string/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, approvedKnownHostsPath: 'hosts' }), /unexpected field/);
});

test('rejects invalid profile identifiers and ports', () => {
  assert.throws(() => validateProfileSelection({}), /profileId/);
  for (const profileId of [' Production-api', 'production-api ', 'Production-api', 'production_api', '__proto__', 'constructor', 'prototype']) {
    assert.throws(() => validateProfileSelection({ profileId }), /canonical lowercase hyphenated/);
  }
  assert.throws(() => validateConnectionProfile({ ...validProfile, port: 0 }), /between 1 and 65535/);
  assert.throws(() => validateConnectionProfile({ ...validProfile, port: 22.5 }), /between 1 and 65535/);
});

test('requires plain records and rejects inherited fields', () => {
  const inheritedProfile = Object.create({ password: 'not-allowed' });
  Object.assign(inheritedProfile, validProfile);
  assert.throws(() => validateConnectionProfile(inheritedProfile), /must be an object/);

  const inheritedSelection = Object.create({ profileId: 'production-api' });
  assert.throws(() => validateProfileSelection(inheritedSelection), /contain only profileId/);
});

test('rejects control characters, including tabs and DEL', () => {
  for (const value of ['deploy\tuser', 'deploy\u007Fuser', 'deploy\u001Fuser']) {
    assert.throws(() => validateConnectionProfile({ ...validProfile, user: value }), /forbidden control characters/);
  }
});

test('does not echo untrusted field names in errors', () => {
  assert.throws(
    () => validateConnectionProfile({ ...validProfile, 'field attacker.example': true }),
    (error) => {
      assert.match((error as Error).message, /unexpected field/);
      assert.doesNotMatch((error as Error).message, /field attacker\.example/);
      return true;
    },
  );
});
