import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  authorizeConnection,
  HostIdentityCredentialPolicy,
  HostIdentityCredentialPolicyError,
  validatePolicyProfile,
} from '../../src/policy/host-identity-credential-policy.ts';

const baseProfile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:approved',
  approvedKnownHostsReference: 'known-hosts://production-api',
  authMode: 'agent-key' as const,
};

const matchingEntry = {
  host: baseProfile.host,
  port: baseProfile.port,
  fingerprint: baseProfile.expectedHostFingerprint,
};

function dependencies(overrides: Record<string, unknown> = {}) {
  return {
    knownHosts: { getEntries: async () => [matchingEntry] },
    agentIdentity: { isAvailable: async () => true },
    credentialResolver: { isApproved: async () => true },
    ...overrides,
  };
}

function assertPolicyError(action: () => unknown, code: HostIdentityCredentialPolicyError['code'], message: string): void {
  assert.throws(action, error => {
    assert.ok(error instanceof HostIdentityCredentialPolicyError);
    assert.equal(error.code, code);
    assert.equal(error.message, message);
    return true;
  });
}

test('authorizes an exact known-host entry and an available agent identity', async () => {
  const plan = await authorizeConnection(baseProfile, dependencies());
  assert.deepEqual(plan, {
    profile: baseProfile,
    knownHostsReference: 'known-hosts://production-api',
    hostIdentity: matchingEntry,
    authentication: { mode: 'agent-key' },
  });
});

test('requires an approved known-hosts reference and rejects arbitrary paths or wildcards', () => {
  for (const reference of ['', '/etc/ssh/known_hosts', 'known-hosts://../production-api', 'known-hosts://*']) {
    assertPolicyError(
      () => validatePolicyProfile({ ...baseProfile, approvedKnownHostsReference: reference }),
      reference === '' ? 'invalid-profile' : 'invalid-known-hosts-reference',
      reference === '' ? 'Connection profile field approvedKnownHostsReference is required' : 'Approved known-hosts reference is invalid',
    );
  }
  assertPolicyError(
    () => validatePolicyProfile({ ...baseProfile, host: 'api-*.internal.example' }),
    'invalid-profile',
    'Connection profile host cannot contain wildcard characters',
  );
});

test('fails closed on missing, mismatched, and ambiguous entries', async () => {
  await assert.rejects(
    authorizeConnection(baseProfile, dependencies({ knownHosts: { getEntries: async () => [] } })),
    error => error instanceof HostIdentityCredentialPolicyError && error.code === 'known-hosts-entry-missing',
  );
  await assert.rejects(
    authorizeConnection(baseProfile, dependencies({ knownHosts: { getEntries: async () => [{ ...matchingEntry, fingerprint: 'SHA256:other' }] } })),
    error => error instanceof HostIdentityCredentialPolicyError && error.code === 'known-hosts-entry-mismatch',
  );
  await assert.rejects(
    authorizeConnection(baseProfile, dependencies({ knownHosts: { getEntries: async () => [matchingEntry, matchingEntry] } })),
    error => error instanceof HostIdentityCredentialPolicyError && error.code === 'known-hosts-entry-ambiguous',
  );
});

test('requires an agent identity and does not expose identity material', async () => {
  await assert.rejects(
    authorizeConnection(baseProfile, dependencies({ agentIdentity: { isAvailable: async () => false } })),
    error => error instanceof HostIdentityCredentialPolicyError && error.code === 'agent-identity-unavailable',
  );
  const plan = await new HostIdentityCredentialPolicy(dependencies()).authorize(baseProfile);
  assert.equal('privateKey' in plan, false);
  assert.equal('password' in plan, false);
});

test('password mode requires and approves only an opaque credential reference', async () => {
  const profile = { ...baseProfile, authMode: 'password' as const, credentialReference: 'os://ssh/production-api' };
  const plan = await authorizeConnection(profile, dependencies());
  assert.deepEqual(plan.authentication, { mode: 'password', credentialReference: 'os://ssh/production-api' });

  await assert.rejects(
    authorizeConnection(profile, dependencies({ credentialResolver: { isApproved: async () => false } })),
    error => error instanceof HostIdentityCredentialPolicyError && error.code === 'credential-reference-unapproved',
  );
  assertPolicyError(
    () => validatePolicyProfile({ ...baseProfile, authMode: 'password' }),
    'credential-reference-missing',
    'Password authentication requires a credential reference',
  );
  for (const field of ['password', 'passphrase', 'privateKey', 'privateKeyContent']) {
    assertPolicyError(
      () => validatePolicyProfile({ ...profile, [field]: 'secret-material' }),
      'invalid-profile',
      'Secret material fields are not accepted',
    );
  }
  assertPolicyError(
    () => validatePolicyProfile({ ...profile, credentialReference: '/tmp/password' }),
    'invalid-profile',
    'Credential reference is invalid',
  );
});

test('rejects unknown and inherited profile fields without echoing attacker data', () => {
  assertPolicyError(
    () => validatePolicyProfile({ ...baseProfile, 'field attacker.example': true }),
    'invalid-profile',
    'Connection profile contains an unexpected field',
  );

  const inherited = Object.create({ password: 'secret' });
  Object.assign(inherited, baseProfile);
  assertPolicyError(() => validatePolicyProfile(inherited), 'invalid-profile', 'Connection profile must be an object');
});

test('provider failures and malformed entries become deterministic redacted errors', async () => {
  await assert.rejects(
    authorizeConnection(baseProfile, dependencies({ knownHosts: { getEntries: async () => { throw new Error('private path'); } } })),
    error => error instanceof HostIdentityCredentialPolicyError && error.message === 'Approved known-hosts data is unavailable',
  );
  await assert.rejects(
    authorizeConnection(baseProfile, dependencies({ knownHosts: { getEntries: async () => [{ host: '*', port: 22, fingerprint: 'x' }] } })),
    error => error instanceof HostIdentityCredentialPolicyError && error.message === 'Approved known-hosts data is unavailable',
  );
  await assert.rejects(
    authorizeConnection(
      { ...baseProfile, authMode: 'password' as const, credentialReference: 'os://ssh/production-api' },
      dependencies({ credentialResolver: { isApproved: async () => { throw new Error('credential secret'); } } }),
    ),
    error => error instanceof HostIdentityCredentialPolicyError && error.message === 'Credential reference approval is unavailable',
  );
});
