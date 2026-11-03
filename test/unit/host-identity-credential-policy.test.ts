import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  authorizeConnection,
  HostIdentityCredentialPolicy,
  HostIdentityCredentialPolicyError,
  validateProfileSelection,
  validatePolicyProfile,
} from '../../src/policy/host-identity-credential-policy.ts';

const baseProfile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
  approvedKnownHostsReference: 'known-hosts://production-api',
  authMode: 'agent-key' as const,
};

const matchingEntry = {
  host: baseProfile.host,
  port: baseProfile.port,
  fingerprint: baseProfile.expectedHostFingerprint,
};
const selection = { profileId: baseProfile.profileId };

function dependencies(overrides: Record<string, unknown> = {}) {
  return {
    knownHosts: { getEntries: async () => [matchingEntry] },
    agentIdentity: { isAvailable: async () => true },
    credentialResolver: { isApproved: async () => true },
    profiles: { getProfile: async () => baseProfile },
    ...overrides,
  };
}

function assertPolicyError(action: () => unknown, code: HostIdentityCredentialPolicyError['code'], message: string): void {
  assert.throws(action, (error) => {
    assert.ok(error instanceof HostIdentityCredentialPolicyError);
    assert.equal(error.code, code);
    assert.equal(error.message, message);
    return true;
  });
}

test('authorizes an exact known-host entry and an available agent identity', async () => {
  const plan = await authorizeConnection(selection, dependencies());
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
    authorizeConnection(selection, dependencies({ knownHosts: { getEntries: async () => [] } })),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.code === 'known-hosts-entry-missing',
  );
  await assert.rejects(
    authorizeConnection(
      selection,
      dependencies({
        knownHosts: { getEntries: async () => [{ ...matchingEntry, fingerprint: 'SHA256:2222222222222222222222222222222222222222222' }] },
      }),
    ),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.code === 'known-hosts-entry-mismatch',
  );
  await assert.rejects(
    authorizeConnection(selection, dependencies({ knownHosts: { getEntries: async () => [matchingEntry, matchingEntry] } })),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.code === 'known-hosts-entry-ambiguous',
  );
});

test('requires an agent identity and does not expose identity material', async () => {
  await assert.rejects(
    authorizeConnection(selection, dependencies({ agentIdentity: { isAvailable: async () => false } })),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.code === 'agent-identity-unavailable',
  );
  const plan = await new HostIdentityCredentialPolicy(dependencies()).authorize(selection);
  assert.equal('privateKey' in plan, false);
  assert.equal('password' in plan, false);
});

test('password mode requires and approves only an opaque credential reference', async () => {
  const profile = { ...baseProfile, authMode: 'password' as const, credentialReference: 'os://ssh/production-api' };
  const plan = await authorizeConnection(selection, dependencies({ profiles: { getProfile: async () => profile } }));
  assert.deepEqual(plan.authentication, { mode: 'password', credentialReference: 'os://ssh/production-api' });

  await assert.rejects(
    authorizeConnection(
      selection,
      dependencies({ profiles: { getProfile: async () => profile }, credentialResolver: { isApproved: async () => false } }),
    ),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.code === 'credential-reference-unapproved',
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

test('public authorization resolves only a profile id from the trusted registry', async () => {
  let resolvedProfileId = '';
  let resolverCalls = 0;
  const trustedDependencies = dependencies({
    profiles: {
      getProfile: async (profileId: string) => {
        resolvedProfileId = profileId;
        return baseProfile;
      },
    },
    knownHosts: {
      getEntries: async () => {
        resolverCalls += 1;
        return [matchingEntry];
      },
    },
  });

  await assert.rejects(
    authorizeConnection({ ...selection, host: 'attacker.example', port: 2222 }, trustedDependencies),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.code === 'invalid-selection',
  );
  assert.equal(resolvedProfileId, '');
  assert.equal(resolverCalls, 0);

  const mutableSelection: { profileId: string } = { ...selection };
  const authorization = authorizeConnection(mutableSelection, trustedDependencies);
  mutableSelection.profileId = 'attacker-profile';
  const plan = await authorization;
  assert.equal(resolvedProfileId, 'production-api');
  assert.equal(plan.profile.host, baseProfile.host);
  assert.equal(plan.profile.port, baseProfile.port);
  assert.deepEqual(validateProfileSelection(selection), selection);

  await assert.rejects(
    authorizeConnection(selection, dependencies({ profiles: { getProfile: async () => ({ ...baseProfile, profileId: 'other-profile' }) } })),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.code === 'trusted-profile-not-found',
  );
});

test('rejects malformed or pattern fingerprints at both trusted and known-host boundaries', async () => {
  for (const fingerprint of [
    'SHA256:*',
    'SHA256:with space',
    'ssh-rsa AAAA',
    'SHA256:',
    `SHA256:${'ab-_'.repeat(10)}abc`,
    `SHA256:${'a'.repeat(42)}=`,
  ]) {
    assertPolicyError(
      () => validatePolicyProfile({ ...baseProfile, expectedHostFingerprint: fingerprint }),
      'invalid-profile',
      'Connection profile field expectedHostFingerprint is invalid',
    );
  }
  await assert.rejects(
    authorizeConnection(selection, dependencies({ knownHosts: { getEntries: async () => [{ ...matchingEntry, fingerprint: 'SHA256:*' }] } })),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.message === 'Approved known-hosts data is unavailable',
  );
});

test('accepts a valid unpadded standard-Base64 SSH fingerprint', () => {
  const fingerprint = `SHA256:${'ab+/'.repeat(10)}abc`;
  assert.equal(validatePolicyProfile({ ...baseProfile, expectedHostFingerprint: fingerprint }).expectedHostFingerprint, fingerprint);
});

test('rejects secret-like credential locators and PEM material without echoing them', () => {
  const profile = { ...baseProfile, authMode: 'password' as const };
  for (const credentialReference of [
    'os://ssh/password:secret',
    'os://ssh/passphrase=secret',
    'os://ssh/private-key:secret',
    'os://ssh/secret=value',
    'os://ssh/token:secret',
    '-----BEGIN OPENSSH PRIVATE KEY-----',
  ]) {
    assertPolicyError(() => validatePolicyProfile({ ...profile, credentialReference }), 'invalid-profile', 'Credential reference is invalid');
  }
});

test('provider failures and malformed entries become deterministic redacted errors', async () => {
  await assert.rejects(
    authorizeConnection(
      selection,
      dependencies({
        knownHosts: {
          getEntries: async () => {
            throw new Error('private path');
          },
        },
      }),
    ),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.message === 'Approved known-hosts data is unavailable',
  );
  await assert.rejects(
    authorizeConnection(
      selection,
      dependencies({
        knownHosts: { getEntries: async () => [{ host: '*', port: 22, fingerprint: 'SHA256:3333333333333333333333333333333333333333333' }] },
      }),
    ),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.message === 'Approved known-hosts data is unavailable',
  );
  await assert.rejects(
    authorizeConnection(
      selection,
      dependencies({
        profiles: { getProfile: async () => ({ ...baseProfile, authMode: 'password' as const, credentialReference: 'os://ssh/production-api' }) },
        credentialResolver: {
          isApproved: async () => {
            throw new Error('credential secret');
          },
        },
      }),
    ),
    (error) => error instanceof HostIdentityCredentialPolicyError && error.message === 'Credential reference approval is unavailable',
  );
});
