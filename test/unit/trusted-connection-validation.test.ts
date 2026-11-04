import { strict as assert } from 'node:assert';
import test from 'node:test';

import { HostIdentityCredentialPolicyError, type AuthorizedConnection } from '../../src/policy/host-identity-credential-policy.js';
import { createTrustedConnectionValidationProvider, toConnectionValidationFailure } from '../../src/validation/trusted-connection-validation.js';

const profile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  authMode: 'agent-key' as const,
  knownHostsReference: 'known-hosts://production-api',
  expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
};

function authorized(): AuthorizedConnection {
  return {
    profile: {
      profileId: profile.profileId,
      host: profile.host,
      port: profile.port,
      user: profile.user,
      authMode: profile.authMode,
      expectedHostFingerprint: profile.expectedHostFingerprint,
      approvedKnownHostsReference: profile.knownHostsReference,
    },
    knownHostsReference: profile.knownHostsReference,
    hostIdentity: { host: profile.host, port: profile.port, fingerprint: profile.expectedHostFingerprint },
    authentication: { mode: 'agent-key' },
  };
}

test('authorizes a selection before invoking readiness with one immutable bound plan', async () => {
  let policyCalls = 0;
  let readinessCalls = 0;
  let received: AuthorizedConnection | undefined;
  const provider = createTrustedConnectionValidationProvider({
    policy: {
      async authorize(input) {
        policyCalls += 1;
        assert.deepEqual(input, { profileId: profile.profileId });
        return authorized();
      },
    },
    readinessAdapter: {
      async connect(authorizedConnection) {
        readinessCalls += 1;
        received = authorizedConnection;
      },
    },
  });

  assert.deepEqual(await provider.validateConnection({ profileId: profile.profileId }), { profileId: profile.profileId, ready: true });
  assert.equal(policyCalls, 1);
  assert.equal(readinessCalls, 1);
  assert.equal(Object.isFrozen(received), true);
  assert.equal(Object.isFrozen(received?.profile), true);
  assert.deepEqual(received, authorized());
});

test('does not invoke readiness when policy rejects host identity or credentials', async () => {
  let readinessCalls = 0;
  const hostFailure = createTrustedConnectionValidationProvider({
    policy: {
      async authorize() {
        throw new HostIdentityCredentialPolicyError('known-hosts-entry-mismatch', 'fingerprint=private');
      },
    },
    readinessAdapter: {
      async connect() {
        readinessCalls += 1;
      },
    },
  });
  await assert.rejects(hostFailure.validateConnection({ profileId: profile.profileId }));
  assert.deepEqual(toConnectionValidationFailure(new HostIdentityCredentialPolicyError('known-hosts-entry-mismatch', 'fingerprint=private')), {
    ready: false,
    outcome: 'failure',
    code: 'host-key-failure',
  });

  const credentialFailure = createTrustedConnectionValidationProvider({
    policy: {
      async authorize() {
        throw new HostIdentityCredentialPolicyError('credential-reference-unapproved', 'credential=private');
      },
    },
    readinessAdapter: {
      async connect() {
        readinessCalls += 1;
      },
    },
  });
  await assert.rejects(credentialFailure.validateConnection({ profileId: profile.profileId }));
  assert.deepEqual(toConnectionValidationFailure(new HostIdentityCredentialPolicyError('credential-reference-unapproved', 'credential=private')), {
    ready: false,
    outcome: 'failure',
    code: 'authentication-failure',
  });
  assert.equal(readinessCalls, 0);
});

test('rejects a policy-to-readiness target divergence before any runner or transport can run', async () => {
  let readinessCalls = 0;
  const provider = createTrustedConnectionValidationProvider({
    policy: {
      async authorize() {
        return { ...authorized(), hostIdentity: { host: 'adapter-b.internal.example', port: 22, fingerprint: profile.expectedHostFingerprint } };
      },
    },
    readinessAdapter: {
      async connect() {
        readinessCalls += 1;
      },
    },
  });

  await assert.rejects(provider.validateConnection({ profileId: profile.profileId }));
  assert.equal(readinessCalls, 0);
});

test('rejects unexpected input before policy', async () => {
  let policyCalls = 0;
  const provider = createTrustedConnectionValidationProvider({
    policy: {
      async authorize() {
        policyCalls += 1;
        return authorized();
      },
    },
    readinessAdapter: { async connect() {} },
  });
  await assert.rejects(provider.validateConnection({ profileId: profile.profileId, command: 'id' }));
  assert.equal(policyCalls, 0);
});
