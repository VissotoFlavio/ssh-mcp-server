import { strict as assert } from 'node:assert';
import test from 'node:test';

import { validateConnectionProfile, validateProfileSelection } from '../../src/profiles/connection-profile.ts';
import { PlatformCredentialStoreResolver, validateCredentialReference, type CredentialStoreCommandRunner } from '../../src/credentials/credential-store.ts';
import { authorizeConnection, HostIdentityCredentialPolicyError } from '../../src/policy/host-identity-credential-policy.ts';
import {
  OpenSshAgentAdapter,
  PasswordSshAdapter,
  SshAdapterError,
  type InMemoryPasswordTransport,
  type SshProcessRunner,
  type TrustedConnectionDescriptor,
} from '../../src/adapters/ssh-connection-adapters.ts';
import { mapConnectionError, serializeAuditEvent, serializeDiagnosticError } from '../../src/diagnostics/redacted-diagnostics-audit.ts';

const fingerprint = 'SHA256:1111111111111111111111111111111111111111111';
const profile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: fingerprint,
  authMode: 'agent-key' as const,
  approvedKnownHostsReference: 'known-hosts://production-api',
  credentialReference: 'os://ssh/production-api',
};

function policyDependencies(overrides: Record<string, unknown> = {}) {
  return {
    profiles: { getProfile: async () => profile },
    knownHosts: { getEntries: async () => [{ host: profile.host, port: profile.port, fingerprint }] },
    agentIdentity: { isAvailable: async () => true },
    credentialResolver: { isApproved: async (reference: string) => reference === profile.credentialReference },
    ...overrides,
  };
}

function adapterDependencies(descriptor: TrustedConnectionDescriptor, runner: SshProcessRunner) {
  return {
    profiles: { getConnection: async () => descriptor },
    knownHosts: { resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint }) },
    trustedKnownHostsDirectory: '/srv/ssh',
    targetPlatform: 'linux',
    realpath: async (value: string) => value,
    runner,
    executable: { resolve: () => '/usr/bin/ssh' },
  };
}

function descriptorFromAuthorized(authorizedProfile: {
  profileId: string;
  host: string;
  port: number;
  user: string;
  authMode: 'agent-key' | 'password';
  approvedKnownHostsReference: string;
  expectedHostFingerprint: string;
  credentialReference?: string;
}): TrustedConnectionDescriptor {
  return {
    profileId: authorizedProfile.profileId,
    host: authorizedProfile.host,
    port: authorizedProfile.port,
    user: authorizedProfile.user,
    authMode: authorizedProfile.authMode,
    knownHostsReference: authorizedProfile.approvedKnownHostsReference,
    expectedHostFingerprint: authorizedProfile.expectedHostFingerprint,
    ...(authorizedProfile.credentialReference === undefined
      ? {}
      : { credentialReference: authorizedProfile.credentialReference }),
  };
}

test('agent-key flow accepts only a profile id and validates host identity before OpenSSH', async () => {
  const selection = validateProfileSelection({ profileId: profile.profileId });
  assert.deepEqual(validateConnectionProfile(profile), profile);
  const authorized = await authorizeConnection(selection, policyDependencies());
  assert.equal(authorized.authentication.mode, 'agent-key');

  let calls = 0;
  const runner: SshProcessRunner = {
    run: async (_executable, args) => {
      calls += 1;
      assert.equal(args.includes('uname -a'), false);
      assert.equal(args.includes('-N'), true);
      assert.equal(args.includes('StrictHostKeyChecking=yes'), true);
      return { exitCode: 0, ready: true };
    },
  };
  await new OpenSshAgentAdapter(adapterDependencies(descriptorFromAuthorized(authorized.profile), runner)).connect(selection);
  assert.equal(calls, 1);
  await assert.rejects(authorizeConnection({ profileId: profile.profileId, host: 'attacker.example' }, policyDependencies()), error =>
    error instanceof HostIdentityCredentialPolicyError && error.code === 'invalid-selection',
  );
});

test('password flow resolves an approved OS reference and keeps the password in transport memory', async () => {
  const passwordProfile = { ...profile, authMode: 'password' as const };
  let credentialStoreCalls = 0;
  const commandRunner: CredentialStoreCommandRunner = {
    run: async () => {
      credentialStoreCalls += 1;
      return { stdout: 'super-secret\n' };
    },
  };
  const credentialResolver = new PlatformCredentialStoreResolver({
    platform: 'linux',
    runner: commandRunner,
    approvedReferences: [profile.credentialReference],
  });
  const ref = validateCredentialReference(profile.credentialReference);
  const credentialStore = credentialResolver.resolve(ref);
  assert.equal(credentialStore !== undefined, true);
  const authorized = await authorizeConnection({ profileId: profile.profileId }, policyDependencies({
    profiles: { getProfile: async () => passwordProfile },
    credentialResolver: { isApproved: async (reference: string) => reference === profile.credentialReference },
  }));
  assert.deepEqual(authorized.authentication, { mode: 'password', credentialReference: profile.credentialReference });

  let transportedPassword = '';
  const transport: InMemoryPasswordTransport = {
    connect: async request => {
      transportedPassword = request.password;
      assert.equal(request.expectedHostFingerprint, fingerprint);
      assert.equal(request.strictHostKeyChecking, 'yes');
    },
  };
  await new PasswordSshAdapter({
    ...adapterDependencies(descriptorFromAuthorized(authorized.profile), { run: async () => ({ exitCode: 0, ready: true }) }),
    credentials: {
      getPassword: async reference => credentialStore.getPassword(validateCredentialReference(reference)),
    },
    transport,
  }).connect({ profileId: profile.profileId });
  assert.equal(transportedPassword, 'super-secret');
  assert.equal(credentialStoreCalls, 1);
  assert.throws(() => credentialResolver.resolve('os://ssh/staging-api'), /not approved/iu);
  assert.equal(credentialStoreCalls, 1);
  assert.doesNotMatch(serializeDiagnosticError(new Error('super-secret /srv/private/key')), /super-secret|private-key/iu);
  assert.doesNotMatch(serializeAuditEvent({ profileId: profile.profileId, authMode: 'password', outcome: 'success', code: 'success' }), /super-secret|known_hosts/iu);
});

test('host-key mismatch fails closed before authentication or transport', async () => {
  let authenticated = false;
  await assert.rejects(
    authorizeConnection({ profileId: profile.profileId }, policyDependencies({
      knownHosts: { getEntries: async () => [{ host: profile.host, port: profile.port, fingerprint: 'SHA256:2222222222222222222222222222222222222222222' }] },
      agentIdentity: { isAvailable: async () => { authenticated = true; return true; } },
    })),
    error => error instanceof HostIdentityCredentialPolicyError && error.code === 'known-hosts-entry-mismatch',
  );
  assert.equal(authenticated, false);

  const approvedPassword = await authorizeConnection({ profileId: profile.profileId }, policyDependencies({
    profiles: { getProfile: async () => ({ ...profile, authMode: 'password' as const }) },
  }));
  let credentialCalls = 0;
  let transportCalls = 0;
  const passwordDescriptor = descriptorFromAuthorized(approvedPassword.profile);
  await assert.rejects(
    new PasswordSshAdapter({
      profiles: { getConnection: async () => passwordDescriptor },
      knownHosts: { resolve: async () => ({ path: '/srv/ssh/approved/known_hosts', fingerprint: 'SHA256:2222222222222222222222222222222222222222222' }) },
      trustedKnownHostsDirectory: '/srv/ssh',
      targetPlatform: 'linux',
      realpath: async (value: string) => value,
      credentials: { getPassword: async () => { credentialCalls += 1; return { password: 'super-secret' }; } },
      transport: { connect: async () => { transportCalls += 1; } },
    }).connect({ profileId: profile.profileId }),
    error => error instanceof SshAdapterError && error.code === 'known-hosts-fingerprint-mismatch',
  );
  assert.equal(credentialCalls, 0);
  assert.equal(transportCalls, 0);
});

test('arbitrary profile inputs and adapter errors remain redacted', async () => {
  assert.throws(() => validateProfileSelection({ profileId: profile.profileId, command: 'rm -rf /' }), /unexpected field/iu);
  const diagnostic = mapConnectionError(new SshAdapterError('ssh-timeout', 'password=super-secret /srv/private/key'));
  assert.equal(diagnostic.code, 'timeout');
  assert.doesNotMatch(serializeDiagnosticError(diagnostic), /super-secret|private-key|ssh-timeout/iu);
});
