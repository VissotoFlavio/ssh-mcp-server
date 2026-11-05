import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import test from 'node:test';

import type { ConnectionProfile } from '../../src/profiles/connection-profile.js';
import { WindowsValidationSession, WindowsValidationSessionError } from '../../src/windows/windows-validation-session.js';

const key = Buffer.from('approved-host-key');
const fingerprint = `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`;
const profile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: fingerprint,
  authMode: 'password' as const,
  credentialReference: 'os://ssh/production-api',
  approvedKnownHostsReference: 'known-hosts://production-api',
};
const knownHosts = Buffer.from(`api.internal.example ssh-ed25519 ${key.toString('base64')}\n`);

function session(overrides: { readonly profile?: ConnectionProfile; readonly bytes?: Buffer } = {}) {
  let captures = 0;
  let disposals = 0;
  const requests: unknown[] = [];
  const candidate = new WindowsValidationSession({
    storage: {
      getProfile: (profileId) => (profileId === profile.profileId ? (overrides.profile ?? profile) : undefined),
      withKnownHostsSnapshot: async (_reference, work) => {
        captures += 1;
        try {
          return await work(overrides.bytes ?? knownHosts);
        } finally {
          disposals += 1;
        }
      },
    },
    agentIdentity: { isAvailable: async () => true },
    createPasswordTransport: () => ({
      connect: async (request) => {
        requests.push(request);
      },
    }),
  });
  return { candidate, captures: () => captures, disposals: () => disposals, requests };
}

test('composes captured known-hosts bytes, policy, and in-memory password readiness without caller connection fields', async () => {
  const candidate = session();
  await candidate.candidate.validate({ profileId: profile.profileId });
  assert.deepEqual(candidate.requests, [
    {
      host: profile.host,
      port: profile.port,
      user: profile.user,
      expectedHostFingerprint: fingerprint,
      credentialReference: profile.credentialReference,
      timeoutMs: 10_000,
    },
  ]);
  assert.equal(candidate.captures(), 1);
  assert.equal(candidate.disposals(), 1);
});

test('rejects caller-controlled connection fields before profile lookup, snapshot capture, or password readiness', async () => {
  const candidate = session();
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId, host: 'attacker.example' }));
  assert.equal(candidate.captures(), 0);
  assert.equal(candidate.disposals(), 0);
  assert.deepEqual(candidate.requests, []);
});

test('fails closed for agent-key profiles until native remote readiness consumes the opaque snapshot', async () => {
  const candidate = session({ profile: { ...profile, authMode: 'agent-key' } });
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId }), WindowsValidationSessionError);
  assert.equal(candidate.captures(), 1);
  assert.equal(candidate.disposals(), 1);
  assert.deepEqual(candidate.requests, []);
});

test('disposes the captured snapshot when known-hosts parsing rejects unsafe data', async () => {
  const candidate = session({ bytes: Buffer.from('api.internal.example ssh-ed25519 not-base64!\n') });
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId }), WindowsValidationSessionError);
  assert.equal(candidate.captures(), 1);
  assert.equal(candidate.disposals(), 1);
  assert.deepEqual(candidate.requests, []);
});
