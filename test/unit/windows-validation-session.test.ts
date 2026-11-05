import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import test from 'node:test';

import type { ConnectionProfile } from '../../src/profiles/connection-profile.js';
import type { WindowsPasswordValidationRequest } from '../../src/windows/windows-password-transport.js';
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

function session(overrides: { readonly profile?: ConnectionProfile; readonly bytes?: Buffer; readonly delayMs?: number } = {}) {
  let captures = 0;
  let disposals = 0;
  const requests: unknown[] = [];
  const candidate = new WindowsValidationSession({
    storage: {
      getProfile: (profileId) => (profileId === profile.profileId ? (overrides.profile ?? profile) : undefined),
      withKnownHostsSnapshot: async (_reference, work) => {
        captures += 1;
        try {
          if (overrides.delayMs !== undefined) await new Promise((resolve) => setTimeout(resolve, overrides.delayMs));
          return await work(overrides.bytes ?? knownHosts, {});
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
  assert.equal(candidate.requests.length, 1);
  const request = candidate.requests[0] as { timeoutMs: number } & Omit<WindowsPasswordValidationRequest, 'timeoutMs'>;
  assert.deepEqual(
    { ...request, timeoutMs: undefined },
    {
      host: profile.host,
      port: profile.port,
      user: profile.user,
      expectedHostFingerprint: fingerprint,
      credentialReference: profile.credentialReference,
      timeoutMs: undefined,
    },
  );
  assert.ok(request.timeoutMs > 0 && request.timeoutMs <= 10_000);
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

test('fails closed for agent-key profiles because native readiness is not cancellable', async () => {
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

test('propagates cancellation before storage access', async () => {
  const candidate = session();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId }, controller.signal), WindowsValidationSessionError);
  assert.equal(candidate.captures(), 0);
  assert.deepEqual(candidate.requests, []);
});

test('uses one remaining validation budget after snapshot capture', async () => {
  const observed: Array<{ timeoutMs: number; signal: AbortSignal | undefined }> = [];
  const timed = new WindowsValidationSession({
    storage: {
      getProfile: () => profile,
      withKnownHostsSnapshot: async (_reference, work) => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        return work(knownHosts, {});
      },
    },
    agentIdentity: { isAvailable: () => false },
    createPasswordTransport: () => ({
      connect: async (request, signal) => {
        observed.push({ timeoutMs: request.timeoutMs, signal });
      },
    }),
    timeoutMs: 50,
  });
  const controller = new AbortController();
  await timed.validate({ profileId: profile.profileId }, controller.signal);
  assert.equal(observed.length, 1);
  assert.ok(observed[0]!.timeoutMs > 0 && observed[0]!.timeoutMs < 50);
  assert.equal(observed[0]!.signal, controller.signal);
});
