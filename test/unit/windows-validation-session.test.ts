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

function session(
  overrides: { readonly profile?: ConnectionProfile; readonly bytes?: Buffer; readonly delayMs?: number; readonly agentAvailable?: boolean } = {},
) {
  let captures = 0;
  let disposals = 0;
  let reads = 0;
  const requests: unknown[] = [];
  const agentRequests: unknown[] = [];
  const candidate = new WindowsValidationSession({
    storage: {
      getProfile: (profileId) => (profileId === profile.profileId ? (overrides.profile ?? profile) : undefined),
      readKnownHosts: () => {
        reads += 1;
        return overrides.bytes ?? knownHosts;
      },
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
    agentIdentity: { isAvailable: async () => overrides.agentAvailable ?? true },
    agentReadiness: {
      validate: async (...values) => {
        agentRequests.push(values);
      },
    },
    createPasswordTransport: () => ({
      connect: async (request) => {
        requests.push(request);
      },
    }),
  });
  return { candidate, reads: () => reads, captures: () => captures, disposals: () => disposals, requests, agentRequests };
}

test('composes verified known-hosts bytes, policy, and in-memory password readiness without caller connection fields', async () => {
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
  assert.equal(candidate.reads(), 1);
  assert.equal(candidate.captures(), 0);
  assert.equal(candidate.disposals(), 0);
});

test('rejects caller-controlled connection fields before profile lookup, snapshot capture, or password readiness', async () => {
  const candidate = session();
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId, host: 'attacker.example' }));
  assert.equal(candidate.reads(), 0);
  assert.equal(candidate.captures(), 0);
  assert.equal(candidate.disposals(), 0);
  assert.deepEqual(candidate.requests, []);
});

test('uses cancellable native readiness for an approved agent-key profile', async () => {
  const candidate = session({ profile: { ...profile, authMode: 'agent-key' } });
  await candidate.candidate.validate({ profileId: profile.profileId });
  assert.equal(candidate.captures(), 1);
  assert.equal(candidate.disposals(), 1);
  assert.deepEqual(candidate.requests, []);
  assert.equal(candidate.agentRequests.length, 1);
  const [capability, descriptor, timeout, signal] = candidate.agentRequests[0] as [object, unknown, number, unknown];
  assert.deepEqual(capability, {});
  assert.deepEqual(descriptor, { host: profile.host, port: profile.port, user: profile.user });
  assert.ok(timeout > 0 && timeout <= 10_000);
  assert.equal(signal, undefined);
});

test('retains the exact validated Windows snapshot for the execution lease', async () => {
  const capability = { opaque: true };
  let capturedCapability: object | undefined;
  let validatedCapability: object | undefined;
  let consumedCapability: object | undefined;
  let disposals = 0;
  const candidate = new WindowsValidationSession({
    storage: {
      getProfile: () => ({ ...profile, authMode: 'agent-key' }),
      readKnownHosts: () => knownHosts,
      withKnownHostsSnapshot: async (_reference, work) => work(knownHosts, capability),
      captureKnownHostsSnapshot: () => {
        capturedCapability = capability;
        return { bytes: knownHosts, capability };
      },
      disposeKnownHostsSnapshot: (value) => {
        assert.equal(value, capability);
        disposals += 1;
      },
    },
    agentIdentity: { isAvailable: async () => true },
    agentReadiness: {
      validate: async (value) => {
        validatedCapability = value;
      },
    },
    createPasswordTransport: () => ({ connect: async () => assert.fail('password must not start') }),
  });

  const lease = await candidate.authorize({ profileId: profile.profileId });
  await lease.withTransportContext!(async (value) => {
    consumedCapability = value;
  });
  await lease.release!();
  await lease.release!();

  assert.equal(capturedCapability, capability);
  assert.equal(validatedCapability, capability);
  assert.equal(consumedCapability, capability);
  assert.equal(disposals, 1);
});

test('does not start native readiness when the trusted ssh-add identity probe is unavailable', async () => {
  const candidate = session({ profile: { ...profile, authMode: 'agent-key' }, agentAvailable: false });
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId }));
  assert.deepEqual(candidate.agentRequests, []);
});

test('forwards cancellation to the native ssh-add identity gate before readiness starts', async () => {
  let received: AbortSignal | undefined;
  let release!: () => void;
  let entered!: () => void;
  const enteredGate = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const controller = new AbortController();
  const candidate = new WindowsValidationSession({
    storage: {
      getProfile: () => ({ ...profile, authMode: 'agent-key' }),
      readKnownHosts: () => knownHosts,
      withKnownHostsSnapshot: async (_reference, work) => work(knownHosts, {}),
    },
    agentIdentity: {
      isAvailable: async (_timeout, signal) => {
        received = signal;
        entered();
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return false;
      },
    },
    agentReadiness: { validate: async () => assert.fail('native readiness must not start') },
    createPasswordTransport: () => ({ connect: async () => assert.fail('password must not start') }),
  });
  const pending = candidate.validate({ profileId: profile.profileId }, controller.signal);
  await enteredGate;
  controller.abort();
  release();
  await assert.rejects(pending);
  assert.equal(received, controller.signal);
});

test('rejects unsafe verified known-hosts data before password readiness', async () => {
  const candidate = session({ bytes: Buffer.from('api.internal.example ssh-ed25519 not-base64!\n') });
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId }), WindowsValidationSessionError);
  assert.equal(candidate.reads(), 1);
  assert.equal(candidate.captures(), 0);
  assert.equal(candidate.disposals(), 0);
  assert.deepEqual(candidate.requests, []);
});

test('propagates cancellation before storage access', async () => {
  const candidate = session();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(candidate.candidate.validate({ profileId: profile.profileId }, controller.signal), WindowsValidationSessionError);
  assert.equal(candidate.reads(), 0);
  assert.equal(candidate.captures(), 0);
  assert.deepEqual(candidate.requests, []);
});

test('uses one remaining validation budget after snapshot capture', async () => {
  const observed: Array<{ timeoutMs: number; signal: AbortSignal | undefined }> = [];
  const timed = new WindowsValidationSession({
    storage: {
      getProfile: () => ({ ...profile, authMode: 'agent-key' }),
      readKnownHosts: () => knownHosts,
      withKnownHostsSnapshot: async (_reference, work) => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        return work(knownHosts, {});
      },
    },
    agentIdentity: { isAvailable: () => true },
    agentReadiness: {
      validate: async (_capability, _descriptor, timeoutMs, signal) => {
        observed.push({ timeoutMs, signal });
      },
    },
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
