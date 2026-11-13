import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { createWindowsReadinessStatusProvider, type WindowsLocalReadinessProbe } from '../../src/windows/windows-readiness-status.js';

const encodedKey = 'AAAAC3NzaC1lZDI1NTE5AAAAItest';
const fingerprint = `SHA256:${createHash('sha256').update(Buffer.from(encodedKey, 'base64')).digest('base64').replace(/=+$/u, '')}`;
const knownHosts = Buffer.from(`[private.example]:22 ssh-ed25519 ${encodedKey}\n`);
const profile = {
  profileId: 'production-api',
  host: 'private.example',
  port: 22,
  user: 'deploy',
  authMode: 'password' as const,
  credentialReference: 'os://ssh/private-credential',
  approvedKnownHostsReference: 'known-hosts://production-api',
  expectedHostFingerprint: fingerprint,
};

function storage(overrides: Partial<WindowsLocalReadinessProbe> = {}): WindowsLocalReadinessProbe {
  return {
    inspectReadiness: () => ({ registry: 'ready', filesystem: 'ready', configuration: 'ready' }),
    listProfiles: () => [profile],
    readKnownHosts: () => knownHosts,
    credentialAvailable: () => true,
    ...overrides,
  };
}

test('reports unsupported Windows without inspecting local state', () => {
  let inspections = 0;
  const status = createWindowsReadinessStatusProvider(
    false,
    storage({ inspectReadiness: () => ((inspections += 1), { registry: 'ready', filesystem: 'ready', configuration: 'ready' }) }),
  );

  assert.deepEqual(status.getWindowsReadinessStatus(), {
    kind: 'windows-readiness-status',
    version: 1,
    runtime: 'unsupported',
    registry: 'not-checked',
    filesystem: 'not-checked',
    configuration: 'not-checked',
    knownHosts: 'not-checked',
    credentials: 'not-checked',
    validationProvider: 'not-checked',
    remoteAuthentication: 'not-checked',
  });
  assert.equal(inspections, 0);
});

test('distinguishes bounded local prerequisite categories without returning profile data', async () => {
  const registryUnavailable = await createWindowsReadinessStatusProvider(
    true,
    storage({ inspectReadiness: () => ({ registry: 'unavailable', filesystem: 'not-checked', configuration: 'not-checked' }) }),
  ).getWindowsReadinessStatus();
  const filesystemUnavailable = await createWindowsReadinessStatusProvider(
    true,
    storage({ inspectReadiness: () => ({ registry: 'ready', filesystem: 'unavailable', configuration: 'not-checked' }) }),
  ).getWindowsReadinessStatus();
  const invalidConfiguration = await createWindowsReadinessStatusProvider(
    true,
    storage({
      listProfiles: () => {
        throw new Error('host=private.example password=secret');
      },
    }),
  ).getWindowsReadinessStatus();
  const knownHostsUnavailable = await createWindowsReadinessStatusProvider(
    true,
    storage({
      readKnownHosts: () => {
        throw new Error('C:\\private\\known_hosts');
      },
    }),
  ).getWindowsReadinessStatus();

  assert.deepEqual(
    [registryUnavailable.registry, filesystemUnavailable.filesystem, invalidConfiguration.configuration, knownHostsUnavailable.knownHosts],
    ['unavailable', 'unavailable', 'invalid', 'unavailable'],
  );
  assert.deepEqual(filesystemUnavailable, {
    kind: 'windows-readiness-status',
    version: 1,
    runtime: 'ready',
    registry: 'ready',
    filesystem: 'unavailable',
    configuration: 'not-checked',
    knownHosts: 'not-checked',
    credentials: 'not-checked',
    validationProvider: 'unavailable',
    remoteAuthentication: 'not-checked',
  });
  for (const result of [registryUnavailable, filesystemUnavailable, invalidConfiguration, knownHostsUnavailable]) {
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes('private.example'), false);
    assert.equal(serialized.includes('secret'), false);
    assert.equal(serialized.includes('known_hosts'), false);
  }
});

test('deduplicates known-hosts inspection and refuses over-bound profile work', async () => {
  let reads = 0;
  const duplicateReferenceStatus = await createWindowsReadinessStatusProvider(
    true,
    storage({
      listProfiles: () => [profile, { ...profile, profileId: 'staging-api' }],
      readKnownHosts: () => ((reads += 1), knownHosts),
    }),
  ).getWindowsReadinessStatus();
  assert.equal(duplicateReferenceStatus.knownHosts, 'ready');
  assert.equal(reads, 1);

  const oversizedProfiles = Array.from({ length: 257 }, () => profile);
  const oversizedStatus = await createWindowsReadinessStatusProvider(
    true,
    storage({
      listProfiles: () => oversizedProfiles,
      readKnownHosts: () => {
        throw new Error('C:\\private\\known_hosts');
      },
    }),
  ).getWindowsReadinessStatus();
  assert.deepEqual(oversizedStatus, {
    kind: 'windows-readiness-status',
    version: 1,
    runtime: 'ready',
    registry: 'ready',
    filesystem: 'ready',
    configuration: 'invalid',
    knownHosts: 'not-checked',
    credentials: 'not-checked',
    validationProvider: 'unavailable',
    remoteAuthentication: 'not-checked',
  });
  assert.equal(JSON.stringify(oversizedStatus).includes('private'), false);
});

test('checks protected known-hosts identity and password credential availability without remote authentication', () => {
  let knownHostsReads = 0;
  let credentialChecks = 0;
  const result = createWindowsReadinessStatusProvider(
    true,
    storage({
      readKnownHosts: () => ((knownHostsReads += 1), knownHosts),
      credentialAvailable: () => ((credentialChecks += 1), true),
    }),
    true,
  ).getWindowsReadinessStatus();

  assert.deepEqual(result, {
    kind: 'windows-readiness-status',
    version: 1,
    runtime: 'ready',
    registry: 'ready',
    filesystem: 'ready',
    configuration: 'ready',
    knownHosts: 'ready',
    credentials: 'ready',
    validationProvider: 'ready',
    remoteAuthentication: 'not-checked',
  });
  assert.equal(knownHostsReads, 1);
  assert.equal(credentialChecks, 1);
});

test('reports absent password credentials and known-hosts identity mismatch as redacted local failures', async () => {
  const absentCredential = await createWindowsReadinessStatusProvider(
    true,
    storage({ credentialAvailable: () => false }),
  ).getWindowsReadinessStatus();
  const mismatchedKnownHosts = await createWindowsReadinessStatusProvider(
    true,
    storage({ readKnownHosts: () => Buffer.from('[private.example]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIdifferent\n') }),
  ).getWindowsReadinessStatus();

  assert.deepEqual(absentCredential, {
    kind: 'windows-readiness-status',
    version: 1,
    runtime: 'ready',
    registry: 'ready',
    filesystem: 'ready',
    configuration: 'ready',
    knownHosts: 'ready',
    credentials: 'unavailable',
    validationProvider: 'unavailable',
    remoteAuthentication: 'not-checked',
  });
  assert.equal(mismatchedKnownHosts.credentials, 'ready');
  assert.equal(mismatchedKnownHosts.knownHosts, 'unavailable');
  for (const result of [absentCredential, mismatchedKnownHosts]) {
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes('private.example'), false);
    assert.equal(serialized.includes('private-credential'), false);
    assert.equal(serialized.includes(fingerprint), false);
  }
});

test('treats malformed and ambiguous protected known-hosts leaves as unavailable identities', async () => {
  const malformed = await createWindowsReadinessStatusProvider(
    true,
    storage({ readKnownHosts: () => Buffer.from('private.example malformed-key') }),
  ).getWindowsReadinessStatus();
  const ambiguous = await createWindowsReadinessStatusProvider(
    true,
    storage({ readKnownHosts: () => Buffer.concat([knownHosts, knownHosts]) }),
  ).getWindowsReadinessStatus();

  assert.equal(malformed.knownHosts, 'unavailable');
  assert.equal(ambiguous.knownHosts, 'unavailable');
  for (const result of [malformed, ambiguous]) assert.equal(JSON.stringify(result).includes('private.example'), false);
});

test('does not probe credentials for agent-key-only configured state', async () => {
  let credentialChecks = 0;
  const result = await createWindowsReadinessStatusProvider(
    true,
    storage({
      listProfiles: () => [{ ...profile, authMode: 'agent-key', credentialReference: undefined }],
      credentialAvailable: () => ((credentialChecks += 1), false),
    }),
  ).getWindowsReadinessStatus();

  assert.equal(result.credentials, 'not-checked');
  assert.equal(credentialChecks, 0);
});
