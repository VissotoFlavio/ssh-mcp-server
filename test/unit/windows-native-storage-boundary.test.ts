import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const addonPath = join(process.cwd(), 'build', 'Release', 'windows_trust.node');
const testAddonPath = join(process.cwd(), 'build', 'Release', 'windows_trust_test.node');
const fixture = join(process.cwd(), 'test', 'helpers', 'windows-native-storage-fixture.ps1');
const nativeRequire = createRequire(import.meta.url);
// Windows PowerShell 5.1 can fail to load ACL type data in isolated child
// processes, so these Windows-only fixtures require PowerShell 7+.
const fixtureShell = 'pwsh.exe';
const testOnlyHookNames = [
  'testReadReplacementRace',
  'testReadStateFile',
  'testSystemOwnerMismatch',
  'testTrustedOpenSsh',
  'testOpenSshIdentityBeforeLaunch',
  'testOpenSshUnexpectedPreLaunchError',
  'testLaunch',
  'testSetSnapshotFailure',
  'testSnapshotFreshIdentityRechecks',
  'testSnapshotArtifactCount',
  'testFinalizeSnapshotCapability',
  'testReadinessDescriptor',
  'testAgentCommandRequest',
  'testBlockDeferredReaper',
  'testReleaseDeferredReaper',
  'testWaitForMasterStarted',
  'testDeferredReaperCompletion',
] as const;

type RegistryMutationRight =
  'SetValue' | 'CreateSubKey' | 'CreateLink' | 'ChangePermissions' | 'TakeOwnership' | 'Delete' | 'WriteKey' | 'GenericWrite';
type FixtureMode =
  | 'safe'
  | 'unsafe-root'
  | 'unsafe-state-leaf'
  | 'unsafe-known-hosts-leaf'
  | 'unsafe-write-dac-root'
  | 'unsafe-write-dac-state-leaf'
  | 'unsafe-write-dac-known-hosts-leaf'
  | 'reparse-state-root'
  | 'reparse-state-leaf'
  | 'reparse-known-hosts-leaf'
  | 'openssh-chain-reparse'
  | 'openssh-chain-unsafe-dacl'
  | 'openssh-chain-safe'
  | 'unsafe-registry-mutation'
  | 'unsafe-registry-unprotected'
  | 'unsafe-inherited-leaf'
  | 'overlap'
  | 'dot-alias'
  | 'junction'
  | 'unsupported-volume'
  | 'cleanup';

function runFixture(mode: FixtureMode, root: string, registryMutationRight?: RegistryMutationRight): void {
  const args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fixture, '-Mode', mode];
  if (registryMutationRight !== undefined) args.push('-RegistryMutationRight', registryMutationRight);
  execFileSync(fixtureShell, args, {
    env: { ...process.env, SSH_MCP_WINDOWS_STORAGE_TEST_ROOT: root },
    stdio: 'pipe',
  });
}

function uniqueRoot(suffix: string): string {
  return join(homedir(), `ssh-mcp-native-boundary-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}-${suffix}`);
}

if (process.platform !== 'win32' || !existsSync(addonPath) || !existsSync(testAddonPath)) {
  test.skip('requires Windows with the compiled production and test native addons', () => undefined);
} else {
  const binding = nativeRequire(addonPath) as {
    readProfileState(): Buffer;
    inspectReadiness(): { readonly registry: string; readonly filesystem: string; readonly configuration: string };
    readKnownHosts(profileId: string): Buffer;
    credentialAvailable(locator: string): boolean;
    captureKnownHostsSnapshot(profileId: string): { bytes: Buffer; capability: object };
    disposeKnownHostsSnapshot(capability: unknown): void;
    startAgentKeyReadiness(
      capability: object,
      descriptor: { readonly host: string; readonly port: number; readonly user: string },
      timeoutMs: number,
    ): { readonly promise: Promise<void>; readonly cancel: () => void };
    readCredential(locator: unknown): string;
    resolveOpenSsh(): { ssh: string; sshAdd: string; version: string };
    probeSshAdd(timeoutMs: unknown): number;
    startSshAddProbe(timeoutMs: unknown): { readonly promise: Promise<boolean>; readonly cancel: () => void };
    execute(capability: object, request: object, signal?: AbortSignal): Promise<unknown>;
  };
  const testBinding = nativeRequire(testAddonPath) as {
    captureKnownHostsSnapshot(profileId: string): { bytes: Buffer; capability: object };
    disposeKnownHostsSnapshot(capability: unknown): void;
    startAgentKeyReadiness(
      capability: object,
      descriptor: { readonly host: string; readonly port: number; readonly user: string },
      timeoutMs: number,
    ): { readonly promise: Promise<void>; readonly cancel: () => void };
    testReadReplacementRace(target: 'state-root' | 'state-leaf' | 'known-hosts-root' | 'known-hosts-leaf'): {
      hookExecuted: boolean;
      replacementError: number;
      readSucceeded: boolean;
      stage: string;
    };
    testReadStateFile(root: string): boolean;
    testSystemOwnerMismatch(): boolean;
    testTrustedOpenSsh(system: string): boolean;
    testOpenSshIdentityBeforeLaunch(): { replacementBlocked: boolean; moveAttempted: boolean; replacementError: number; launchCompleted: boolean };
    testOpenSshUnexpectedPreLaunchError(): {
      replacementBlocked: boolean;
      moveAttempted: boolean;
      replacementError: number;
      launchCompleted: boolean;
    };
    testLaunch(mode: 'exit' | 'hang', timeoutMs: number): { completed: boolean; timedOut: boolean; exitCode: number };
    testSetSnapshotFailure(
      failure:
        | 'directory-create'
        | 'directory-verify'
        | 'directory-identity'
        | 'file-verify'
        | 'file-identity'
        | 'write'
        | 'flush'
        | 'file-disposition'
        | 'directory-disposition',
    ): void;
    testSnapshotFreshIdentityRechecks(): number;
    testSnapshotArtifactCount(): number;
    testFinalizeSnapshotCapability(capability: object): void;
    testReadinessDescriptor(descriptor: unknown): boolean;
    testAgentCommandRequest(request: unknown): boolean;
    testBlockDeferredReaper(): void;
    testReleaseDeferredReaper(): void;
    testWaitForMasterStarted(timeoutMs: number): boolean;
    testDeferredReaperCompletion(): Promise<void>;
  };

  test('keeps test-only hooks out of the production native addon', () => {
    for (const hook of testOnlyHookNames) {
      assert.equal(hook in binding, false, `Production addon exposes ${hook}`);
    }
  });

  test('accepts only the fixed native agent-readiness descriptor grammar', () => {
    assert.equal(testBinding.testReadinessDescriptor(Object.freeze({ host: 'api.internal.example', port: 22, user: 'deploy' })), true);
    assert.equal(testBinding.testReadinessDescriptor(Object.freeze({ host: '2001:db8::1', port: 22, user: 'deploy' })), true);
    assert.equal(testBinding.testReadinessDescriptor({ host: 'api.internal.example', port: 22, user: 'deploy', command: 'id' }), false);
    assert.equal(testBinding.testReadinessDescriptor({ host: 'api.internal.example -oProxyCommand=evil', port: 22, user: 'deploy' }), false);
    assert.equal(testBinding.testReadinessDescriptor({ host: 'api.internal.example', port: 22, user: '-oProxyCommand=evil' }), false);
    assert.equal(testBinding.testReadinessDescriptor({ host: 'api.internal.example', port: 0, user: 'deploy' }), false);
  });

  test('accepts only bounded native agent-command request data', () => {
    const valid = {
      profileId: 'production-api',
      host: 'api.internal.example',
      port: 22,
      user: 'deploy',
      expectedHostFingerprint: `SHA256:${'a'.repeat(43)}`,
      command: 'id',
      args: ['--version'],
      timeoutMs: 1_000,
      maxOutputBytes: 1_024,
    };
    assert.equal(testBinding.testAgentCommandRequest(valid), true);
    assert.equal(testBinding.testAgentCommandRequest({ ...valid, command: 'sh' }), false);
    assert.equal(testBinding.testAgentCommandRequest({ ...valid, args: ['-c'] }), false);
    assert.equal(testBinding.testAgentCommandRequest({ ...valid, args: ['echo;whoami'] }), false);
    assert.equal(testBinding.testAgentCommandRequest({ ...valid, extra: 'rejected' }), false);
  });

  test('accepts only an isolated private per-user configuration and verified Windows OpenSSH', () => {
    const root = uniqueRoot('safe');
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      assert.equal(binding.readProfileState().toString('utf8'), '{"profiles":[]}');
      assert.deepEqual(binding.inspectReadiness(), { registry: 'ready', filesystem: 'ready', configuration: 'ready' });
      assert.match(binding.readKnownHosts('production-api').toString('utf8'), /ssh-ed25519/u);
      assert.throws(() => binding.readCredential('.'), /Windows secure storage is unavailable/u);
      assert.equal(typeof binding.credentialAvailable, 'function');
      const ssh = binding.resolveOpenSsh();
      assert.match(ssh.ssh, /\\System32\\OpenSSH\\ssh\.exe$/iu);
      assert.match(ssh.sshAdd, /\\System32\\OpenSSH\\ssh-add\.exe$/iu);
      assert.match(ssh.version, /^9\.(?:[5-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$/u);
      assert.equal(typeof binding.probeSshAdd, 'function');
      assert.equal('validateAgentKeyReadiness' in binding, false);
      assert.equal(typeof binding.startSshAddProbe, 'function');
      assert.equal(typeof binding.execute, 'function');
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  test('captures verified known-hosts bytes in an opaque one-use native snapshot capability', () => {
    const root = uniqueRoot('snapshot');
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      const expected = binding.readKnownHosts('production-api');
      const snapshot = binding.captureKnownHostsSnapshot('production-api');
      const sentinel = join(root, 'state', 'snapshot-sentinel');
      writeFileSync(sentinel, 'sentinel', 'utf8');
      assert.equal(Buffer.isBuffer(snapshot.bytes), true);
      assert.deepEqual(snapshot.bytes, expected);
      assert.equal(testBinding.testSnapshotArtifactCount(), 1);
      assert.deepEqual(Object.keys(snapshot).sort(), ['bytes', 'capability']);
      assert.deepEqual(Object.getOwnPropertyNames(snapshot.capability), []);
      assert.equal(JSON.stringify(snapshot.capability).includes(root), false);
      assert.throws(() => binding.disposeKnownHostsSnapshot({}), /Windows secure storage is unavailable/u);
      assert.throws(() => binding.disposeKnownHostsSnapshot(Object.create(snapshot.capability)), /Windows secure storage is unavailable/u);
      assert.equal(existsSync(sentinel), true);
      assert.doesNotThrow(() => binding.disposeKnownHostsSnapshot(snapshot.capability));
      assert.equal(testBinding.testSnapshotArtifactCount(), 0);
      assert.throws(() => binding.disposeKnownHostsSnapshot(snapshot.capability), /Windows secure storage is unavailable/u);
      assert.equal(existsSync(sentinel), true);
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  test('cancellation retains the opaque snapshot until native readiness has reaped its children', async () => {
    const root = uniqueRoot('snapshot-cancel');
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      const snapshot = testBinding.captureKnownHostsSnapshot('production-api');
      const operation = testBinding.startAgentKeyReadiness(snapshot.capability, { host: 'api.internal.example', port: 22, user: 'deploy' }, 5_000);
      operation.cancel();
      assert.throws(() => testBinding.disposeKnownHostsSnapshot(snapshot.capability), /Windows secure storage is unavailable/u);
      await assert.rejects(operation.promise, /Windows connection validation is unavailable/u);
      assert.doesNotThrow(() => testBinding.disposeKnownHostsSnapshot(snapshot.capability));
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  test('retains a busy snapshot while the forced deferred reaper is blocked', async () => {
    const root = uniqueRoot('deferred-reaper');
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      testBinding.testBlockDeferredReaper();
      const snapshot = testBinding.captureKnownHostsSnapshot('production-api');
      const operation = testBinding.startAgentKeyReadiness(snapshot.capability, { host: '192.0.2.1', port: 22, user: 'deploy' }, 1_000);
      assert.equal(testBinding.testWaitForMasterStarted(1_000), true);
      operation.cancel();
      await assert.rejects(operation.promise, /Windows connection validation is unavailable/u);
      assert.throws(() => testBinding.disposeKnownHostsSnapshot(snapshot.capability), /Windows secure storage is unavailable/u);
      const reaped = testBinding.testDeferredReaperCompletion();
      testBinding.testReleaseDeferredReaper();
      await reaped;
      assert.equal(testBinding.testSnapshotArtifactCount(), 0);
      assert.throws(() => testBinding.disposeKnownHostsSnapshot(snapshot.capability), /Windows secure storage is unavailable/u);
    } finally {
      if (configured) {
        try {
          testBinding.testReleaseDeferredReaper();
        } catch {
          // The gate may already be released.
        }
        runFixture('cleanup', root);
      }
    }
  });

  test('lets the test native addon capture and dispose a baseline snapshot', () => {
    const root = uniqueRoot('test-snapshot-baseline');
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      const snapshot = testBinding.captureKnownHostsSnapshot('production-api');
      assert.equal(testBinding.testSnapshotArtifactCount(), 1);
      assert.doesNotThrow(() => testBinding.disposeKnownHostsSnapshot(snapshot.capability));
      assert.equal(testBinding.testSnapshotArtifactCount(), 0);
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  test('cancels native agent readiness before it can retain a snapshot or start a remote command', async () => {
    const root = uniqueRoot('cancel-agent-readiness');
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      const snapshot = binding.captureKnownHostsSnapshot('production-api');
      const operation = binding.startAgentKeyReadiness(snapshot.capability, Object.freeze({ host: '192.0.2.1', port: 22, user: 'deploy' }), 1_000);
      operation.cancel();
      await assert.rejects(operation.promise, /Windows connection validation is unavailable/u);
      assert.doesNotThrow(() => binding.disposeKnownHostsSnapshot(snapshot.capability));
      assert.equal(testBinding.testSnapshotArtifactCount(), 0);
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  for (const failure of ['directory-create', 'directory-verify', 'directory-identity', 'file-verify', 'file-identity', 'write', 'flush'] as const) {
    test(`leaves no snapshot artifacts when ${failure} fails before capability creation`, () => {
      const root = uniqueRoot(`snapshot-${failure}`);
      let configured = false;
      try {
        runFixture('safe', root);
        configured = true;
        assert.equal(testBinding.testSnapshotArtifactCount(), 0);
        testBinding.testSetSnapshotFailure(failure);
        assert.throws(() => testBinding.captureKnownHostsSnapshot('production-api'), /Windows secure storage is unavailable/u);
        assert.equal(testBinding.testSnapshotFreshIdentityRechecks(), failure.endsWith('identity') ? 1 : 0);
        assert.equal(testBinding.testSnapshotArtifactCount(), 0);
      } finally {
        if (configured) runFixture('cleanup', root);
      }
    });
  }

  for (const failure of ['file-disposition', 'directory-disposition'] as const) {
    test(`retains a retryable capability when ${failure} cleanup fails`, () => {
      const root = uniqueRoot(`snapshot-${failure}`);
      let configured = false;
      try {
        runFixture('safe', root);
        configured = true;
        const snapshot = testBinding.captureKnownHostsSnapshot('production-api');
        assert.equal(testBinding.testSnapshotArtifactCount(), 1);
        testBinding.testSetSnapshotFailure(failure);
        assert.throws(() => testBinding.disposeKnownHostsSnapshot(snapshot.capability), /Windows secure storage is unavailable/u);
        assert.equal(testBinding.testSnapshotArtifactCount(), 1);
        assert.doesNotThrow(() => testBinding.disposeKnownHostsSnapshot(snapshot.capability));
        assert.equal(testBinding.testSnapshotArtifactCount(), 0);
      } finally {
        if (configured) runFixture('cleanup', root);
      }
    });
  }

  test('retries a transient cleanup failure during native finalization without leaving artifacts', () => {
    const root = uniqueRoot('snapshot-finalizer');
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      const snapshot = testBinding.captureKnownHostsSnapshot('production-api');
      assert.equal(testBinding.testSnapshotArtifactCount(), 1);
      testBinding.testSetSnapshotFailure('file-disposition');
      assert.doesNotThrow(() => testBinding.testFinalizeSnapshotCapability(snapshot.capability));
      assert.equal(testBinding.testSnapshotArtifactCount(), 0);
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  for (const target of ['state-root', 'state-leaf', 'known-hosts-root', 'known-hosts-leaf'] as const) {
    test(`rejects ${target} replacement through the production protected-file routine`, () => {
      const root = uniqueRoot(`${target}-replacement`);
      let configured = false;
      try {
        runFixture('safe', root);
        configured = true;
        assert.deepEqual(testBinding.testReadReplacementRace(target), {
          hookExecuted: true,
          replacementError: 0,
          readSucceeded: false,
          stage: 'production-read',
        });
      } finally {
        if (configured) runFixture('cleanup', root);
      }
    });
  }

  test('rejects a state-root reparse point through the production protected-file routine', () => {
    const root = uniqueRoot('reparse-state-root');
    let configured = false;
    try {
      runFixture('reparse-state-root', root);
      configured = true;
      assert.equal(testBinding.testReadStateFile(join(root, 'linked-state')), false);
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  for (const mode of ['openssh-chain-reparse', 'openssh-chain-unsafe-dacl'] as const) {
    test(`rejects ${mode} through the production trusted OpenSSH routine`, () => {
      const root = uniqueRoot(mode);
      let configured = false;
      try {
        runFixture(mode, root);
        configured = true;
        assert.equal(testBinding.testTrustedOpenSsh(join(root, 'openssh-system')), false);
      } finally {
        if (configured) runFixture('cleanup', root);
      }
    });
  }

  test('blocks OpenSSH identity replacement immediately before the production launch chain', () => {
    const result = testBinding.testOpenSshIdentityBeforeLaunch();
    assert.equal(result.replacementBlocked, true);
    assert.equal(result.moveAttempted, true);
    assert.equal([5, 32].includes(result.replacementError), true);
    assert.equal(result.launchCompleted, true);
  });

  test('fails closed before launch when the OpenSSH replacement attempt has an unexpected error', () => {
    assert.deepEqual(testBinding.testOpenSshUnexpectedPreLaunchError(), {
      replacementBlocked: false,
      moveAttempted: false,
      replacementError: 5,
      launchCompleted: false,
    });
  });

  test('rejects an existing system-owned location without mutating it', () => {
    assert.equal(testBinding.testSystemOwnerMismatch(), false);
  });

  test('launches a completed native child and terminates a timed-out native child', () => {
    assert.deepEqual(testBinding.testLaunch('exit', 5_000), { completed: true, timedOut: false, exitCode: 23 });
    assert.deepEqual(testBinding.testLaunch('hang', 100), { completed: false, timedOut: true, exitCode: 0 });
  });

  test('reports an unsafe root as a redacted filesystem prerequisite', () => {
    const root = uniqueRoot('unsafe-readiness-root');
    let configured = false;
    try {
      runFixture('unsafe-root', root);
      configured = true;
      const readiness = binding.inspectReadiness();
      assert.deepEqual(readiness, { registry: 'ready', filesystem: 'unavailable', configuration: 'not-checked' });
      assert.equal(JSON.stringify(readiness).includes(root), false);
      assert.equal(JSON.stringify(readiness).includes('\\'), false);
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  const registryMutationRights: readonly RegistryMutationRight[] = [
    'SetValue',
    'CreateSubKey',
    'CreateLink',
    'ChangePermissions',
    'TakeOwnership',
    'Delete',
    'WriteKey',
    'GenericWrite',
  ];
  const rejectedConfigurations: ReadonlyArray<{
    readonly doD: string;
    readonly mode: FixtureMode;
    readonly read: 'profile' | 'known-hosts';
    readonly registryMutationRight?: RegistryMutationRight;
  }> = [
    { doD: 'rejects writable state root', mode: 'unsafe-root', read: 'profile' },
    { doD: 'rejects writable state file', mode: 'unsafe-state-leaf', read: 'profile' },
    { doD: 'rejects writable known-hosts file', mode: 'unsafe-known-hosts-leaf', read: 'known-hosts' },
    { doD: 'rejects WRITE_DAC on the state root', mode: 'unsafe-write-dac-root', read: 'profile' },
    { doD: 'rejects WRITE_DAC on the state file', mode: 'unsafe-write-dac-state-leaf', read: 'profile' },
    { doD: 'rejects WRITE_DAC on the known-hosts file', mode: 'unsafe-write-dac-known-hosts-leaf', read: 'known-hosts' },
    { doD: 'rejects a reparse state file', mode: 'reparse-state-leaf', read: 'profile' },
    { doD: 'rejects a reparse known-hosts file', mode: 'reparse-known-hosts-leaf', read: 'known-hosts' },
    ...registryMutationRights.map((registryMutationRight) => ({
      doD: `rejects registry mutation right ${registryMutationRight}`,
      mode: 'unsafe-registry-mutation' as const,
      read: 'profile' as const,
      registryMutationRight,
    })),
    { doD: 'rejects an inheritable registry DACL', mode: 'unsafe-registry-unprotected', read: 'profile' },
    { doD: 'rejects an inherited state-file DACL', mode: 'unsafe-inherited-leaf', read: 'profile' },
    { doD: 'rejects overlapping roots', mode: 'overlap', read: 'profile' },
    { doD: 'rejects dot-alias roots', mode: 'dot-alias', read: 'profile' },
    { doD: 'rejects junction roots', mode: 'junction', read: 'profile' },
    { doD: 'rejects unsupported local-volume paths', mode: 'unsupported-volume', read: 'profile' },
  ];

  for (const { doD, mode, read, registryMutationRight } of rejectedConfigurations) {
    test(doD, () => {
      const root = uniqueRoot(registryMutationRight ?? mode);
      let configured = false;
      try {
        runFixture(mode, root, registryMutationRight);
        configured = true;
        const readBoundary = read === 'profile' ? () => binding.readProfileState() : () => binding.readKnownHosts('production-api');
        assert.throws(readBoundary, /Windows secure storage is unavailable/u);
      } finally {
        if (configured) runFixture('cleanup', root);
      }
    });
  }

  test('rejects invalid native inputs before the trust boundary can read storage or credentials', () => {
    for (const invalid of ['', '../production-api', 'production_api', 'PRODUCTION']) {
      assert.throws(() => binding.readKnownHosts(invalid), /Windows secure storage is unavailable/u);
    }
    for (const invalid of ['', '.', '../production-api', 'Production']) {
      assert.throws(() => binding.readCredential(invalid), /Windows secure storage is unavailable/u);
    }
    for (const invalid of [0, -1, 60_001, '1000']) {
      assert.throws(() => binding.probeSshAdd(invalid), /Windows secure storage is unavailable/u);
    }
  });
}
