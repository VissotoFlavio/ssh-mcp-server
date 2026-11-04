import { strict as assert } from 'node:assert';
import { constants } from 'node:fs';
import { lstat, mkdtemp, mkdir, open, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  CONNECTION_PROFILE_STATE_FILE,
  getNoFollowReadFlags,
  LocalConnectionProfileRegistry,
  MAX_CONNECTION_PROFILES,
  MAX_CONNECTION_PROFILE_STATE_BYTES,
  type LocalProfileRegistryFileStats,
  LocalProfileRegistryError,
} from '../../src/profiles/local-profile-registry.js';

const validProfile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  authMode: 'agent-key',
  approvedKnownHostsReference: 'known-hosts://production-api',
};

async function withStateRoot(run: (stateRoot: string) => Promise<void>): Promise<void> {
  const stateRoot = await mkdtemp(join(tmpdir(), 'ssh-mcp-profiles-'));
  try {
    await run(stateRoot);
  } finally {
    await rm(stateRoot, { recursive: true, force: true });
  }
}

async function writeState(stateRoot: string, state: unknown): Promise<void> {
  await writeFile(join(stateRoot, CONNECTION_PROFILE_STATE_FILE), JSON.stringify(state), 'utf8');
}

async function expectRegistryFailure(action: () => Promise<unknown>, code: LocalProfileRegistryError['code']): Promise<void> {
  await assert.rejects(action, (error: unknown) => error instanceof LocalProfileRegistryError && error.code === code);
}

function fileStats(dev: number, ino: number, size: number): LocalProfileRegistryFileStats {
  return {
    dev,
    ino,
    size,
    isDirectory: () => false,
    isFile: () => true,
    isSymbolicLink: () => false,
  };
}

function directoryStats(dev: number, ino: number): LocalProfileRegistryFileStats {
  return {
    dev,
    ino,
    size: 0,
    isDirectory: () => true,
    isFile: () => false,
    isSymbolicLink: () => false,
  };
}

function createRegistry(stateRoot: string): LocalConnectionProfileRegistry {
  return new LocalConnectionProfileRegistry(
    { stateRoot },
    {
      supportsNoFollow: true,
      lstat,
      realpath,
      openReadOnlyNoFollow: async (path) => open(path, constants.O_RDONLY),
    },
  );
}

test('derives native no-follow flags only from a supported non-zero capability', () => {
  assert.equal(getNoFollowReadFlags(undefined), undefined);
  assert.equal(getNoFollowReadFlags(0), undefined);

  const noFollowFlag = 0x20000;
  const flags = getNoFollowReadFlags(noFollowFlag);
  assert.notEqual(flags, undefined);
  assert.equal((flags as number) & noFollowFlag, noFollowFlag);
});

test('loads only approved non-secret profiles from the fixed local state file', async () => {
  await withStateRoot(async (stateRoot) => {
    await writeState(stateRoot, { profiles: [validProfile] });
    const registry = createRegistry(stateRoot);

    assert.deepEqual(await registry.getProfile('production-api'), validProfile);
    assert.deepEqual(await registry.listProfiles(), [validProfile]);
    assert.equal(await registry.getProfile('unknown-profile'), undefined);
  });
});

test('does not expose mutable registry state', async () => {
  await withStateRoot(async (stateRoot) => {
    await writeState(stateRoot, { profiles: [validProfile] });
    const registry = createRegistry(stateRoot);

    const profiles = await registry.listProfiles();
    (profiles[0] as { host: string }).host = 'attacker.example';

    assert.equal((await registry.getProfile('production-api'))?.host, validProfile.host);
  });
});

test('rejects non-canonical profile identifiers without making them file paths', async () => {
  await withStateRoot(async (stateRoot) => {
    await writeState(stateRoot, { profiles: [validProfile] });
    const registry = createRegistry(stateRoot);

    await assert.rejects(() => registry.getProfile('../production-api'), /canonical lowercase hyphenated/);
    await assert.rejects(() => registry.getProfile('Production-api'), /canonical lowercase hyphenated/);
  });
});

test('rejects malformed state, unknown fields, secret material, and duplicate identifiers', async () => {
  await withStateRoot(async (stateRoot) => {
    const registry = createRegistry(stateRoot);
    const rejectedStates: unknown[] = [
      [],
      {},
      { profiles: [], source: 'https://attacker.example/profiles.json' },
      { profiles: { profileId: 'production-api' } },
      { profiles: [{ ...validProfile, password: 'secret' }] },
      { profiles: [{ ...validProfile, privateKey: 'not-allowed' }] },
      { profiles: [validProfile, validProfile] },
    ];

    for (const state of rejectedStates) {
      await writeState(stateRoot, state);
      await expectRegistryFailure(() => registry.listProfiles(), 'invalid-state');
    }
  });
});

test('fails closed for invalid JSON and filesystem failures', async () => {
  await withStateRoot(async (stateRoot) => {
    const registry = createRegistry(stateRoot);
    await expectRegistryFailure(() => registry.listProfiles(), 'state-unavailable');

    await writeFile(join(stateRoot, CONNECTION_PROFILE_STATE_FILE), '{ not json', 'utf8');
    await expectRegistryFailure(() => registry.listProfiles(), 'invalid-state');
  });
});

test('bounds state bytes and profile cardinality before accepting state', async () => {
  await withStateRoot(async (stateRoot) => {
    const registry = createRegistry(stateRoot);
    await writeFile(join(stateRoot, CONNECTION_PROFILE_STATE_FILE), 'x'.repeat(MAX_CONNECTION_PROFILE_STATE_BYTES + 1), 'utf8');
    await expectRegistryFailure(() => registry.listProfiles(), 'invalid-state');

    await writeState(stateRoot, { profiles: Array.from({ length: MAX_CONNECTION_PROFILES + 1 }, () => validProfile) });
    await expectRegistryFailure(() => registry.listProfiles(), 'invalid-state');
  });
});

test('does not parse a descriptor when the state path is substituted after open', async () => {
  const stateRoot = resolve(tmpdir(), 'approved-state');
  const stateFile = join(stateRoot, CONNECTION_PROFILE_STATE_FILE);
  const root = directoryStats(1, 1);
  const openedFile = fileStats(1, 2, 2);
  const replacement = fileStats(1, 3, 80);
  let readCalled = false;
  const registry = new LocalConnectionProfileRegistry(
    { stateRoot },
    {
      supportsNoFollow: true,
      lstat: async (path) => (path === stateRoot ? root : replacement),
      realpath: async (path) => (path === stateRoot ? stateRoot : stateFile),
      openReadOnlyNoFollow: async () => ({
        stat: async () => openedFile,
        read: async () => {
          readCalled = true;
          return { bytesRead: 0 };
        },
        close: async () => undefined,
      }),
    },
  );

  await expectRegistryFailure(() => registry.listProfiles(), 'state-unavailable');
  assert.equal(readCalled, false);
});

test('fails closed when the configured root changes identity after opening state', async () => {
  const stateRoot = resolve(tmpdir(), 'approved-state');
  const stateFile = join(stateRoot, CONNECTION_PROFILE_STATE_FILE);
  const originalRoot = directoryStats(1, 1);
  const replacementRoot = directoryStats(1, 4);
  const state = fileStats(1, 2, 2);
  let rootChecks = 0;
  let readCalled = false;
  const registry = new LocalConnectionProfileRegistry(
    { stateRoot },
    {
      supportsNoFollow: true,
      lstat: async (path) => {
        if (path === stateRoot) {
          rootChecks += 1;
          return rootChecks === 1 ? originalRoot : replacementRoot;
        }
        return state;
      },
      realpath: async (path) => (path === stateRoot ? stateRoot : stateFile),
      openReadOnlyNoFollow: async () => ({
        stat: async () => state,
        read: async () => {
          readCalled = true;
          return { bytesRead: 0 };
        },
        close: async () => undefined,
      }),
    },
  );

  await expectRegistryFailure(() => registry.listProfiles(), 'state-unavailable');
  assert.equal(readCalled, false);
});

test('fails closed when no-follow descriptor access is unavailable', async () => {
  const registry = new LocalConnectionProfileRegistry(
    { stateRoot: resolve(tmpdir(), 'approved-state') },
    {
      supportsNoFollow: false,
      lstat: async () => directoryStats(1, 1),
      realpath: async (path) => path,
      openReadOnlyNoFollow: async () => {
        throw new Error('open must not be called');
      },
    },
  );

  await expectRegistryFailure(() => registry.listProfiles(), 'state-unavailable');
});

test('rejects state roots with traversal and does not allow alternate state filenames', async () => {
  await withStateRoot(async (stateRoot) => {
    assert.throws(() => new LocalConnectionProfileRegistry({ stateRoot: `${stateRoot}\\..\\other` }), /parent traversal/);
    await writeFile(join(stateRoot, 'profiles.json'), JSON.stringify({ profiles: [validProfile] }), 'utf8');

    const registry = createRegistry(stateRoot);
    await expectRegistryFailure(() => registry.listProfiles(), 'state-unavailable');
  });
});

test('rejects symbolic-link roots and state files', async (t) => {
  await withStateRoot(async (stateRoot) => {
    const targetRoot = await mkdtemp(join(tmpdir(), 'ssh-mcp-profile-target-'));
    try {
      await writeState(targetRoot, { profiles: [validProfile] });
      const linkedRoot = join(stateRoot, 'linked-root');
      try {
        await symlink(targetRoot, linkedRoot, 'junction');
      } catch (error) {
        t.skip(`symbolic links are unavailable: ${(error as Error).message}`);
        return;
      }

      const linkedRegistry = createRegistry(linkedRoot);
      await expectRegistryFailure(() => linkedRegistry.listProfiles(), 'state-unavailable');

      const fileRoot = join(stateRoot, 'file-root');
      await mkdir(fileRoot);
      const externalState = join(targetRoot, CONNECTION_PROFILE_STATE_FILE);
      await symlink(externalState, join(fileRoot, CONNECTION_PROFILE_STATE_FILE), 'file');
      const fileRegistry = createRegistry(fileRoot);
      await expectRegistryFailure(() => fileRegistry.listProfiles(), 'state-unavailable');
    } finally {
      await rm(targetRoot, { recursive: true, force: true });
    }
  });
});
