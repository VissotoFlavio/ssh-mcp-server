import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

import { validateConnectionProfile, validateProfileSelection, type ConnectionProfile } from './connection-profile.js';

/** The sole operator-owned state file consulted by the local registry. */
export const CONNECTION_PROFILE_STATE_FILE = 'connection-profiles.json';
export const MAX_CONNECTION_PROFILE_STATE_BYTES = 1024 * 1024;
export const MAX_CONNECTION_PROFILES = 256;

export interface LocalProfileRegistryOptions {
  /** Absolute, operator-configured directory containing connection-profiles.json. */
  readonly stateRoot: string;
  /** When set, require the root and state file to be privately owned by this UID. */
  readonly operatorUid?: number;
}

export interface LocalProfileRegistry {
  getProfile(profileId: string): Promise<ConnectionProfile | undefined>;
  listProfiles(): Promise<readonly ConnectionProfile[]>;
}

/** Minimal file API boundary, allowing deterministic substitution tests. */
export interface LocalProfileRegistryFileSystem {
  readonly supportsNoFollow: boolean;
  lstat(path: string): Promise<LocalProfileRegistryFileStats>;
  realpath(path: string): Promise<string>;
  openReadOnlyNoFollow(path: string): Promise<LocalProfileRegistryFileHandle>;
}

export interface LocalProfileRegistryFileStats {
  readonly dev: number;
  readonly ino: number;
  readonly size: number;
  readonly uid?: number;
  readonly mode?: number;
  isDirectory(): boolean;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

export interface LocalProfileRegistryFileHandle {
  stat(): Promise<LocalProfileRegistryFileStats>;
  read(buffer: Buffer, offset: number, length: number, position: number): Promise<{ readonly bytesRead: number }>;
  close(): Promise<void>;
}

interface ConnectionProfileState {
  readonly profiles: readonly ConnectionProfile[];
}

const STATE_FIELDS = new Set(['profiles']);

/** Return secure read flags only when the platform provides a non-zero no-follow flag. */
export function getNoFollowReadFlags(noFollowFlag: unknown): number | undefined {
  if (typeof noFollowFlag !== 'number' || !Number.isInteger(noFollowFlag) || noFollowFlag === 0) {
    return undefined;
  }
  return constants.O_RDONLY | noFollowFlag;
}

const nodeNoFollowReadFlags = getNoFollowReadFlags(constants.O_NOFOLLOW);

const nodeFileSystem: LocalProfileRegistryFileSystem = {
  supportsNoFollow: nodeNoFollowReadFlags !== undefined,
  lstat,
  realpath,
  openReadOnlyNoFollow: async (path) => {
    if (nodeNoFollowReadFlags === undefined) {
      throw new Error('No-follow descriptor access is unavailable');
    }
    return open(path, nodeNoFollowReadFlags);
  },
};

function invalidState(): never {
  throw new LocalProfileRegistryError('invalid-state', 'Approved connection profile state is invalid');
}

function unavailableState(): never {
  throw new LocalProfileRegistryError('state-unavailable', 'Approved connection profile state is unavailable');
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasParentTraversal(value: string): boolean {
  return value.split(/[\\/]+/u).includes('..');
}

function isWithin(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === '' || (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== '..' && !isAbsolute(pathFromRoot));
}

function hasSameIdentity(left: LocalProfileRegistryFileStats, right: LocalProfileRegistryFileStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function isOperatorOwned(stats: LocalProfileRegistryFileStats, uid: number, directory: boolean): boolean {
  return (
    stats.uid === uid &&
    typeof stats.mode === 'number' &&
    (stats.mode & 0o022) === 0 &&
    !stats.isSymbolicLink() &&
    (directory ? stats.isDirectory() : stats.isFile())
  );
}

function validateStateRoot(stateRoot: string): string {
  if (typeof stateRoot !== 'string' || stateRoot.trim() === '' || !isAbsolute(stateRoot) || hasParentTraversal(stateRoot)) {
    throw new TypeError('stateRoot must be an absolute path without parent traversal');
  }

  return resolve(stateRoot);
}

function parseState(input: unknown): ConnectionProfileState {
  if (!isPlainRecord(input)) {
    return invalidState();
  }

  const fields = Reflect.ownKeys(input);
  if (fields.length !== 1 || fields.some((field) => typeof field !== 'string' || !STATE_FIELDS.has(field))) {
    return invalidState();
  }

  const profiles = input.profiles;
  if (!Array.isArray(profiles) || profiles.length > MAX_CONNECTION_PROFILES) {
    return invalidState();
  }

  const profileIds = new Set<string>();
  const validatedProfiles = profiles.map((profile) => {
    try {
      const validated = validateConnectionProfile(profile);
      if (profileIds.has(validated.profileId)) {
        return invalidState();
      }
      profileIds.add(validated.profileId);
      return validated;
    } catch {
      return invalidState();
    }
  });

  return { profiles: validatedProfiles };
}

/**
 * Registry backed only by a fixed state file beneath an operator-configured root.
 * It intentionally never turns a profile identifier or caller input into a path.
 */
export class LocalConnectionProfileRegistry implements LocalProfileRegistry {
  private readonly stateRoot: string;
  private readonly stateFile: string;
  private readonly fileSystem: LocalProfileRegistryFileSystem;
  private readonly operatorUid: number | undefined;

  constructor(options: LocalProfileRegistryOptions, fileSystem: LocalProfileRegistryFileSystem = nodeFileSystem) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('Local profile registry options are required');
    }

    this.stateRoot = validateStateRoot(options.stateRoot);
    this.stateFile = resolve(this.stateRoot, CONNECTION_PROFILE_STATE_FILE);
    if (!isWithin(this.stateRoot, this.stateFile)) {
      throw new TypeError('Connection profile state file escapes stateRoot');
    }
    this.fileSystem = fileSystem;
    this.operatorUid = options.operatorUid;
  }

  async getProfile(profileId: string): Promise<ConnectionProfile | undefined> {
    const selection = validateProfileSelection({ profileId });
    const state = await this.loadState();
    const profile = state.profiles.find((candidate) => candidate.profileId === selection.profileId);
    return profile === undefined ? undefined : { ...profile };
  }

  async listProfiles(): Promise<readonly ConnectionProfile[]> {
    const state = await this.loadState();
    return state.profiles.map((profile) => ({ ...profile }));
  }

  private async loadState(): Promise<ConnectionProfileState> {
    if (!this.fileSystem.supportsNoFollow) {
      return unavailableState();
    }

    let handle: LocalProfileRegistryFileHandle | undefined;
    try {
      const rootStats = await this.fileSystem.lstat(this.stateRoot);
      if (
        rootStats.isSymbolicLink() ||
        !rootStats.isDirectory() ||
        (this.operatorUid !== undefined && !isOperatorOwned(rootStats, this.operatorUid, true))
      ) {
        return unavailableState();
      }
      const rootPath = await this.fileSystem.realpath(this.stateRoot);

      handle = await this.fileSystem.openReadOnlyNoFollow(this.stateFile);
      const handleStats = await handle.stat();
      if (!handleStats.isFile() || (this.operatorUid !== undefined && !isOperatorOwned(handleStats, this.operatorUid, false))) {
        return unavailableState();
      }
      if (handleStats.size < 0 || handleStats.size > MAX_CONNECTION_PROFILE_STATE_BYTES) {
        return invalidState();
      }

      const rootAfterOpen = await this.fileSystem.lstat(this.stateRoot);
      if (
        rootAfterOpen.isSymbolicLink() ||
        !rootAfterOpen.isDirectory() ||
        !hasSameIdentity(rootStats, rootAfterOpen) ||
        (this.operatorUid !== undefined && !isOperatorOwned(rootAfterOpen, this.operatorUid, true))
      ) {
        return unavailableState();
      }
      if ((await this.fileSystem.realpath(this.stateRoot)) !== rootPath) {
        return unavailableState();
      }

      const fileAfterOpen = await this.fileSystem.lstat(this.stateFile);
      if (
        fileAfterOpen.isSymbolicLink() ||
        !fileAfterOpen.isFile() ||
        !hasSameIdentity(handleStats, fileAfterOpen) ||
        (this.operatorUid !== undefined && !isOperatorOwned(fileAfterOpen, this.operatorUid, false))
      ) {
        return unavailableState();
      }
      const statePath = await this.fileSystem.realpath(this.stateFile);
      if (!isWithin(rootPath, statePath) || relative(rootPath, statePath) !== CONNECTION_PROFILE_STATE_FILE) {
        return unavailableState();
      }

      const rawState = await this.readState(handle);
      let parsedState: unknown;
      try {
        parsedState = JSON.parse(rawState) as unknown;
      } catch {
        return invalidState();
      }
      return parseState(parsedState);
    } catch (error) {
      if (error instanceof LocalProfileRegistryError) {
        throw error;
      }
      return unavailableState();
    } finally {
      if (handle !== undefined) {
        try {
          await handle.close();
        } catch {
          // The state was already read through a verified descriptor; close errors cannot widen access.
        }
      }
    }
  }

  private async readState(handle: LocalProfileRegistryFileHandle): Promise<string> {
    const buffer = Buffer.allocUnsafe(MAX_CONNECTION_PROFILE_STATE_BYTES + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) {
        break;
      }
      bytesRead += result.bytesRead;
    }
    if (bytesRead > MAX_CONNECTION_PROFILE_STATE_BYTES) {
      return invalidState();
    }
    return buffer.toString('utf8', 0, bytesRead);
  }
}

/** A non-secret error suitable for callers to map to a fail-closed response. */
export class LocalProfileRegistryError extends Error {
  readonly code: 'invalid-state' | 'state-unavailable';

  constructor(code: 'invalid-state' | 'state-unavailable', message: string) {
    super(message);
    this.name = 'LocalProfileRegistryError';
    this.code = code;
  }
}
