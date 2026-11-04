import { createRequire } from 'node:module';
import { release } from 'node:os';

import { validateConnectionProfile, validateProfileSelection, type ConnectionProfile } from '../profiles/connection-profile.js';

const require = createRequire(import.meta.url);
const MAX_STATE_BYTES = 1024 * 1024;
const MAX_PROFILES = 256;
const KNOWN_HOSTS_REFERENCE = /^known-hosts:\/\/([a-z0-9]+(?:-[a-z0-9]+)*)$/u;

export interface WindowsTrustBinding {
  readProfileState(): Buffer;
  readKnownHosts(profileId: string): Buffer;
}

export class WindowsSecureStorageError extends Error {
  constructor() {
    super('Windows secure storage is unavailable');
    this.name = 'WindowsSecureStorageError';
  }
}

function unavailable(): never {
  throw new WindowsSecureStorageError();
}

function supportedWindowsRuntime(): boolean {
  if (process.platform !== 'win32' || process.arch !== 'x64') return false;
  const nodeMajor = Number.parseInt(process.versions.node.split('.')[0] ?? '', 10);
  const windowsBuild = Number.parseInt(release().split('.')[2] ?? '', 10);
  return Number.isSafeInteger(nodeMajor) && nodeMajor >= 22 && Number.isSafeInteger(windowsBuild) && windowsBuild >= 20_348;
}

function loadNativeBinding(): WindowsTrustBinding {
  if (!supportedWindowsRuntime()) {
    return unavailable();
  }

  let candidate: unknown;
  try {
    candidate = require('../../build/Release/windows_trust.node');
  } catch {
    return unavailable();
  }
  if (
    typeof candidate !== 'object' ||
    candidate === null ||
    typeof (candidate as { readProfileState?: unknown }).readProfileState !== 'function' ||
    typeof (candidate as { readKnownHosts?: unknown }).readKnownHosts !== 'function'
  ) {
    return unavailable();
  }
  return candidate as WindowsTrustBinding;
}

function parseState(value: Buffer): readonly ConnectionProfile[] {
  if (!Buffer.isBuffer(value) || value.byteLength > MAX_STATE_BYTES) {
    return unavailable();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value.toString('utf8')) as unknown;
  } catch {
    return unavailable();
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) || Object.getPrototypeOf(parsed) !== Object.prototype) {
    return unavailable();
  }
  const keys = Reflect.ownKeys(parsed);
  if (keys.length !== 1 || keys[0] !== 'profiles' || !Array.isArray((parsed as { profiles?: unknown }).profiles)) {
    return unavailable();
  }
  const profiles = (parsed as { profiles: unknown[] }).profiles;
  if (profiles.length > MAX_PROFILES) {
    return unavailable();
  }
  const ids = new Set<string>();
  try {
    return profiles.map((profile) => {
      const valid = validateConnectionProfile(profile);
      if (ids.has(valid.profileId)) return unavailable();
      ids.add(valid.profileId);
      return valid;
    });
  } catch {
    return unavailable();
  }
}

/**
 * Reads only fixed Windows trust anchors through the native boundary. Neither
 * roots nor filenames are accepted from MCP callers or environment variables.
 */
export class WindowsSecureStorage {
  constructor(private readonly binding: WindowsTrustBinding = loadNativeBinding()) {}

  listProfiles(): readonly ConnectionProfile[] {
    try {
      return parseState(this.binding.readProfileState()).map((profile) => ({ ...profile }));
    } catch {
      return unavailable();
    }
  }

  getProfile(profileId: string): ConnectionProfile | undefined {
    const selection = validateProfileSelection({ profileId });
    return this.listProfiles().find((profile) => profile.profileId === selection.profileId);
  }

  readKnownHosts(reference: string): Buffer {
    const match = KNOWN_HOSTS_REFERENCE.exec(reference);
    if (match === null) return unavailable();
    try {
      const value = this.binding.readKnownHosts(match[1]);
      if (!Buffer.isBuffer(value) || value.byteLength === 0 || value.byteLength > MAX_STATE_BYTES) return unavailable();
      return Buffer.from(value);
    } catch {
      return unavailable();
    }
  }
}
