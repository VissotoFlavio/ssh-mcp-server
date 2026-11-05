import { createRequire } from 'node:module';

import { validateConnectionProfile, validateProfileSelection, type ConnectionProfile } from '../profiles/connection-profile.js';

import { supportsWindowsAlphaRuntime } from './windows-runtime-support.js';

const require = createRequire(import.meta.url);
const MAX_STATE_BYTES = 1024 * 1024;
const MAX_PROFILES = 256;
const KNOWN_HOSTS_REFERENCE = /^known-hosts:\/\/([a-z0-9]+(?:-[a-z0-9]+)*)$/u;

export interface WindowsTrustBinding {
  readProfileState(): Buffer;
  readKnownHosts(profileId: string): Buffer;
  captureKnownHostsSnapshot(profileId: string): { readonly bytes: Buffer; readonly capability: object };
  disposeKnownHostsSnapshot(capability: object): void;
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

function loadNativeBinding(): WindowsTrustBinding {
  if (!supportsWindowsAlphaRuntime()) {
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
    typeof (candidate as { readKnownHosts?: unknown }).readKnownHosts !== 'function' ||
    typeof (candidate as { captureKnownHostsSnapshot?: unknown }).captureKnownHostsSnapshot !== 'function' ||
    typeof (candidate as { disposeKnownHostsSnapshot?: unknown }).disposeKnownHostsSnapshot !== 'function'
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

function snapshotProfileId(reference: string): string {
  const match = KNOWN_HOSTS_REFERENCE.exec(reference);
  if (match === null) return unavailable();
  return match[1];
}

function validSnapshot(value: unknown): value is { readonly bytes: Buffer; readonly capability: object } {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const bytes = (value as { bytes?: unknown }).bytes;
  const capability = (value as { capability?: unknown }).capability;
  return (
    keys.length === 2 &&
    keys.includes('bytes') &&
    keys.includes('capability') &&
    Buffer.isBuffer(bytes) &&
    bytes.byteLength > 0 &&
    bytes.byteLength <= MAX_STATE_BYTES &&
    typeof capability === 'object' &&
    capability !== null &&
    !Array.isArray(capability)
  );
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
    const profileId = snapshotProfileId(reference);
    try {
      const value = this.binding.readKnownHosts(profileId);
      if (!Buffer.isBuffer(value) || value.byteLength === 0 || value.byteLength > MAX_STATE_BYTES) return unavailable();
      return Buffer.from(value);
    } catch {
      return unavailable();
    }
  }

  /**
   * Gives work a copy of native-captured known-hosts bytes and always disposes
   * the opaque native snapshot afterwards. The snapshot pathname never enters
   * TypeScript or an SSH child command.
   */
  async withKnownHostsSnapshot<T>(reference: string, work: (bytes: Buffer, capability: object) => Promise<T>): Promise<T> {
    const profileId = snapshotProfileId(reference);
    let snapshot: { readonly bytes: Buffer; readonly capability: object };
    try {
      const captured = this.binding.captureKnownHostsSnapshot(profileId);
      if (!validSnapshot(captured)) return unavailable();
      snapshot = captured;
    } catch {
      return unavailable();
    }
    try {
      return await work(Buffer.from(snapshot.bytes), snapshot.capability);
    } finally {
      try {
        this.binding.disposeKnownHostsSnapshot(snapshot.capability);
      } catch {
        unavailable();
      }
    }
  }
}
