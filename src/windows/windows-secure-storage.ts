import { createRequire } from 'node:module';

import { parseCredentialReference } from '../credentials/credential-store.js';
import {
  WindowsExecutionAuditJournal,
  type ExecutionAuditFinished,
  type ExecutionAuditIntent,
  type ExecutionAuditJournal,
  type WindowsExecutionAuditBinding,
} from '../execution/execution-audit-journal.js';
import type { RemoteCommandTransportResult } from '../execution/remote-command-execution.js';
import { validateConnectionProfile, validateProfileSelection, type ConnectionProfile } from '../profiles/connection-profile.js';

import type { WindowsNativeAgentCommandRequest } from './windows-native-command.js';
import { supportsWindowsAlphaRuntime } from './windows-runtime-support.js';

const require = createRequire(import.meta.url);
const MAX_STATE_BYTES = 1024 * 1024;
const MAX_PROFILES = 256;
const KNOWN_HOSTS_REFERENCE = /^known-hosts:\/\/([a-z0-9]+(?:-[a-z0-9]+)*)$/u;

export interface WindowsTrustBinding {
  readProfileState(): Buffer;
  readKnownHosts(profileId: string): Buffer;
  inspectReadiness?(): unknown;
  captureKnownHostsSnapshot(profileId: string): { readonly bytes: Buffer; readonly capability: object };
  disposeKnownHostsSnapshot(capability: object): void;
  isKnownHostsSnapshotBusy(capability: object): boolean;
  execute?(capability: object, request: WindowsNativeAgentCommandRequest, signal?: AbortSignal): Promise<RemoteCommandTransportResult>;
  readCredential(locator: string): string;
  credentialAvailable?(locator: string): boolean;
  digestExecutionAuditArguments?(args: readonly string[]): string;
  appendExecutionAuditIntent?(intent: ExecutionAuditIntent): {
    readonly keyId: string;
    readonly previousEventHmac: string | null;
    readonly eventHmac: string;
  };
  appendExecutionAuditFinished?(event: ExecutionAuditFinished & { readonly operationId: string }): {
    readonly keyId: string;
    readonly previousEventHmac: string | null;
    readonly eventHmac: string;
  };
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
    typeof (candidate as { disposeKnownHostsSnapshot?: unknown }).disposeKnownHostsSnapshot !== 'function' ||
    typeof (candidate as { isKnownHostsSnapshotBusy?: unknown }).isKnownHostsSnapshotBusy !== 'function' ||
    typeof (candidate as { execute?: unknown }).execute !== 'function' ||
    typeof (candidate as { readCredential?: unknown }).readCredential !== 'function' ||
    typeof (candidate as { digestExecutionAuditArguments?: unknown }).digestExecutionAuditArguments !== 'function' ||
    typeof (candidate as { appendExecutionAuditIntent?: unknown }).appendExecutionAuditIntent !== 'function' ||
    typeof (candidate as { appendExecutionAuditFinished?: unknown }).appendExecutionAuditFinished !== 'function'
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

function validReadiness(value: unknown): value is {
  readonly registry: 'ready' | 'unavailable';
  readonly filesystem: 'ready' | 'unavailable' | 'not-checked';
  readonly configuration: 'ready' | 'unavailable' | 'not-checked';
} {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const registry = (value as { registry?: unknown }).registry;
  const filesystem = (value as { filesystem?: unknown }).filesystem;
  const configuration = (value as { configuration?: unknown }).configuration;
  return (
    keys.length === 3 &&
    keys.includes('registry') &&
    keys.includes('filesystem') &&
    keys.includes('configuration') &&
    (registry === 'ready' || registry === 'unavailable') &&
    (filesystem === 'ready' || filesystem === 'unavailable' || filesystem === 'not-checked') &&
    (configuration === 'ready' || configuration === 'unavailable' || configuration === 'not-checked')
  );
}

/**
 * Reads only fixed Windows trust anchors through the native boundary. Neither
 * roots nor filenames are accepted from MCP callers or environment variables.
 */
export class WindowsSecureStorage {
  readonly executionAuditJournal?: ExecutionAuditJournal;

  constructor(private readonly binding: WindowsTrustBinding = loadNativeBinding()) {
    if (
      typeof binding.digestExecutionAuditArguments === 'function' &&
      typeof binding.appendExecutionAuditIntent === 'function' &&
      typeof binding.appendExecutionAuditFinished === 'function'
    ) {
      this.executionAuditJournal = new WindowsExecutionAuditJournal(binding as WindowsExecutionAuditBinding);
    }
  }

  listProfiles(): readonly ConnectionProfile[] {
    try {
      return parseState(this.binding.readProfileState()).map((profile) => ({ ...profile }));
    } catch {
      return unavailable();
    }
  }

  /**
   * Returns only native, bounded prerequisite states. No configured value,
   * path, profile, key, or credential crosses this diagnostic boundary.
   */
  inspectReadiness(): {
    readonly registry: 'ready' | 'unavailable';
    readonly filesystem: 'ready' | 'unavailable' | 'not-checked';
    readonly configuration: 'ready' | 'unavailable' | 'not-checked';
  } {
    try {
      const inspect = this.binding.inspectReadiness;
      if (typeof inspect !== 'function') return { registry: 'unavailable', filesystem: 'not-checked', configuration: 'not-checked' };
      const result = inspect.call(this.binding);
      if (!validReadiness(result)) return unavailable();
      return { registry: result.registry, filesystem: result.filesystem, configuration: result.configuration };
    } catch {
      return unavailable();
    }
  }

  getProfile(profileId: string): ConnectionProfile | undefined {
    const selection = validateProfileSelection({ profileId });
    return this.listProfiles().find((profile) => profile.profileId === selection.profileId);
  }

  executeNativeAgentCommand(
    capability: object,
    request: WindowsNativeAgentCommandRequest,
    signal?: AbortSignal,
  ): Promise<RemoteCommandTransportResult> {
    if (this.binding.execute === undefined) return Promise.reject(new WindowsSecureStorageError());
    return this.binding.execute(capability, request, signal);
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
   * Checks only whether an approved Windows Generic Credential can be opened.
   * The native probe immediately frees the record and never routes its blob
   * through TypeScript.
   */
  credentialAvailable(reference: string): boolean {
    try {
      const parsed = parseCredentialReference(reference);
      const probe = this.binding.credentialAvailable;
      if (parsed.provider !== 'ssh' || typeof probe !== 'function') return unavailable();
      const available = probe.call(this.binding, parsed.locator);
      if (typeof available !== 'boolean') return unavailable();
      return available;
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
    const snapshot = this.captureKnownHostsSnapshot(reference);
    try {
      return await work(Buffer.from(snapshot.bytes), snapshot.capability);
    } finally {
      this.disposeKnownHostsSnapshot(snapshot.capability);
    }
  }

  captureKnownHostsSnapshot(reference: string): { readonly bytes: Buffer; readonly capability: object } {
    const profileId = snapshotProfileId(reference);
    try {
      const captured = this.binding.captureKnownHostsSnapshot(profileId);
      if (!validSnapshot(captured)) return unavailable();
      return { bytes: Buffer.from(captured.bytes), capability: captured.capability };
    } catch {
      return unavailable();
    }
  }

  disposeKnownHostsSnapshot(capability: object): void {
    try {
      this.binding.disposeKnownHostsSnapshot(capability);
    } catch {
      let busy = false;
      try {
        busy = this.binding.isKnownHostsSnapshotBusy(capability) === true;
      } catch {
        // A failed busy check is not an ownership transfer.
      }
      if (!busy) unavailable();
    }
  }
}
