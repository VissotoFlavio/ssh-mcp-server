import { assertApprovedHostIdentity, validatePolicyProfile, type ConnectionProfile } from '../policy/host-identity-credential-policy.js';

import { parseWindowsKnownHosts } from './windows-known-hosts.js';

export const WINDOWS_READINESS_STATUS_KIND = 'windows-readiness-status';
export const WINDOWS_READINESS_STATUS_VERSION = 1;
const MAX_READINESS_KNOWN_HOSTS_REFERENCES = 256;
const PROFILE_FIELDS = [
  'profileId',
  'host',
  'port',
  'user',
  'expectedHostFingerprint',
  'authMode',
  'approvedKnownHostsReference',
  'credentialReference',
] as const;

export type WindowsReadinessCheck = 'ready' | 'unavailable' | 'invalid' | 'not-checked';
export type WindowsRuntimeReadiness = 'ready' | 'unsupported';

/**
 * A deliberately small local-only report. Values are enums, not descriptions:
 * neither the report nor the provider interface can carry connection metadata.
 */
export interface WindowsReadinessStatus {
  readonly kind: typeof WINDOWS_READINESS_STATUS_KIND;
  readonly version: typeof WINDOWS_READINESS_STATUS_VERSION;
  readonly runtime: WindowsRuntimeReadiness;
  readonly registry: WindowsReadinessCheck;
  readonly filesystem: WindowsReadinessCheck;
  readonly configuration: WindowsReadinessCheck;
  readonly knownHosts: WindowsReadinessCheck;
  readonly credentials: 'ready' | 'unavailable' | 'not-checked';
  readonly validationProvider: WindowsReadinessCheck;
  readonly remoteAuthentication: 'not-checked';
}

export interface WindowsReadinessStatusProvider {
  getWindowsReadinessStatus(): Promise<WindowsReadinessStatus> | WindowsReadinessStatus;
}

export interface WindowsLocalReadinessProbe {
  inspectReadiness(): {
    readonly registry: 'ready' | 'unavailable';
    readonly filesystem: 'ready' | 'unavailable' | 'not-checked';
    readonly configuration: 'ready' | 'unavailable' | 'not-checked';
  };
  listProfiles(): readonly ConnectionProfile[];
  readKnownHosts(reference: string): Buffer;
  credentialAvailable(reference: string): boolean;
}

function unsupportedStatus(): WindowsReadinessStatus {
  return {
    kind: WINDOWS_READINESS_STATUS_KIND,
    version: WINDOWS_READINESS_STATUS_VERSION,
    runtime: 'unsupported',
    registry: 'not-checked',
    filesystem: 'not-checked',
    configuration: 'not-checked',
    knownHosts: 'not-checked',
    credentials: 'not-checked',
    validationProvider: 'not-checked',
    remoteAuthentication: 'not-checked',
  };
}

function unavailableStatus(): WindowsReadinessStatus {
  return {
    kind: WINDOWS_READINESS_STATUS_KIND,
    version: WINDOWS_READINESS_STATUS_VERSION,
    runtime: 'ready',
    registry: 'unavailable',
    filesystem: 'not-checked',
    configuration: 'not-checked',
    knownHosts: 'not-checked',
    credentials: 'not-checked',
    validationProvider: 'unavailable',
    remoteAuthentication: 'not-checked',
  };
}

function invalidConfigurationStatus(): WindowsReadinessStatus {
  return {
    ...unavailableStatus(),
    registry: 'ready',
    filesystem: 'ready',
    configuration: 'invalid',
  };
}

/**
 * Accept a fixed amount of plain trusted profile data and project it to unique
 * known-hosts references before inspecting any leaf. This keeps diagnostic
 * work bounded even if a provider violates its normal storage contract.
 */
function boundedProfiles(profiles: unknown):
  | {
      readonly profiles: readonly ConnectionProfile[];
      readonly knownHostsReferences: readonly string[];
      readonly credentialReferences: readonly string[];
    }
  | undefined {
  try {
    if (!Array.isArray(profiles) || Object.getPrototypeOf(profiles) !== Array.prototype) return undefined;
    const length = Object.getOwnPropertyDescriptor(profiles, 'length')?.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_READINESS_KNOWN_HOSTS_REFERENCES) return undefined;
    const keys = Reflect.ownKeys(profiles);
    if (keys.length !== length + 1 || !keys.includes('length')) return undefined;

    const safeProfiles: ConnectionProfile[] = [];
    const knownHostsReferences = new Set<string>();
    const credentialReferences = new Set<string>();
    for (let index = 0; index < length; index += 1) {
      const entry = Object.getOwnPropertyDescriptor(profiles, String(index));
      if (entry === undefined || !Object.prototype.hasOwnProperty.call(entry, 'value')) return undefined;
      const profile = entry.value;
      if (typeof profile !== 'object' || profile === null || Array.isArray(profile)) return undefined;
      const prototype = Object.getPrototypeOf(profile);
      if (prototype !== Object.prototype && prototype !== null) return undefined;
      const profileKeys = Reflect.ownKeys(profile);
      if (!profileKeys.every((key) => typeof key === 'string' && PROFILE_FIELDS.includes(key as (typeof PROFILE_FIELDS)[number]))) return undefined;

      const copy: Record<string, unknown> = {};
      for (const field of PROFILE_FIELDS) {
        const descriptor = Object.getOwnPropertyDescriptor(profile, field);
        if (descriptor === undefined) {
          if (field !== 'credentialReference') return undefined;
          continue;
        }
        if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) return undefined;
        copy[field] = descriptor.value;
      }
      const validated = validatePolicyProfile(copy);
      safeProfiles.push(validated);
      knownHostsReferences.add(validated.approvedKnownHostsReference);
      if (validated.authMode === 'password' && validated.credentialReference !== undefined) credentialReferences.add(validated.credentialReference);
    }
    return { profiles: safeProfiles, knownHostsReferences: [...knownHostsReferences], credentialReferences: [...credentialReferences] };
  } catch {
    return undefined;
  }
}

/**
 * Compose a local status probe without reading credentials or contacting a
 * remote host. Protected local known-hosts data is parsed only to verify its
 * approved identity and is never retained or returned.
 */
export function createWindowsReadinessStatusProvider(
  runtimeSupported: boolean,
  storage?: WindowsLocalReadinessProbe,
  validationProviderAvailable = false,
): WindowsReadinessStatusProvider {
  return {
    getWindowsReadinessStatus(): WindowsReadinessStatus {
      if (!runtimeSupported) return unsupportedStatus();
      if (storage === undefined) return unavailableStatus();

      let local;
      try {
        local = storage.inspectReadiness();
      } catch {
        return unavailableStatus();
      }
      if (local.registry !== 'ready') {
        return {
          ...unavailableStatus(),
          registry: 'unavailable',
        };
      }
      if (local.filesystem !== 'ready') {
        return {
          ...unavailableStatus(),
          registry: 'ready',
          filesystem: local.filesystem === 'unavailable' ? 'unavailable' : 'not-checked',
        };
      }
      if (local.configuration !== 'ready') {
        return {
          ...unavailableStatus(),
          registry: 'ready',
          filesystem: 'ready',
          configuration: local.configuration === 'unavailable' ? 'unavailable' : 'not-checked',
        };
      }

      let configured: ReturnType<typeof boundedProfiles>;
      try {
        configured = boundedProfiles(storage.listProfiles());
      } catch {
        return invalidConfigurationStatus();
      }
      if (configured === undefined) return invalidConfigurationStatus();

      let knownHosts: WindowsReadinessCheck = 'ready';
      try {
        const entriesByReference = new Map<string, ReturnType<typeof parseWindowsKnownHosts>>();
        for (const reference of configured.knownHostsReferences) {
          entriesByReference.set(
            reference,
            parseWindowsKnownHosts(storage.readKnownHosts(reference), () => {
              throw new TypeError('Known-hosts data is unavailable');
            }),
          );
        }
        for (const profile of configured.profiles) {
          const entries = entriesByReference.get(profile.approvedKnownHostsReference);
          if (entries === undefined) throw new TypeError('Known-hosts data is unavailable');
          assertApprovedHostIdentity(profile, entries);
        }
      } catch {
        knownHosts = 'unavailable';
      }

      let credentials: WindowsReadinessStatus['credentials'] = 'not-checked';
      if (configured.credentialReferences.length > 0) {
        try {
          credentials = configured.credentialReferences.every((reference) => storage.credentialAvailable(reference)) ? 'ready' : 'unavailable';
        } catch {
          credentials = 'unavailable';
        }
      }

      return {
        kind: WINDOWS_READINESS_STATUS_KIND,
        version: WINDOWS_READINESS_STATUS_VERSION,
        runtime: 'ready',
        registry: 'ready',
        filesystem: 'ready',
        configuration: 'ready',
        knownHosts,
        credentials,
        validationProvider: validationProviderAvailable ? 'ready' : 'unavailable',
        // This endpoint intentionally has no remote-access authority.
        remoteAuthentication: 'not-checked',
      };
    },
  };
}
