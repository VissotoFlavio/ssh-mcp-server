import { HostIdentityCredentialPolicy } from '../policy/host-identity-credential-policy.js';
import { validateProfileSelection, type ConnectionProfile } from '../profiles/connection-profile.js';

import { WindowsCredentialManager } from './windows-credential-manager.js';
import { parseWindowsKnownHosts } from './windows-known-hosts.js';
import { WindowsNativeAgentReadiness } from './windows-native-agent-readiness.js';
import { WindowsOpenSshResolver, WindowsSshAddIdentity } from './windows-openssh.js';
import { WindowsInMemoryPasswordTransport, type WindowsPasswordValidationRequest } from './windows-password-transport.js';
import { WindowsSecureStorage } from './windows-secure-storage.js';

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;

export class WindowsValidationSessionError extends Error {
  constructor() {
    super('Windows connection validation is unavailable');
    this.name = 'WindowsValidationSessionError';
  }
}

function unavailable(): never {
  throw new WindowsValidationSessionError();
}

function boundedTimeout(value: number | undefined): number {
  return Number.isInteger(value) && value !== undefined && value > 0 && value <= MAX_TIMEOUT_MS ? value : DEFAULT_TIMEOUT_MS;
}

export interface WindowsPasswordReadinessTransport {
  connect(request: WindowsPasswordValidationRequest, signal?: AbortSignal): Promise<void>;
}

export interface WindowsValidationSessionDependencies {
  readonly storage: Pick<WindowsSecureStorage, 'getProfile' | 'readKnownHosts' | 'withKnownHostsSnapshot'> &
    Partial<Pick<WindowsSecureStorage, 'captureKnownHostsSnapshot' | 'disposeKnownHostsSnapshot'>>;
  readonly agentIdentity: { isAvailable(timeoutMs?: number, signal?: AbortSignal): boolean | Promise<boolean> };
  readonly agentReadiness: Pick<WindowsNativeAgentReadiness, 'validate'>;
  readonly createPasswordTransport: (approvedReference: string) => WindowsPasswordReadinessTransport;
  readonly timeoutMs?: number;
}

function defaultDependencies(
  storage: Pick<WindowsSecureStorage, 'getProfile' | 'readKnownHosts' | 'withKnownHostsSnapshot'> = new WindowsSecureStorage(),
): WindowsValidationSessionDependencies {
  const timeoutMs = DEFAULT_TIMEOUT_MS;
  return {
    storage,
    agentIdentity: {
      isAvailable: async (remainingMs, signal) =>
        new WindowsSshAddIdentity(new WindowsOpenSshResolver(), remainingMs ?? timeoutMs).isAvailable(signal),
    },
    agentReadiness: new WindowsNativeAgentReadiness(),
    createPasswordTransport: (approvedReference) =>
      new WindowsInMemoryPasswordTransport(new WindowsCredentialManager(undefined, [approvedReference])),
    timeoutMs,
  };
}

/**
 * Internal Windows validation composition. It has no MCP-facing provider:
 * native snapshots intentionally do not reveal a pathname, and agent-key
 * readiness needs a native consumer for that opaque capability. Password
 * readiness can safely use the captured bytes in the in-process transport.
 */
export class WindowsValidationSession {
  private readonly timeoutMs: number;

  constructor(private readonly dependencies: WindowsValidationSessionDependencies = defaultDependencies()) {
    this.timeoutMs = boundedTimeout(dependencies.timeoutMs);
  }

  async validate(input: unknown, signal?: AbortSignal): Promise<void> {
    const started = Date.now();
    const remaining = (): number => {
      if (signal?.aborted) return 0;
      return Math.max(0, this.timeoutMs - (Date.now() - started));
    };
    if (remaining() === 0) return unavailable();
    const selection = validateProfileSelection(input);
    const profile = this.dependencies.storage.getProfile(selection.profileId);
    if (profile === undefined) return unavailable();

    // Password validation never passes a known-hosts pathname to a child
    // process. The verified bytes can therefore remain in memory, avoiding a
    // temporary snapshot while preserving host-key verification before any
    // credential lookup.
    if (profile.authMode === 'password') {
      if (remaining() === 0) return unavailable();
      const entries = parseWindowsKnownHosts(this.dependencies.storage.readKnownHosts(profile.approvedKnownHostsReference), unavailable);
      const policy = new HostIdentityCredentialPolicy({
        profiles: { getProfile: (profileId) => (profileId === selection.profileId ? profile : undefined) },
        knownHosts: {
          getEntries: (reference) => (reference === profile.approvedKnownHostsReference ? entries : unavailable()),
        },
        agentIdentity: { isAvailable: () => this.dependencies.agentIdentity.isAvailable(remaining(), signal) },
        credentialResolver: {
          isApproved: (reference) => reference === profile.credentialReference,
        },
      });
      const authorized = await policy.authorize(selection);
      if (authorized.authentication.mode !== 'password' || remaining() === 0) return unavailable();

      await this.dependencies.createPasswordTransport(authorized.authentication.credentialReference).connect(
        {
          host: authorized.profile.host,
          port: authorized.profile.port,
          user: authorized.profile.user,
          expectedHostFingerprint: authorized.hostIdentity.fingerprint,
          credentialReference: authorized.authentication.credentialReference,
          timeoutMs: remaining(),
        },
        signal,
      );
      return;
    }

    await this.dependencies.storage.withKnownHostsSnapshot(profile.approvedKnownHostsReference, async (bytes, capability) => {
      if (remaining() === 0) return unavailable();
      const entries = parseWindowsKnownHosts(bytes, unavailable);
      const policy = new HostIdentityCredentialPolicy({
        profiles: { getProfile: (profileId) => (profileId === selection.profileId ? profile : undefined) },
        knownHosts: {
          getEntries: (reference) => (reference === profile.approvedKnownHostsReference ? entries : unavailable()),
        },
        agentIdentity: { isAvailable: () => this.dependencies.agentIdentity.isAvailable(remaining(), signal) },
        credentialResolver: {
          isApproved: (reference) => profile.authMode === 'password' && reference === profile.credentialReference,
        },
      });
      const authorized = await policy.authorize(selection);
      if (authorized.authentication.mode === 'agent-key') {
        if (remaining() === 0) return unavailable();
        await this.dependencies.agentReadiness.validate(
          capability,
          Object.freeze({ host: authorized.profile.host, port: authorized.profile.port, user: authorized.profile.user }),
          remaining(),
          signal,
        );
        return;
      }
      if (authorized.authentication.mode !== 'password' || remaining() === 0) return unavailable();

      await this.dependencies.createPasswordTransport(authorized.authentication.credentialReference).connect(
        {
          host: authorized.profile.host,
          port: authorized.profile.port,
          user: authorized.profile.user,
          expectedHostFingerprint: authorized.hostIdentity.fingerprint,
          credentialReference: authorized.authentication.credentialReference,
          timeoutMs: remaining(),
        },
        signal,
      );
    });
  }

  /**
   * Validates one immutable execution plan and retains the exact native
   * snapshot used by agent-key readiness until the caller releases the lease.
   */
  async authorize(
    input: unknown,
    signal?: AbortSignal,
  ): Promise<{
    readonly profile: ConnectionProfile;
    readonly withTransportContext?: <T>(work: (context: object) => Promise<T>) => Promise<T>;
    readonly release?: () => Promise<void>;
  }> {
    const started = Date.now();
    const remaining = (): number => {
      if (signal?.aborted) return 0;
      return Math.max(0, this.timeoutMs - (Date.now() - started));
    };
    if (remaining() === 0) return unavailable();
    const selection = validateProfileSelection(input);
    const profile = this.dependencies.storage.getProfile(selection.profileId);
    if (profile === undefined) return unavailable();

    if (profile.authMode === 'password') {
      if (remaining() === 0) return unavailable();
      const entries = parseWindowsKnownHosts(this.dependencies.storage.readKnownHosts(profile.approvedKnownHostsReference), unavailable);
      const policy = new HostIdentityCredentialPolicy({
        profiles: { getProfile: (profileId) => (profileId === selection.profileId ? profile : undefined) },
        knownHosts: {
          getEntries: (reference) => (reference === profile.approvedKnownHostsReference ? entries : unavailable()),
        },
        agentIdentity: { isAvailable: () => this.dependencies.agentIdentity.isAvailable(remaining(), signal) },
        credentialResolver: { isApproved: (reference) => reference === profile.credentialReference },
      });
      const authorized = await policy.authorize(selection);
      if (authorized.authentication.mode !== 'password' || remaining() === 0) return unavailable();
      await this.dependencies.createPasswordTransport(authorized.authentication.credentialReference).connect(
        {
          host: authorized.profile.host,
          port: authorized.profile.port,
          user: authorized.profile.user,
          expectedHostFingerprint: authorized.hostIdentity.fingerprint,
          credentialReference: authorized.authentication.credentialReference,
          timeoutMs: remaining(),
        },
        signal,
      );
      return { profile: authorized.profile };
    }

    const capture = this.dependencies.storage.captureKnownHostsSnapshot;
    const dispose = this.dependencies.storage.disposeKnownHostsSnapshot;
    if (capture === undefined || dispose === undefined) return unavailable();
    const snapshot = capture.call(this.dependencies.storage, profile.approvedKnownHostsReference);
    let released = false;
    const release = async (): Promise<void> => {
      if (released) return;
      released = true;
      dispose.call(this.dependencies.storage, snapshot.capability);
    };
    try {
      if (remaining() === 0) return unavailable();
      const entries = parseWindowsKnownHosts(snapshot.bytes, unavailable);
      const policy = new HostIdentityCredentialPolicy({
        profiles: { getProfile: (profileId) => (profileId === selection.profileId ? profile : undefined) },
        knownHosts: {
          getEntries: (reference) => (reference === profile.approvedKnownHostsReference ? entries : unavailable()),
        },
        agentIdentity: { isAvailable: () => this.dependencies.agentIdentity.isAvailable(remaining(), signal) },
        credentialResolver: { isApproved: () => false },
      });
      const authorized = await policy.authorize(selection);
      if (authorized.authentication.mode !== 'agent-key' || remaining() === 0) return unavailable();
      await this.dependencies.agentReadiness.validate(
        snapshot.capability,
        Object.freeze({ host: authorized.profile.host, port: authorized.profile.port, user: authorized.profile.user }),
        remaining(),
        signal,
      );
      return {
        profile: authorized.profile,
        withTransportContext: async <T>(work: (context: object) => Promise<T>): Promise<T> => work(snapshot.capability),
        release,
      };
    } catch (error) {
      await release();
      throw error;
    }
  }
}

export function createWindowsValidationSession(
  storage: Pick<WindowsSecureStorage, 'getProfile' | 'readKnownHosts' | 'withKnownHostsSnapshot'> &
    Partial<Pick<WindowsSecureStorage, 'captureKnownHostsSnapshot' | 'disposeKnownHostsSnapshot'>>,
): WindowsValidationSession {
  return new WindowsValidationSession(defaultDependencies(storage));
}
