import { createHash } from 'node:crypto';

import { HostIdentityCredentialPolicy, type ApprovedKnownHostsEntry } from '../policy/host-identity-credential-policy.js';
import { validateProfileSelection } from '../profiles/connection-profile.js';

import { WindowsCredentialManager } from './windows-credential-manager.js';
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

function parseKnownHosts(bytes: Buffer): readonly ApprovedKnownHostsEntry[] {
  const contents = bytes.toString('utf8');
  if (!Buffer.from(contents, 'utf8').equals(bytes)) return unavailable();

  const entries: ApprovedKnownHostsEntry[] = [];
  for (const line of contents.split(/\r?\n/u)) {
    const value = line.trim();
    if (value === '' || value.startsWith('#')) continue;
    const fields = value.split(/\s+/u);
    const endpoint = /^(?:\[([^\]]+)\]:(\d+)|([A-Za-z0-9.-]+))$/u.exec(fields[0] ?? '');
    const encodedKey = fields[2];
    if (
      fields.length !== 3 ||
      endpoint === null ||
      !/^[A-Za-z0-9@._+-]+$/u.test(fields[1] ?? '') ||
      !/^[A-Za-z0-9+/]+={0,2}$/u.test(encodedKey ?? '')
    ) {
      return unavailable();
    }
    const key = Buffer.from(encodedKey, 'base64');
    const host = endpoint[1] ?? endpoint[3];
    const port = endpoint[2] === undefined ? 22 : Number(endpoint[2]);
    if (host === undefined || key.byteLength === 0 || !Number.isInteger(port) || port < 1 || port > 65_535) return unavailable();
    entries.push({
      host,
      port,
      fingerprint: `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`,
    });
  }
  return entries;
}

export interface WindowsPasswordReadinessTransport {
  connect(request: WindowsPasswordValidationRequest): Promise<void>;
}

export interface WindowsValidationSessionDependencies {
  readonly storage: Pick<WindowsSecureStorage, 'getProfile' | 'withKnownHostsSnapshot'>;
  readonly agentIdentity: Pick<WindowsSshAddIdentity, 'isAvailable'>;
  readonly agentReadiness: Pick<WindowsNativeAgentReadiness, 'validate'>;
  readonly createPasswordTransport: (approvedReference: string) => WindowsPasswordReadinessTransport;
  readonly timeoutMs?: number;
}

function defaultDependencies(): WindowsValidationSessionDependencies {
  const storage = new WindowsSecureStorage();
  const timeoutMs = DEFAULT_TIMEOUT_MS;
  return {
    storage,
    agentIdentity: new WindowsSshAddIdentity(new WindowsOpenSshResolver(), timeoutMs),
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

  async validate(input: unknown): Promise<void> {
    const selection = validateProfileSelection(input);
    const profile = this.dependencies.storage.getProfile(selection.profileId);
    if (profile === undefined) return unavailable();

    await this.dependencies.storage.withKnownHostsSnapshot(profile.approvedKnownHostsReference, async (bytes, capability) => {
      const entries = parseKnownHosts(bytes);
      const policy = new HostIdentityCredentialPolicy({
        profiles: { getProfile: (profileId) => (profileId === selection.profileId ? profile : undefined) },
        knownHosts: {
          getEntries: (reference) => (reference === profile.approvedKnownHostsReference ? entries : unavailable()),
        },
        agentIdentity: this.dependencies.agentIdentity,
        credentialResolver: {
          isApproved: (reference) => profile.authMode === 'password' && reference === profile.credentialReference,
        },
      });
      const authorized = await policy.authorize(selection);
      if (authorized.authentication.mode === 'agent-key') {
        const descriptor = Object.freeze({
          host: authorized.profile.host,
          port: authorized.profile.port,
          user: authorized.profile.user,
        });
        this.dependencies.agentReadiness.validate(capability, descriptor, this.timeoutMs);
        return;
      }

      await this.dependencies.createPasswordTransport(authorized.authentication.credentialReference).connect({
        host: authorized.profile.host,
        port: authorized.profile.port,
        user: authorized.profile.user,
        expectedHostFingerprint: authorized.hostIdentity.fingerprint,
        credentialReference: authorized.authentication.credentialReference,
        timeoutMs: this.timeoutMs,
      });
    });
  }
}
