import { mapConnectionError, type ConnectionDiagnosticCode, type ConnectionDiagnosticOutcome } from '../diagnostics/redacted-diagnostics-audit.js';
import {
  HostIdentityCredentialPolicyError,
  validatePolicyProfile,
  type AuthorizedConnection,
  type ConnectionProfile,
  type HostIdentityCredentialPolicy,
} from '../policy/host-identity-credential-policy.js';
import { validateProfileSelection } from '../profiles/connection-profile.js';

/** The narrow readiness boundary implemented by a trusted host integration. */
export interface ConnectionReadinessAdapter {
  connect(authorized: AuthorizedConnection, signal?: AbortSignal): Promise<void>;
  authorize?(authorized: AuthorizedConnection, signal?: AbortSignal): Promise<ValidatedConnectionAuthorization>;
}

/**
 * Trusted boundary consumed by the MCP server.  It receives a selection only;
 * connection configuration is resolved by the policy and readiness adapter.
 */
export interface ConnectionValidationProvider {
  validateConnection(input: unknown, signal?: AbortSignal): Promise<ConnectionValidationOutcome>;
  /** Internal execution lease; never exposed by the MCP response projection. */
  authorizeExecution?(input: unknown, signal?: AbortSignal): Promise<ValidatedConnectionAuthorization>;
}

export interface ValidatedConnectionAuthorization {
  readonly profile: ConnectionProfile;
  readonly withTransportContext?: <T>(work: (context: object) => Promise<T>) => Promise<T>;
  readonly release?: () => Promise<void>;
}

/** Deliberately small, non-secret result that can cross the MCP boundary. */
export interface ConnectionValidationOutcome {
  readonly profileId: string;
  readonly ready: true;
}

export interface TrustedConnectionValidationDependencies {
  readonly policy: Pick<HostIdentityCredentialPolicy, 'authorize'>;
  readonly readinessAdapter: ConnectionReadinessAdapter;
}

export interface ConnectionValidationFailure {
  readonly ready: false;
  readonly outcome: ConnectionDiagnosticOutcome;
  readonly code: ConnectionDiagnosticCode;
}

function invalidDependencies(): never {
  throw new TypeError('Trusted connection validation dependencies are unavailable');
}

function isPolicy(value: unknown): value is Pick<HostIdentityCredentialPolicy, 'authorize'> {
  return typeof value === 'object' && value !== null && typeof (value as { authorize?: unknown }).authorize === 'function';
}

function isReadinessAdapter(value: unknown): value is ConnectionReadinessAdapter {
  return typeof value === 'object' && value !== null && typeof (value as { connect?: unknown }).connect === 'function';
}

function invalidAuthorization(): never {
  throw new HostIdentityCredentialPolicyError('invalid-profile', 'Authorized connection is invalid');
}

/** Copy the policy output into a frozen plan before it crosses into readiness. */
function bindAuthorizedConnection(value: unknown, selectedProfileId: string): AuthorizedConnection {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return invalidAuthorization();
  }
  const authorized = value as AuthorizedConnection;
  const profile = validatePolicyProfile(authorized.profile);
  if (profile.profileId !== selectedProfileId || authorized.knownHostsReference !== profile.approvedKnownHostsReference) {
    return invalidAuthorization();
  }
  const hostIdentity = authorized.hostIdentity;
  if (
    !hostIdentity ||
    hostIdentity.host !== profile.host ||
    hostIdentity.port !== profile.port ||
    hostIdentity.fingerprint !== profile.expectedHostFingerprint
  ) {
    return invalidAuthorization();
  }
  const authentication = authorized.authentication;
  if (
    !authentication ||
    (authentication.mode === 'agent-key' && profile.authMode !== 'agent-key') ||
    (authentication.mode === 'password' && (profile.authMode !== 'password' || authentication.credentialReference !== profile.credentialReference)) ||
    (authentication.mode !== 'agent-key' && authentication.mode !== 'password')
  ) {
    return invalidAuthorization();
  }
  const bound = {
    profile: Object.freeze({ ...profile }),
    knownHostsReference: profile.approvedKnownHostsReference,
    hostIdentity: Object.freeze({ host: profile.host, port: profile.port, fingerprint: profile.expectedHostFingerprint }),
    authentication: Object.freeze(
      authentication.mode === 'agent-key'
        ? { mode: 'agent-key' as const }
        : { mode: 'password' as const, credentialReference: profile.credentialReference! },
    ),
  };
  return Object.freeze(bound);
}

/**
 * Compose the authorization policy with an SSH readiness adapter.  The policy
 * always runs before OpenSSH is invoked. Readiness receives only an immutable
 * policy result, never the caller selection or a second profile provider.
 */
export function createTrustedConnectionValidationProvider(dependencies: TrustedConnectionValidationDependencies): ConnectionValidationProvider {
  if (!dependencies || !isPolicy(dependencies.policy) || !isReadinessAdapter(dependencies.readinessAdapter)) {
    return invalidDependencies();
  }

  const authorizeExecution = async (input: unknown, signal?: AbortSignal): Promise<ValidatedConnectionAuthorization> => {
    const selection = validateProfileSelection(input);
    if (signal?.aborted) throw new Error('Connection validation cancelled');
    const authorized = bindAuthorizedConnection(await dependencies.policy.authorize(selection), selection.profileId);
    if (dependencies.readinessAdapter.authorize !== undefined) return dependencies.readinessAdapter.authorize(authorized, signal);
    await dependencies.readinessAdapter.connect(authorized, signal);
    if (signal?.aborted) throw new Error('Connection validation cancelled');
    return { profile: authorized.profile };
  };

  return {
    async validateConnection(input: unknown, signal?: AbortSignal): Promise<ConnectionValidationOutcome> {
      const authorization = await authorizeExecution(input, signal);
      await authorization.release?.();
      return { profileId: authorization.profile.profileId, ready: true };
    },
    authorizeExecution,
  };
}

/** Project arbitrary dependency failures onto a fixed public allowlist. */
export function toConnectionValidationFailure(error: unknown): ConnectionValidationFailure {
  const diagnostic = mapConnectionError(error);
  return { ready: false, outcome: diagnostic.outcome, code: diagnostic.code };
}
