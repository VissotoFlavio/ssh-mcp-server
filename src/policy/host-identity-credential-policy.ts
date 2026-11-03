/**
 * Boundary policy for an approved SSH connection.
 *
 * This module deliberately does not open SSH connections, read files, invoke
 * credential-store commands, or return secret material. Adapters can implement
 * the small provider contracts below without widening the MCP input surface.
 */

export type AuthenticationMode = 'agent-key' | 'password';

export interface ConnectionProfile {
  readonly profileId: string;
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly expectedHostFingerprint: string;
  readonly authMode: AuthenticationMode;
  readonly approvedKnownHostsReference: string;
  readonly credentialReference?: string;
}

export interface ApprovedKnownHostsEntry {
  readonly host: string;
  readonly port: number;
  readonly fingerprint: string;
}

export interface ApprovedKnownHostsProvider {
  /** Return parsed, operator-approved entries for an opaque reference. */
  getEntries(reference: string): readonly ApprovedKnownHostsEntry[] | Promise<readonly ApprovedKnownHostsEntry[]>;
}

export interface AgentIdentityAvailability {
  /** Do not return key material; only report whether an identity is available. */
  isAvailable(): boolean | Promise<boolean>;
}

export interface CredentialReferenceApproval {
  /** Approve an opaque reference without returning the credential. */
  isApproved(reference: string): boolean | Promise<boolean>;
}

export interface HostIdentityCredentialPolicyDependencies {
  readonly knownHosts: ApprovedKnownHostsProvider;
  readonly agentIdentity: AgentIdentityAvailability;
  readonly credentialResolver: CredentialReferenceApproval;
}

export interface AuthorizedConnection {
  readonly profile: ConnectionProfile;
  readonly knownHostsReference: string;
  readonly hostIdentity: ApprovedKnownHostsEntry;
  readonly authentication:
    | { readonly mode: 'agent-key' }
    | { readonly mode: 'password'; readonly credentialReference: string };
}

export type HostIdentityCredentialPolicyErrorCode =
  | 'invalid-profile'
  | 'invalid-known-hosts-reference'
  | 'known-hosts-unavailable'
  | 'known-hosts-entry-missing'
  | 'known-hosts-entry-mismatch'
  | 'known-hosts-entry-ambiguous'
  | 'agent-identity-unavailable'
  | 'credential-reference-missing'
  | 'credential-reference-unapproved'
  | 'credential-resolver-unavailable';

const SECRET_FIELDS = new Set([
  'password',
  'passphrase',
  'privateKey',
  'privateKeyContent',
  'privateKeyPath',
  'privateKeyFile',
  'secret',
  'token',
]);

const PROFILE_FIELDS = new Set([
  'profileId',
  'host',
  'port',
  'user',
  'expectedHostFingerprint',
  'authMode',
  'approvedKnownHostsReference',
  'credentialReference',
]);

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const WILDCARD_CHARACTERS = /[*?\[\]]/u;
const PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const KNOWN_HOSTS_REFERENCE = /^known-hosts:\/\/[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const CREDENTIAL_REFERENCE = /^os:\/\/([a-z][a-z0-9-]{0,31})\/([a-z0-9][a-z0-9._:-]{0,127})$/u;
const SECRET_CREDENTIAL_LOCATOR = /^(?:password|passphrase|private[._-]*key|secret|token)$/iu;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function fail(code: HostIdentityCredentialPolicyErrorCode, message: string): never {
  throw new HostIdentityCredentialPolicyError(code, message);
}

function rejectFields(value: Record<string, unknown>): void {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      fail('invalid-profile', 'Connection profile contains an unexpected field');
    }
    if (SECRET_FIELDS.has(key)) {
      fail('invalid-profile', 'Secret material fields are not accepted');
    }
    if (!PROFILE_FIELDS.has(key)) {
      fail('invalid-profile', 'Connection profile contains an unexpected field');
    }
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null) {
    for (const key of Reflect.ownKeys(prototype)) {
      if (typeof key !== 'string') {
        continue;
      }
      if (SECRET_FIELDS.has(key)) {
        fail('invalid-profile', 'Secret material fields are not accepted');
      }
      if (PROFILE_FIELDS.has(key)) {
        fail('invalid-profile', 'Connection profile contains an unexpected inherited field');
      }
    }
  }
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    fail('invalid-profile', `Connection profile field ${field} is required`);
  }
  if (CONTROL_CHARACTERS.test(value)) {
    fail('invalid-profile', 'Connection profile contains forbidden control characters');
  }
  return value;
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requiredString(value, field);
}

function own(value: Record<string, unknown>, field: string): unknown {
  return Object.prototype.hasOwnProperty.call(value, field) ? value[field] : undefined;
}

function validateProfileId(value: unknown): string {
  const profileId = requiredString(value, 'profileId');
  if (!PROFILE_ID.test(profileId) || profileId === 'constructor' || profileId === 'prototype' || profileId === '__proto__') {
    fail('invalid-profile', 'Connection profile field profileId is invalid');
  }
  return profileId;
}

function validateHost(value: unknown): string {
  const host = requiredString(value, 'host');
  if (WILDCARD_CHARACTERS.test(host)) {
    fail('invalid-profile', 'Connection profile host cannot contain wildcard characters');
  }
  return host;
}

function validateReference(value: unknown): string {
  const reference = requiredString(value, 'approvedKnownHostsReference');
  if (!KNOWN_HOSTS_REFERENCE.test(reference)) {
    fail('invalid-known-hosts-reference', 'Approved known-hosts reference is invalid');
  }
  return reference;
}

function validateCredentialReference(value: unknown): string | undefined {
  const reference = optionalString(value, 'credentialReference');
  if (reference === undefined) {
    return undefined;
  }
  const match = CREDENTIAL_REFERENCE.exec(reference);
  const locator = match?.[2];
  if (
    match === null ||
    locator === undefined ||
    locator === '.' ||
    locator === '..' ||
    locator.includes('..') ||
    SECRET_CREDENTIAL_LOCATOR.test(locator)
  ) {
    fail('invalid-profile', 'Credential reference is invalid');
  }
  return reference;
}

/** Validate and normalize the non-secret profile accepted by this policy. */
export function validatePolicyProfile(input: unknown): ConnectionProfile {
  if (!isPlainRecord(input)) {
    fail('invalid-profile', 'Connection profile must be an object');
  }
  rejectFields(input);

  const authMode = own(input, 'authMode');
  if (authMode !== 'agent-key' && authMode !== 'password') {
    fail('invalid-profile', 'Connection profile authentication mode is invalid');
  }

  const port = own(input, 'port');
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) {
    fail('invalid-profile', 'Connection profile port is invalid');
  }

  const credentialReference = validateCredentialReference(own(input, 'credentialReference'));
  if (authMode === 'password' && credentialReference === undefined) {
    fail('credential-reference-missing', 'Password authentication requires a credential reference');
  }

  return {
    profileId: validateProfileId(own(input, 'profileId')),
    host: validateHost(own(input, 'host')),
    port: port as number,
    user: requiredString(own(input, 'user'), 'user'),
    expectedHostFingerprint: requiredString(own(input, 'expectedHostFingerprint'), 'expectedHostFingerprint'),
    authMode: authMode as AuthenticationMode,
    approvedKnownHostsReference: validateReference(own(input, 'approvedKnownHostsReference')),
    ...(credentialReference === undefined ? {} : { credentialReference }),
  };
}

function validateEntry(entry: unknown): ApprovedKnownHostsEntry {
  if (!isPlainRecord(entry)) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  const keys = Reflect.ownKeys(entry);
  if (keys.length !== 3 || !keys.every(key => typeof key === 'string' && ['host', 'port', 'fingerprint'].includes(key))) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  const host = entry.host;
  const fingerprint = entry.fingerprint;
  if (
    typeof host !== 'string' ||
    host.trim() === '' ||
    CONTROL_CHARACTERS.test(host) ||
    WILDCARD_CHARACTERS.test(host) ||
    typeof entry.port !== 'number' ||
    !Number.isInteger(entry.port) ||
    (entry.port as number) < 1 ||
    (entry.port as number) > 65535 ||
    typeof fingerprint !== 'string' ||
    fingerprint.trim() === '' ||
    CONTROL_CHARACTERS.test(fingerprint)
  ) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  return { host: host as string, port: entry.port as number, fingerprint: fingerprint as string };
}

/**
 * Check host identity and select an approved authentication mechanism. The
 * returned plan contains references and metadata only; no secret or key data.
 */
export async function authorizeConnection(
  input: unknown,
  dependencies: HostIdentityCredentialPolicyDependencies,
): Promise<AuthorizedConnection> {
  const profile = validatePolicyProfile(input);
  if (!dependencies || typeof dependencies !== 'object') {
    fail('known-hosts-unavailable', 'Policy dependencies are unavailable');
  }

  let entries: readonly ApprovedKnownHostsEntry[];
  try {
    entries = await dependencies.knownHosts.getEntries(profile.approvedKnownHostsReference);
  } catch {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }
  if (!Array.isArray(entries)) {
    fail('known-hosts-unavailable', 'Approved known-hosts data is unavailable');
  }

  const normalizedEntries = entries.map(validateEntry);
  const matchingEndpoint = normalizedEntries.filter(entry => entry.host === profile.host && entry.port === profile.port);
  if (matchingEndpoint.length === 0) {
    fail('known-hosts-entry-missing', 'Approved known-hosts entry is missing');
  }
  if (matchingEndpoint.length !== 1) {
    fail('known-hosts-entry-ambiguous', 'Approved known-hosts entry is ambiguous');
  }
  const hostIdentity = matchingEndpoint[0];
  if (hostIdentity.fingerprint !== profile.expectedHostFingerprint) {
    fail('known-hosts-entry-mismatch', 'Approved known-hosts entry does not match');
  }

  if (profile.authMode === 'agent-key') {
    let available = false;
    try {
      available = await dependencies.agentIdentity.isAvailable();
    } catch {
      available = false;
    }
    if (available !== true) {
      fail('agent-identity-unavailable', 'SSH agent identity is unavailable');
    }
    return {
      profile,
      knownHostsReference: profile.approvedKnownHostsReference,
      hostIdentity,
      authentication: { mode: 'agent-key' },
    };
  }

  const credentialReference = profile.credentialReference;
  if (credentialReference === undefined) {
    fail('credential-reference-missing', 'Password authentication requires a credential reference');
  }
  let approved = false;
  try {
    approved = await dependencies.credentialResolver.isApproved(credentialReference);
  } catch {
    fail('credential-resolver-unavailable', 'Credential reference approval is unavailable');
  }
  if (approved !== true) {
    fail('credential-reference-unapproved', 'Credential reference is not approved');
  }
  return {
    profile,
    knownHostsReference: profile.approvedKnownHostsReference,
    hostIdentity,
    authentication: { mode: 'password', credentialReference },
  };
}

export class HostIdentityCredentialPolicyError extends Error {
  readonly code: HostIdentityCredentialPolicyErrorCode;

  constructor(code: HostIdentityCredentialPolicyErrorCode, message: string) {
    super(message);
    this.name = 'HostIdentityCredentialPolicyError';
    this.code = code;
  }
}

export class HostIdentityCredentialPolicy {
  private readonly dependencies: HostIdentityCredentialPolicyDependencies;

  constructor(dependencies: HostIdentityCredentialPolicyDependencies) {
    this.dependencies = dependencies;
  }

  authorize(input: unknown): Promise<AuthorizedConnection> {
    return authorizeConnection(input, this.dependencies);
  }
}
