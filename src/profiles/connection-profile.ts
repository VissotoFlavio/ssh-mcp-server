/**
 * Metadata for a pre-approved SSH destination.
 *
 * This type intentionally contains no credential material. A credentialReference
 * is an opaque lookup key for a later credential-store integration.
 */
export type AuthenticationMode = 'agent-key' | 'password';

export interface ConnectionProfile {
  readonly profileId: string;
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly expectedHostFingerprint: string;
  readonly authMode: AuthenticationMode;
  readonly credentialReference?: string;
  readonly approvedKnownHostsReference?: string;
  readonly approvedKnownHostsPath?: string;
}

export interface ProfileSelectionInput {
  readonly profileId: string;
}

const PROFILE_KEYS = new Set([
  'profileId',
  'host',
  'port',
  'user',
  'expectedHostFingerprint',
  'authMode',
  'credentialReference',
  'approvedKnownHostsReference',
  'approvedKnownHostsPath',
]);

const SECRET_KEYS = new Set([
  'password',
  'passphrase',
  'privateKey',
  'privateKeyContent',
  'privateKeyPath',
  'secret',
  'token',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${field} must be a non-empty string`);
  }

  if (/[\[\]{}\r\n\0]/u.test(value)) {
    throw new TypeError(`${field} contains forbidden control characters`);
  }

  return value;
}

function rejectUnexpectedKeys(value: Record<string, unknown>, allowed: Set<string>): void {
  for (const key of Object.keys(value)) {
    if (SECRET_KEYS.has(key)) {
      throw new TypeError(`${key} is secret material and is not accepted`);
    }
    if (!allowed.has(key)) {
      throw new TypeError(`Unexpected connection profile field: ${key}`);
    }
  }
}

/** Validate the only input exposed by the MCP connection capability. */
export function validateProfileSelection(input: unknown): ProfileSelectionInput {
  if (!isRecord(input)) {
    throw new TypeError('Connection input must contain only profileId');
  }

  rejectUnexpectedKeys(input, new Set(['profileId']));
  return { profileId: requireString(input.profileId, 'profileId') };
}

/** Validate locally configured profile metadata and return a normalized copy. */
export function validateConnectionProfile(input: unknown): ConnectionProfile {
  if (!isRecord(input)) {
    throw new TypeError('Connection profile must be an object');
  }

  rejectUnexpectedKeys(input, PROFILE_KEYS);

  const authMode = input.authMode;
  if (authMode !== 'agent-key' && authMode !== 'password') {
    throw new TypeError("authMode must be 'agent-key' or 'password'");
  }

  if (!Number.isInteger(input.port) || (input.port as number) < 1 || (input.port as number) > 65535) {
    throw new TypeError('port must be an integer between 1 and 65535');
  }

  const knownHostsReference = input.approvedKnownHostsReference;
  const knownHostsPath = input.approvedKnownHostsPath;
  if ((knownHostsReference === undefined) === (knownHostsPath === undefined)) {
    throw new TypeError('Exactly one approved known-hosts reference or path is required');
  }

  const credentialReference = input.credentialReference;
  if (credentialReference !== undefined) {
    requireString(credentialReference, 'credentialReference');
  }
  if (authMode === 'password' && credentialReference === undefined) {
    throw new TypeError('password authentication requires a credentialReference');
  }

  return {
    profileId: requireString(input.profileId, 'profileId'),
    host: requireString(input.host, 'host'),
    port: input.port as number,
    user: requireString(input.user, 'user'),
    expectedHostFingerprint: requireString(input.expectedHostFingerprint, 'expectedHostFingerprint'),
    authMode,
    ...(credentialReference === undefined ? {} : { credentialReference }),
    ...(knownHostsReference === undefined
      ? { approvedKnownHostsPath: requireString(knownHostsPath, 'approvedKnownHostsPath') }
      : { approvedKnownHostsReference: requireString(knownHostsReference, 'approvedKnownHostsReference') }),
  };
}
