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
  readonly approvedKnownHostsReference: string;
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
]);

const SECRET_KEYS = new Set(['password', 'passphrase', 'privateKey', 'privateKeyContent', 'privateKeyPath', 'secret', 'token']);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${field} must be a non-empty string`);
  }

  if (/[\u0000-\u001F\u007F\[\]{}]/u.test(value)) {
    throw new TypeError(`${field} contains forbidden control characters`);
  }

  return value;
}

function rejectUnexpectedKeys(value: Record<string, unknown>, allowed: Set<string>): void {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      throw new TypeError('Connection profile contains an unexpected field');
    }
    if (SECRET_KEYS.has(key)) {
      throw new TypeError('Secret material fields are not accepted');
    }
    if (!allowed.has(key)) {
      throw new TypeError('Connection profile contains an unexpected field');
    }
  }
}

function rejectInheritedFields(value: Record<string, unknown>, allowed: Set<string>): void {
  const prototype = Object.getPrototypeOf(value);
  if (prototype === null) {
    return;
  }

  for (const key of Reflect.ownKeys(prototype)) {
    if (typeof key !== 'string') {
      continue;
    }
    if (SECRET_KEYS.has(key)) {
      throw new TypeError('Secret material fields are not accepted');
    }
    if (allowed.has(key)) {
      throw new TypeError('Connection profile contains an unexpected inherited field');
    }
  }
}

function requireOwnString(value: Record<string, unknown>, key: string): string {
  if (!Object.prototype.hasOwnProperty.call(value, key)) {
    return requireString(undefined, key);
  }

  return requireString(value[key], key);
}

function requireProfileId(value: unknown): string {
  const profileId = requireString(value, 'profileId');
  if (profileId === '__proto__' || profileId === 'constructor' || profileId === 'prototype' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(profileId)) {
    throw new TypeError('profileId must use the canonical lowercase hyphenated form');
  }

  return profileId;
}

/** Validate the only input exposed by the MCP connection capability. */
export function validateProfileSelection(input: unknown): ProfileSelectionInput {
  if (!isRecord(input)) {
    throw new TypeError('Connection input must contain only profileId');
  }

  const allowedKeys = new Set(['profileId']);
  rejectUnexpectedKeys(input, allowedKeys);
  rejectInheritedFields(input, allowedKeys);
  return { profileId: requireProfileId(requireOwnString(input, 'profileId')) };
}

/** Validate locally configured profile metadata and return a normalized copy. */
export function validateConnectionProfile(input: unknown): ConnectionProfile {
  if (!isRecord(input)) {
    throw new TypeError('Connection profile must be an object');
  }

  rejectUnexpectedKeys(input, PROFILE_KEYS);
  rejectInheritedFields(input, PROFILE_KEYS);

  const authMode = Object.prototype.hasOwnProperty.call(input, 'authMode') ? input.authMode : undefined;
  if (authMode !== 'agent-key' && authMode !== 'password') {
    throw new TypeError("authMode must be 'agent-key' or 'password'");
  }

  if (
    !Object.prototype.hasOwnProperty.call(input, 'port') ||
    !Number.isInteger(input.port) ||
    (input.port as number) < 1 ||
    (input.port as number) > 65535
  ) {
    throw new TypeError('port must be an integer between 1 and 65535');
  }

  const knownHostsReference = requireOwnString(input, 'approvedKnownHostsReference');

  const rawCredentialReference = Object.prototype.hasOwnProperty.call(input, 'credentialReference') ? input.credentialReference : undefined;
  const credentialReference = rawCredentialReference === undefined ? undefined : requireString(rawCredentialReference, 'credentialReference');
  if (authMode === 'password' && credentialReference === undefined) {
    throw new TypeError('password authentication requires a credentialReference');
  }

  return {
    profileId: requireProfileId(requireOwnString(input, 'profileId')),
    host: requireOwnString(input, 'host'),
    port: input.port as number,
    user: requireOwnString(input, 'user'),
    expectedHostFingerprint: requireOwnString(input, 'expectedHostFingerprint'),
    authMode,
    ...(credentialReference === undefined ? {} : { credentialReference }),
    approvedKnownHostsReference: knownHostsReference,
  };
}
