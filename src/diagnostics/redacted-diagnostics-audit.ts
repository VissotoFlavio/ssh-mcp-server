/**
 * Safe diagnostics and audit records for SSH connection boundaries.
 *
 * This module is intentionally dependency-free and does not log.  It accepts
 * unknown provider errors only to classify them; no provider value is ever
 * copied to a public error, audit record, or serialized payload.
 */

export type ConnectionDiagnosticStage =
  | 'selection'
  | 'provider'
  | 'profile-resolution'
  | 'credential-resolution'
  | 'host-key'
  | 'host-key-verification'
  | 'authentication'
  | 'transport'
  | 'readiness'
  | 'timeout'
  | 'unknown';

export type ConnectionDiagnosticOutcome = 'success' | 'failure' | 'timeout';

/** Stable, non-sensitive codes suitable for an MCP response or log sink. */
export type ConnectionDiagnosticCode =
  | 'success'
  | 'unknown'
  | 'invalid-input'
  | 'provider-failure'
  | 'timeout'
  | 'host-key-failure'
  | 'authentication-failure'
  | 'connection-failure';

export interface RedactedDiagnosticErrorOptions {
  readonly code: unknown;
  readonly stage?: unknown;
  readonly outcome?: unknown;
}

export interface DiagnosticErrorPayload {
  readonly kind: 'connection-diagnostic-error';
  readonly code: ConnectionDiagnosticCode;
  readonly stage: ConnectionDiagnosticStage;
  readonly outcome: ConnectionDiagnosticOutcome;
  readonly message: string;
}

const SAFE_MESSAGES: Readonly<Record<ConnectionDiagnosticCode, string>> = {
  success: 'Connection completed',
  unknown: 'Connection failed',
  'invalid-input': 'Connection input is invalid',
  'provider-failure': 'Connection provider is unavailable',
  timeout: 'Connection timed out',
  'host-key-failure': 'Host identity verification failed',
  'authentication-failure': 'Authentication failed',
  'connection-failure': 'Connection failed',
};

const STAGES = new Set<ConnectionDiagnosticStage>([
  'selection',
  'provider',
  'profile-resolution',
  'credential-resolution',
  'host-key',
  'host-key-verification',
  'authentication',
  'transport',
  'readiness',
  'timeout',
  'unknown',
]);

const PROFILE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const MAX_DIAGNOSTIC_CODE_LENGTH = 96;
export const MAX_AUDIT_DURATION_MS = 300_000;
export const MAX_AUDIT_ATTEMPT = 100;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function own(value: Record<string, unknown>, key: string): unknown {
  try {
    return Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined;
  } catch {
    return undefined;
  }
}

/** Read only discriminator properties from class instances without inspecting
 * or serializing their message, cause, stack, or other provider state. */
function discriminator(value: unknown, key: string): unknown {
  if ((typeof value !== 'object' || value === null) && typeof value !== 'function') return undefined;
  try {
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function isRedactedDiagnosticError(value: unknown): value is RedactedDiagnosticError {
  try {
    return value instanceof RedactedDiagnosticError;
  } catch {
    return false;
  }
}

function safeString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length <= MAX_DIAGNOSTIC_CODE_LENGTH ? value : undefined;
}

function normalizeStage(value: unknown): ConnectionDiagnosticStage {
  return typeof value === 'string' && STAGES.has(value as ConnectionDiagnosticStage) ? (value as ConnectionDiagnosticStage) : 'unknown';
}

function normalizeOutcome(value: unknown): ConnectionDiagnosticOutcome | undefined {
  if (value === 'success' || value === 'failure' || value === 'timeout') return value;
  return undefined;
}

/**
 * Normalize aliases at the trust boundary.  Aliases are accepted only as
 * classifier input; the public record always uses the stable code names.
 */
function normalizeCode(value: unknown): ConnectionDiagnosticCode | undefined {
  if (value === 'success' || value === 'ok' || value === 'completed') return 'success';
  if (value === 'unknown') return 'unknown';
  if (
    value === 'invalid-input' ||
    value === 'invalid-selection' ||
    value === 'invalid-profile' ||
    value === 'invalid-reference' ||
    value === 'invalid-known-hosts-reference'
  )
    return 'invalid-input';
  if (
    value === 'provider-failure' ||
    value === 'provider' ||
    value === 'trusted-profile-unavailable' ||
    value === 'trusted-profile-not-found' ||
    value === 'invalid-trusted-profile' ||
    value === 'credential-resolver-unavailable' ||
    value === 'unsupported-platform' ||
    value === 'unsupported-provider' ||
    value === 'unapproved-reference' ||
    value === 'credential-unavailable' ||
    value === 'credential-store-failure'
  ) {
    return 'provider-failure';
  }
  if (value === 'timeout' || value === 'ssh-timeout' || value === 'ETIMEDOUT' || value === 'TIMEOUT') return 'timeout';
  if (
    value === 'host-key-failure' ||
    value === 'host-key' ||
    value === 'known-hosts-unavailable' ||
    value === 'known-hosts-fingerprint-mismatch' ||
    value === 'known-hosts-entry-missing' ||
    value === 'known-hosts-entry-mismatch' ||
    value === 'known-hosts-entry-ambiguous'
  ) {
    return 'host-key-failure';
  }
  if (
    value === 'authentication-failure' ||
    value === 'authentication' ||
    value === 'auth' ||
    value === 'permission-denied' ||
    value === 'unsupported-authentication' ||
    value === 'password-unavailable' ||
    value === 'agent-identity-unavailable' ||
    value === 'credential-reference-missing' ||
    value === 'credential-reference-unapproved'
  ) {
    return 'authentication-failure';
  }
  if (
    value === 'connection-failure' ||
    value === 'connection' ||
    value === 'ssh-connection-failed' ||
    value === 'invalid-executable' ||
    value === 'password-transport-unavailable'
  )
    return 'connection-failure';
  return undefined;
}

function inferredStage(code: ConnectionDiagnosticCode): ConnectionDiagnosticStage {
  if (code === 'timeout') return 'timeout';
  if (code === 'provider-failure') return 'provider';
  if (code === 'host-key-failure') return 'host-key-verification';
  if (code === 'authentication-failure') return 'authentication';
  return 'unknown';
}

function safeOptions(value: RedactedDiagnosticErrorOptions | ConnectionDiagnosticCode): {
  code: ConnectionDiagnosticCode;
  stage: ConnectionDiagnosticStage;
  outcome: ConnectionDiagnosticOutcome;
} {
  const record = isRecord(value) ? value : undefined;
  const code = normalizeCode(record === undefined ? value : own(record, 'code')) ?? 'unknown';
  const requestedOutcome = normalizeOutcome(record === undefined ? undefined : own(record, 'outcome'));
  let outcome: ConnectionDiagnosticOutcome;
  let normalizedCode = code;
  if (code === 'timeout' || requestedOutcome === 'timeout') {
    normalizedCode = 'timeout';
    outcome = 'timeout';
  } else if (code === 'success' && requestedOutcome !== 'failure') {
    outcome = 'success';
  } else {
    if (code === 'success') normalizedCode = 'unknown';
    outcome = requestedOutcome === 'success' ? 'failure' : (requestedOutcome ?? 'failure');
  }
  const requestedStage = record === undefined ? undefined : own(record, 'stage');
  return {
    code: normalizedCode,
    stage: normalizeStage(requestedStage ?? inferredStage(normalizedCode)),
    outcome,
  };
}

/** A typed public error with a fixed message and no provider cause attached. */
export class RedactedDiagnosticError extends Error {
  readonly code: ConnectionDiagnosticCode;
  readonly stage: ConnectionDiagnosticStage;
  readonly outcome: ConnectionDiagnosticOutcome;

  constructor(options: RedactedDiagnosticErrorOptions | ConnectionDiagnosticCode, stage?: unknown, outcome?: unknown) {
    const normalized = safeOptions(
      typeof options === 'string' && (stage !== undefined || outcome !== undefined) ? { code: options, stage, outcome } : options,
    );
    super(SAFE_MESSAGES[normalized.code]);
    this.name = 'RedactedDiagnosticError';
    this.code = normalized.code;
    this.stage = normalized.stage;
    this.outcome = normalized.outcome;
    Object.freeze(this);
  }

  /** JSON conversion deliberately excludes stack and every non-allowlisted field. */
  toJSON(): DiagnosticErrorPayload {
    return diagnosticErrorPayload(this);
  }
}

/** Descriptive alias for consumers that use the connection-oriented name. */
export class ConnectionDiagnosticError extends RedactedDiagnosticError {}

export function diagnosticErrorPayload(error: unknown): DiagnosticErrorPayload {
  const normalized = safeOptions({
    code: normalizeCode(discriminator(error, 'code')) ?? 'unknown',
    stage: discriminator(error, 'stage'),
    outcome: discriminator(error, 'outcome'),
  });
  return {
    kind: 'connection-diagnostic-error',
    code: normalized.code,
    stage: normalized.stage,
    outcome: normalized.outcome,
    message: SAFE_MESSAGES[normalized.code],
  };
}

function classifyProviderCode(value: unknown): ConnectionDiagnosticCode | undefined {
  const code = safeString(value);
  if (code === undefined) return undefined;
  return normalizeCode(code);
}

/**
 * Convert any provider/adapter failure into a fixed, redacted diagnostic.
 * Only small discriminator fields are inspected; the error itself is never
 * serialized, used as a cause, or included in a message.
 */
export function mapConnectionError(error: unknown, context?: unknown): RedactedDiagnosticError {
  if (isRedactedDiagnosticError(error)) {
    return new RedactedDiagnosticError({ code: error.code, stage: error.stage, outcome: error.outcome });
  }

  const explicitCode = classifyProviderCode(discriminator(error, 'diagnosticCode')) ?? classifyProviderCode(discriminator(error, 'code'));
  const name = safeString(discriminator(error, 'name'));
  const contextRecord = isRecord(context) ? context : undefined;
  const requestedStage = contextRecord === undefined ? (typeof context === 'string' ? context : undefined) : own(contextRecord, 'stage');
  const stage = normalizeStage(requestedStage);

  let code = explicitCode;
  if (code === undefined && (name === 'TimeoutError' || name === 'AbortError')) code = 'timeout';
  if (code === undefined) {
    if (stage === 'timeout') code = 'timeout';
    else if (stage === 'provider' || stage === 'profile-resolution' || stage === 'credential-resolution') code = 'provider-failure';
    else if (stage === 'host-key' || stage === 'host-key-verification') code = 'host-key-failure';
    else if (stage === 'authentication') code = 'authentication-failure';
  }
  code ??= 'unknown';
  const outcome = code === 'timeout' ? 'timeout' : 'failure';
  return new RedactedDiagnosticError({ code, stage: stage === 'unknown' ? inferredStage(code) : stage, outcome });
}

export interface ConnectionAuditMetadata {
  readonly profileId?: string;
  readonly authMode?: 'agent-key' | 'password';
  readonly outcome: ConnectionDiagnosticOutcome;
  readonly code: ConnectionDiagnosticCode;
  readonly durationMs?: number;
  readonly attempt?: number;
}

export interface ConnectionAuditEvent extends ConnectionAuditMetadata {
  readonly kind: 'connection-audit-event';
  readonly version: 1;
  readonly stage: ConnectionDiagnosticStage;
}

export interface ConnectionAuditInput {
  readonly profileId?: unknown;
  readonly authMode?: unknown;
  readonly outcome?: unknown;
  readonly code?: unknown;
  readonly stage?: unknown;
  readonly durationMs?: unknown;
  readonly attempt?: unknown;
}

function canonicalProfileId(value: unknown): string | undefined {
  if (typeof value !== 'string' || !PROFILE_ID.test(value)) return undefined;
  if (value === 'constructor' || value === 'prototype' || value === '__proto__') return undefined;
  return value;
}

function boundedInteger(value: unknown, maximum: number, minimum: number): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum ? value : undefined;
}

/** Build a metadata allowlist. Unknown and sensitive input fields are omitted. */
export function buildAuditMetadata(input: unknown): ConnectionAuditMetadata {
  const record = isRecord(input) ? input : {};
  let code = normalizeCode(own(record, 'code')) ?? 'unknown';
  let outcome = normalizeOutcome(own(record, 'outcome')) ?? (code === 'success' ? 'success' : code === 'timeout' ? 'timeout' : 'failure');
  if (code === 'timeout' || outcome === 'timeout') {
    code = 'timeout';
    outcome = 'timeout';
  } else if (outcome === 'success' && code !== 'success') {
    outcome = 'failure';
  } else if (code === 'success' && outcome !== 'success') {
    code = 'unknown';
  }

  const profileIdValue = own(record, 'profileId');
  const authModeValue = own(record, 'authMode');
  const profileId = canonicalProfileId(profileIdValue);
  const authMode = authModeValue === 'agent-key' || authModeValue === 'password' ? (authModeValue as 'agent-key' | 'password') : undefined;
  const durationMs = boundedInteger(own(record, 'durationMs'), MAX_AUDIT_DURATION_MS, 0);
  const attempt = boundedInteger(own(record, 'attempt'), MAX_AUDIT_ATTEMPT, 1);

  return {
    ...(profileId === undefined ? {} : { profileId }),
    ...(authMode === undefined ? {} : { authMode }),
    outcome,
    code,
    ...(durationMs === undefined ? {} : { durationMs }),
    ...(attempt === undefined ? {} : { attempt }),
  };
}

/** Build a complete, safe event for an MCP response or downstream log sink. */
export function buildAuditEvent(input: unknown): ConnectionAuditEvent {
  const record = isRecord(input) ? input : {};
  const metadata = buildAuditMetadata(input);
  const code = metadata.code;
  const requestedStage = own(record, 'stage');
  return {
    kind: 'connection-audit-event',
    version: 1,
    stage: normalizeStage(requestedStage ?? inferredStage(code)),
    ...metadata,
  };
}

export function serializeDiagnosticError(error: unknown): string {
  const safeError = isRedactedDiagnosticError(error) ? error : mapConnectionError(error);
  return JSON.stringify(diagnosticErrorPayload(safeError));
}

export function serializeAuditEvent(input: unknown): string {
  return JSON.stringify(buildAuditEvent(input));
}

// Names kept as explicit aliases for callers that prefer "safe" terminology.
export const createRedactedDiagnosticError = (options: RedactedDiagnosticErrorOptions | ConnectionDiagnosticCode): RedactedDiagnosticError =>
  new RedactedDiagnosticError(options);
export const safeSerializeDiagnosticError = serializeDiagnosticError;
export const safeSerializeAuditEvent = serializeAuditEvent;
export const createAuditEvent = buildAuditEvent;
export const serializeSafeDiagnostic = serializeDiagnosticError;
export const serializeSafeAuditEvent = serializeAuditEvent;
export const AUDIT_MAX_DURATION_MS = MAX_AUDIT_DURATION_MS;
