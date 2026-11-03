import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  buildAuditEvent,
  buildAuditMetadata,
  diagnosticErrorPayload,
  mapConnectionError,
  RedactedDiagnosticError,
  serializeAuditEvent,
  serializeDiagnosticError,
} from '../../src/diagnostics/redacted-diagnostics-audit.ts';

test('diagnostic errors use fixed messages and omit a provider error', () => {
  const raw = new Error('password=super-secret /srv/private/key stderr output');
  const diagnostic = mapConnectionError(raw, { stage: 'authentication' });

  assert.ok(diagnostic instanceof RedactedDiagnosticError);
  assert.equal(diagnostic.code, 'authentication-failure');
  assert.equal(diagnostic.stage, 'authentication');
  assert.equal(diagnostic.outcome, 'failure');
  assert.equal(diagnostic.message, 'Authentication failed');
  assert.equal(serializeDiagnosticError(raw).includes('super-secret'), false);
  assert.equal(serializeDiagnosticError(raw).includes('/srv/private/key'), false);
  assert.equal(serializeDiagnosticError(raw).includes('stderr output'), false);
  assert.equal(serializeDiagnosticError(raw).includes('stack'), false);
});

test('maps class-instance adapter errors and rejects contradictory success states', () => {
  class AdapterError extends Error {
    readonly code = 'ssh-timeout';
  }

  const mapped = mapConnectionError(new AdapterError('secret path and password'));
  assert.equal(mapped.code, 'timeout');
  assert.equal(mapped.outcome, 'timeout');
  assert.doesNotMatch(serializeDiagnosticError(mapped), /secret|password|path/iu);

  const contradictory = new RedactedDiagnosticError({ code: 'success', outcome: 'failure' });
  assert.equal(contradictory.code, 'unknown');
  assert.equal(contradictory.outcome, 'failure');
});

test('maps credential-store and host-reference discriminator codes', () => {
  class CredentialError extends Error {
    readonly code = 'credential-store-failure';
  }
  class HostReferenceError extends Error {
    readonly code = 'invalid-known-hosts-reference';
  }

  assert.equal(mapConnectionError(new CredentialError()).code, 'provider-failure');
  assert.equal(mapConnectionError(new HostReferenceError()).code, 'invalid-input');
});

test('normalizes forged or mutated diagnostic objects at serialization', () => {
  const diagnostic = new RedactedDiagnosticError('success');
  const forged = { code: 'password=/tmp/secret', stage: 'transport', outcome: 'success' };
  assert.doesNotMatch(JSON.stringify(diagnosticErrorPayload(forged)), /password|secret/iu);
  assert.doesNotMatch(serializeDiagnosticError(diagnostic), /password|secret/iu);
  assert.equal(Object.isFrozen(diagnostic), true);
});

test('known adapter discriminator codes map deterministically', () => {
  assert.equal(mapConnectionError({ code: 'ssh-timeout' }).code, 'timeout');
  assert.equal(mapConnectionError({ code: 'known-hosts-fingerprint-mismatch' }).code, 'host-key-failure');
  assert.equal(mapConnectionError({ code: 'unsupported-authentication' }).code, 'authentication-failure');
  assert.equal(mapConnectionError({ code: 'trusted-profile-unavailable' }).code, 'provider-failure');
  assert.equal(mapConnectionError({ code: 'unexpected-provider-error' }).code, 'unknown');
});

test('maps discriminator fields on Error and custom class instances without copying the error', () => {
  class ProviderError extends Error {
    readonly code = 'known-hosts-fingerprint-mismatch';
  }
  const error = new ProviderError('fingerprint=secret host=db.internal.example');
  const diagnostic = mapConnectionError(error);

  assert.equal(diagnostic.code, 'host-key-failure');
  assert.equal(diagnostic.stage, 'host-key-verification');
  assert.equal(serializeDiagnosticError(error).includes('fingerprint=secret'), false);
  assert.equal(serializeDiagnosticError(error).includes('db.internal.example'), false);
});

test('fails closed for hostile proxy errors', () => {
  const hostile = new Proxy({}, {
    getPrototypeOf() {
      throw new Error('prototype lookup failed');
    },
  });
  const mapped = mapConnectionError(hostile);
  assert.equal(mapped.code, 'unknown');
  assert.doesNotMatch(serializeDiagnosticError(hostile), /prototype lookup failed/iu);
});

test('diagnostic serialization is an allowlisted safe payload', () => {
  const diagnostic = new RedactedDiagnosticError({
    code: 'host-key-failure',
    stage: 'host-key-verification',
    outcome: 'failure',
  });
  const parsed = JSON.parse(serializeDiagnosticError(diagnostic)) as Record<string, unknown>;
  assert.deepEqual(parsed, {
    kind: 'connection-diagnostic-error',
    code: 'host-key-failure',
    stage: 'host-key-verification',
    outcome: 'failure',
    message: 'Host identity verification failed',
  });
});

test('audit metadata keeps canonical non-secret fields and drops invalid or secret fields', () => {
  const metadata = buildAuditMetadata({
    profileId: 'production-api',
    authMode: 'password',
    outcome: 'failure',
    code: 'authentication-failure',
    durationMs: 120,
    attempt: 2,
    host: 'db.internal.example',
    user: 'deploy',
    credentialReference: 'os://ssh/production-api',
    password: 'super-secret',
    privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----',
    stderr: 'private stderr',
    command: 'ssh deploy@db.internal.example',
  });

  assert.deepEqual(metadata, {
    profileId: 'production-api',
    authMode: 'password',
    outcome: 'failure',
    code: 'authentication-failure',
    durationMs: 120,
    attempt: 2,
  });
});

test('reads accessor-backed audit fields once and emits only allowlisted values', () => {
  let reads = 0;
  const input = {
    get authMode() {
      reads += 1;
      return reads === 1 ? 'password' : 'password=super-secret';
    },
    outcome: 'failure',
    code: 'connection-failure',
  };
  const serialized = serializeAuditEvent(input);
  assert.equal(reads, 1);
  assert.doesNotMatch(serialized, /super-secret|password=/iu);
  assert.match(serialized, /"authMode":"password"/u);
});

test('audit event fails closed for invalid identity and unbounded metrics', () => {
  const event = buildAuditEvent({
    profileId: '../secrets',
    authMode: 'private-key',
    outcome: 'timeout',
    code: 'authentication-failure',
    stage: 'timeout',
    durationMs: 300_001,
    attempt: 101,
    secret: 'do not serialize',
  });

  assert.deepEqual(event, {
    kind: 'connection-audit-event',
    version: 1,
    stage: 'timeout',
    outcome: 'timeout',
    code: 'timeout',
  });
  assert.equal(serializeAuditEvent(event).includes('do not serialize'), false);
});

test('audit metadata keeps outcome and code consistent when callers contradict themselves', () => {
  assert.deepEqual(buildAuditMetadata({ code: 'success', outcome: 'failure' }), {
    outcome: 'failure',
    code: 'unknown',
  });
  assert.deepEqual(buildAuditMetadata({ code: 'authentication-failure', outcome: 'success' }), {
    outcome: 'failure',
    code: 'authentication-failure',
  });
});
