import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  buildAuditEvent,
  buildAuditMetadata,
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

test('known adapter discriminator codes map deterministically', () => {
  assert.equal(mapConnectionError({ code: 'ssh-timeout' }).code, 'timeout');
  assert.equal(mapConnectionError({ code: 'known-hosts-fingerprint-mismatch' }).code, 'host-key-failure');
  assert.equal(mapConnectionError({ code: 'unsupported-authentication' }).code, 'authentication-failure');
  assert.equal(mapConnectionError({ code: 'trusted-profile-unavailable' }).code, 'provider-failure');
  assert.equal(mapConnectionError({ code: 'unexpected-provider-error' }).code, 'unknown');
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

