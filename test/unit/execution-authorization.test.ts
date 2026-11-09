import assert from 'node:assert/strict';
import test from 'node:test';

import { createExecutionAuthorization, RemoteExecutionError } from '../../src/execution/remote-command-execution.js';

const profile = {
  profileId: 'production-api',
  host: 'private.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:host',
  authMode: 'agent-key' as const,
  approvedKnownHostsReference: 'known-hosts://production-api',
};

test('authorization freezes profile identity and consumes exactly once', () => {
  let now = 100;
  const lease = createExecutionAuthorization(profile, 200, () => now);
  assert.equal(lease.profile.host, 'private.example');
  assert.equal(Object.isFrozen(lease.profile), true);
  assert.equal(lease.consume(), lease);
  assert.throws(
    () => lease.consume(),
    (error: unknown) => error instanceof RemoteExecutionError && error.code === 'approval-expired',
  );
  const expired = createExecutionAuthorization(profile, 200, () => now);
  now = 201;
  assert.throws(
    () => expired.consume(),
    (error: unknown) => error instanceof RemoteExecutionError && error.code === 'approval-expired',
  );
});
