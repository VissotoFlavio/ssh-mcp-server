import { deepEqual, strict as assert } from 'node:assert';
import test from 'node:test';

import {
  createLocalApprovedProfileListingProvider,
  createRuntimeApprovedProfileListingProvider,
  SSH_MCP_STATE_ROOT_ENV,
} from '../../src/profiles/approved-profile-listing.js';
import type { LocalProfileRegistry } from '../../src/profiles/local-profile-registry.js';

test('projects trusted registry entries to approved profile discovery metadata only', async () => {
  const registry: LocalProfileRegistry = {
    async getProfile() {
      return undefined;
    },
    async listProfiles() {
      return [
        {
          profileId: 'production-readonly',
          host: 'internal.example.test',
          port: 22,
          user: 'deploy',
          expectedHostFingerprint: 'SHA256:host-secret',
          authMode: 'password' as const,
          credentialReference: 'credential-secret',
          approvedKnownHostsReference: '/private/known_hosts',
        },
      ];
    },
  };

  const provider = createLocalApprovedProfileListingProvider(registry);

  deepEqual(await provider.listApprovedProfiles(), [{ profileId: 'production-readonly', classification: 'operator-approved' }]);
  assert.equal(JSON.stringify(await provider.listApprovedProfiles()).includes('secret'), false);
  assert.equal(JSON.stringify(await provider.listApprovedProfiles()).includes('known_hosts'), false);
});

test('composes discovery from the configured state root only', async () => {
  let configuredStateRoot: string | undefined;
  const registry: LocalProfileRegistry = {
    async getProfile() {
      return undefined;
    },
    async listProfiles() {
      return [
        {
          profileId: 'production-readonly',
          host: 'internal.example.test',
          port: 22,
          user: 'deploy',
          expectedHostFingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          authMode: 'agent-key',
          approvedKnownHostsReference: 'known-hosts://production-readonly',
        },
      ];
    },
  };

  const provider = createRuntimeApprovedProfileListingProvider({ [SSH_MCP_STATE_ROOT_ENV]: 'D:\\operator-state' }, (options) => {
    configuredStateRoot = options.stateRoot;
    return registry;
  });

  assert.equal(configuredStateRoot, 'D:\\operator-state');
  deepEqual(await provider.listApprovedProfiles(), [{ profileId: 'production-readonly', classification: 'operator-approved' }]);
});

test('fails closed for missing or invalid runtime state-root configuration', () => {
  const invalidRoot = 'relative-secret-root';

  for (const environment of [{}, { [SSH_MCP_STATE_ROOT_ENV]: invalidRoot }]) {
    assert.throws(
      () => createRuntimeApprovedProfileListingProvider(environment),
      (error: unknown) =>
        error instanceof TypeError && error.message === 'Approved profile discovery configuration is invalid' && !error.message.includes(invalidRoot),
    );
  }
});
