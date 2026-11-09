import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

test('Windows Codex skill keeps discovery and validation inputs bounded', async () => {
  const skill = await readFile(join(repositoryRoot, 'skills', 'windows-ssh-mcp', 'SKILL.md'), 'utf8');

  assert.match(skill, /list_approved_profiles/u);
  assert.match(skill, /get_windows_readiness_status/u);
  assert.match(skill, /validate_connection/u);
  assert.match(skill, /profileId/u);
  assert.match(skill, /discovered/u);
  assert.match(skill, /readiness is not\s+authorization/iu);
  assert.match(skill, /Credential Manager/u);
  assert.match(skill, /Do not add any other field/u);
  assert.match(skill, /Never send or request a host, port, user, path, command/u);

  for (const category of [
    'unsupported',
    'registry',
    'filesystem',
    'configuration',
    'known-hosts',
    'credential',
    'provider',
    'authentication-failure',
    'host-key-failure',
    'timeout',
    'connection-failure',
  ]) {
    assert.match(skill, new RegExp(`\\b${category}\\b`, 'u'));
  }

  assert.doesNotMatch(skill, /StrictHostKeyChecking=accept-new/iu);
});
