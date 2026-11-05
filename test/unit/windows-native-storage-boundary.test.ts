import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const addonPath = join(process.cwd(), 'build', 'Release', 'windows_trust.node');
const fixture = join(process.cwd(), 'test', 'helpers', 'windows-native-storage-fixture.ps1');
const nativeRequire = createRequire(import.meta.url);
// Windows PowerShell 5.1 can fail to load the ACL type data in isolated child
// processes. Native-boundary fixtures must use PowerShell 7+ explicitly.
const fixtureShell = 'pwsh.exe';

function runFixture(
  mode: 'safe' | 'unsafe-root' | 'unsafe-leaf' | 'unsafe-registry' | 'overlap' | 'dot-alias' | 'junction' | 'cleanup',
  root: string,
): void {
  execFileSync(fixtureShell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fixture, '-Mode', mode], {
    env: { ...process.env, SSH_MCP_WINDOWS_STORAGE_TEST_ROOT: root },
    stdio: 'pipe',
  });
}

if (process.platform !== 'win32' || !existsSync(addonPath)) {
  test.skip('requires a locally compiled Windows native addon', () => undefined);
} else {
  test('accepts only an isolated private per-user configuration', async () => {
    const root = join(homedir(), `ssh-mcp-native-boundary-${process.pid}-${Date.now()}`);
    let configured = false;
    try {
      runFixture('safe', root);
      configured = true;
      const binding = nativeRequire(addonPath) as {
        readProfileState(): Buffer;
        readCredential(locator: string): string;
        resolveOpenSsh(): { ssh: string; sshAdd: string; version: string };
      };
      assert.equal(binding.readProfileState().toString('utf8'), '{"profiles":[]}');
      assert.throws(() => binding.readCredential('.'), /Windows secure storage is unavailable/u);
      assert.match(binding.resolveOpenSsh().ssh, /\\System32\\OpenSSH\\ssh\.exe$/iu);
      assert.match(binding.resolveOpenSsh().sshAdd, /\\System32\\OpenSSH\\ssh-add\.exe$/iu);
      assert.match(binding.resolveOpenSsh().version, /^9\.(?:[5-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$/u);
    } finally {
      if (configured) runFixture('cleanup', root);
    }
  });

  for (const mode of ['unsafe-root', 'unsafe-leaf', 'unsafe-registry', 'overlap', 'dot-alias', 'junction'] as const) {
    test(`fails closed for ${mode}`, async () => {
      const root = join(homedir(), `ssh-mcp-native-boundary-${process.pid}-${Date.now()}-${mode}`);
      let configured = false;
      try {
        runFixture(mode, root);
        configured = true;
        const binding = nativeRequire(addonPath) as { readProfileState(): Buffer };
        assert.throws(() => binding.readProfileState(), /Windows secure storage is unavailable/u);
      } finally {
        if (configured) runFixture('cleanup', root);
      }
    });
  }
}
