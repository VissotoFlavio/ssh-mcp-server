import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const scriptPath = join(repositoryRoot, 'scripts', 'windows', 'provision-approved-profile.ps1');
const windowsGuidePath = join(repositoryRoot, 'docs', 'windows-codex-setup.md');

async function source(): Promise<string> {
  return readFile(scriptPath, 'utf8');
}

test('provisioning helper uses fixed roots and rejects unsafe path state before leaf probes', async () => {
  const script = await source();

  assert.match(script, /provision-approved-profile\.mjs/u);
  assert.match(script, /SpecialFolderOption\]::DoNotVerify/u);
  assert.doesNotMatch(script, /New-Item|Set-Acl|RegistryKey|LocalApplicationData|CreateDirectory|connection-profiles\.json/iu);
});

test('provisioning helper fails closed for existing state and never re-ACLs it', async () => {
  const script = await source();

  const native = await readFile(join(repositoryRoot, 'native', 'windows_trust.cc'), 'utf8');
  assert.match(native, /napi_value ProvisionApprovedProfile/u);
  assert.match(native, /FILE_CREATE/u);
  assert.match(native, /PROTECTED_DACL_SECURITY_INFORMATION/u);
  assert.match(native, /REG_CREATED_NEW_KEY/u);
  assert.match(native, /KF_FLAG_DONT_VERIFY/u);
  assert.match(native, /IsExactProvisionObject/u);
  assert.match(native, /VerifyKnownHostLine/u);
  assert.match(native, /Base64Sha256/u);
  assert.match(native, /JsonString/u);
  assert.match(native, /OpenVerifiedLocalAppData/u);
  assert.match(native, /OpenVerifiedDirectoryRelative/u);
  assert.match(native, /CreateFileW\(drive_root\.c_str\(\)/u);
  assert.match(native, /require_child_creation \? FILE_ADD_SUBDIRECTORY : 0/u);
  assert.match(native, /next == std::wstring::npos, &child/u);
  assert.doesNotMatch(native, /CreateFileW\(drive_root[^\n]*FILE_ADD_SUBDIRECTORY/u);
  assert.doesNotMatch(native, /NewPrivateDirectory|NewPrivateFile|NewPrivateDacl|NewPrivateRegistryDacl/u);
  assert.match(native, /napi_get_all_property_names/u);
  assert.match(native, /"com9"/u);
  assert.match(native, /"lpt9"/u);
  assert.match(native, /CreatePrivateRelative\(local_handle\.get\(\), L"Vissoto"/u);
  assert.match(native, /OpenVerifiedLocalAppData\(local_app_data, &local_handle\)/u);
  assert.doesNotMatch(native, /VerifyNoReparseDirectoryChain|CreateFileW\(local_app_data\.c_str\(\)|GetFileAttributesW/u);
  assert.match(native, /write_new_file\(state_handle\.get\(\), kStateFile/u);
  assert.match(native, /OBJ_CASE_INSENSITIVE \| OBJ_DONT_REPARSE/u);
  assert.doesNotMatch(native, /FILE_DIRECTORY_FILE[^\n]*FILE_OPEN_REPARSE_POINT/u);
  assert.doesNotMatch(script, /Remove-Item|Clear-Content|Set-Content|Add-Content|Out-File/iu);
});

test('provisioning helper validates exact host identity locally without launching SSH', async () => {
  const script = await source();

  assert.match(script, /\[string\]\$TargetHost/u);
  assert.match(script, /-csplit '\\s\+'/u);
  assert.match(script, /\$parts\.Count -cne 3/u);
  assert.match(script, /System\.Security\.Cryptography\.SHA256/u);
  assert.match(script, /\$actualFingerprint -cne \$ExpectedHostFingerprint/u);
  assert.match(script, /IPv6 is not supported by this helper/u);
  assert.match(script, /\$reservedIds/u);
  assert.match(script, /\$CredentialLocator -cmatch '\^\(\?:password/u);
  assert.doesNotMatch(script, /ssh-keyscan|ssh-keygen|ssh\.exe|Invoke-WebRequest|Invoke-Command|Enter-PSSession|Start-Process/iu);
});

test('provisioning helper limits modes and keeps credential entry in the Windows UI', async () => {
  const script = await source();

  assert.match(script, /\$AuthMode -cne 'agent-key' -and \$AuthMode -cne 'password'/u);
  assert.match(script, /request\['credentialLocator'\] = \$CredentialLocator/u);
  assert.match(script, /Windows Generic Credential in Credential Manager/u);
  assert.doesNotMatch(script, /\[string\]\$Password|Read-Host|Get-Credential|ConvertTo-SecureString/iu);
});

test('Windows guide invokes the helper with TargetHost', async () => {
  const guide = await readFile(windowsGuidePath, 'utf8');

  assert.match(guide, /-TargetHost 'approved\.example\.invalid'/u);
  assert.doesNotMatch(guide, /\n\s+-Host 'approved\.example\.invalid'/u);
});
