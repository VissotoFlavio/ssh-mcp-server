# Native Windows installation and Codex setup

This guide configures the Windows alpha for one local Windows user. It never
requires starting Codex, Node.js, or this MCP server as Administrator. Each
user has independent configuration and approved state.

The [Windows trust model](windows-trust-model.md) is the authoritative security
boundary. Follow it when this guide conflicts with local policy.

## Scope and current limitation

The supported alpha envelope is 64-bit Windows 11 23H2 or newer, or Windows
Server 2022 or newer, with 64-bit Node.js 22 or newer and Microsoft OpenSSH
9.5.0.0 or newer installed in the Windows system OpenSSH directory. Any other
platform, architecture, version, filesystem, or safety failure is unavailable
rather than partially supported.

The Windows runtime advertises `validate_connection` only when the supported
native addon, protected profile state, verified known-hosts boundary, trusted
OpenSSH/agent boundary, and Credential Manager boundary are all available.
It validates only an approved profile identifier; agent-key validation first
uses the native `ssh-add -l` probe and then a cancellable native no-command
readiness check with a private known-hosts snapshot. Password validation keeps
the verified known-hosts bytes in memory because it launches no SSH child. If
any prerequisite is unavailable, the tool is omitted as a safe fail-closed
result, not an invitation to pass hosts, credentials, paths, or commands to
the MCP server.

## Prerequisites

1. Install a supported 64-bit Node.js release and confirm its intended absolute
   `node.exe` path reports 22 or later. Do not use a `node` command selected
   through `PATH`.
2. Have the device administrator install the Microsoft OpenSSH Client optional
   feature if it is not already present. The one-time Windows feature
   installation can be governed by device policy; using this MCP afterwards
   does not need elevation. Do not use an executable selected through `PATH`:

   ```powershell
   $openSsh = Join-Path ([System.Environment]::SystemDirectory) 'OpenSSH'
   & (Join-Path $openSsh 'ssh.exe') -V
   Test-Path -LiteralPath (Join-Path $openSsh 'ssh-add.exe') -PathType Leaf
   ```

   The first command must report the supported Microsoft OpenSSH release, and
   the second must return `True`.

3. If an `agent-key` profile will be used, add the approved key to the current
   user's `ssh-agent` and confirm the verified system executable lists it:

   ```powershell
   & (Join-Path $openSsh 'ssh-add.exe') -l
   ```

   Do not put a private key, passphrase, or agent socket path in an MCP profile
   or Codex setting.

4. Build the trusted checkout before registering it with Codex:

   ```powershell
   npm ci
   npm run build
   npm run build:native
   ```

   The native build requires the Windows C++ build prerequisites for Node.js
   addons. If the build or runtime support gate fails, stop and fix that local
   prerequisite; do not use WSL, a POSIX fallback, `PATH`, or a copied binary.

## Create per-user approved state

Use local NTFS directories owned by the current user. The recommended layout
is below the current user's Local AppData directory; it is not a shared or
machine-wide location.

```powershell
$root = Join-Path $env:LOCALAPPDATA 'Vissoto\ssh-mcp-server'
$stateRoot = Join-Path $root 'state'
$knownHostsRoot = Join-Path $root 'known-hosts'
New-Item -ItemType Directory -Force $stateRoot, $knownHostsRoot | Out-Null

Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

function Set-PrivateFileAcl([string]$Path, [bool]$Directory) {
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($sid)
  $inheritance = if ($Directory) {
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  } else {
    [System.Security.AccessControl.InheritanceFlags]::None
  }
  $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $acl.SetAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
}

Set-PrivateFileAcl $stateRoot $true
Set-PrivateFileAcl $knownHostsRoot $true

$keyPath = 'Software\Vissoto\ssh-mcp-server'
$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($keyPath, $true)
try {
  $key.SetValue('StateRoot', $stateRoot, [Microsoft.Win32.RegistryValueKind]::String)
  $key.SetValue('KnownHostsRoot', $knownHostsRoot, [Microsoft.Win32.RegistryValueKind]::String)
  $acl = [System.Security.AccessControl.RegistrySecurity]::new()
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetAccessRule([System.Security.AccessControl.RegistryAccessRule]::new(
    $sid,
    [System.Security.AccessControl.RegistryRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
  ))
  $key.SetAccessControl($acl)
} finally {
  $key.Close()
}
```

These are the only Windows root locations read by the native boundary:
`HKCU\Software\Vissoto\ssh-mcp-server\StateRoot` and `KnownHostsRoot`.
Environment variables, command-line arguments, the current directory, and
other registry values cannot replace them. The native boundary verifies the
registry key, both roots, and the files it reads. It refuses unsafe ownership,
DACLs, reparse points, non-NTFS locations, network paths, and ambiguous state.
The procedure above deliberately makes each terminal root and the configuration
key current-user-owned with a protected DACL, not an inherited or broad DACL.
It is the same narrowly scoped ACL shape exercised by the native storage test
fixture. Run it in the intended user's normal PowerShell session; do not relax
permissions or grant access to a group to make a rejected location work.

Create exactly one `connection-profiles.json` file in `StateRoot`. It contains
connection metadata, never a private key, password, passphrase, token, or
host-key material. This intentionally non-working template shows the required
shape without a real destination:

```json
{
  "profiles": [
    {
      "profileId": "example-service",
      "host": "approved.example.invalid",
      "port": 22,
      "user": "example-user",
      "expectedHostFingerprint": "SHA256:REPLACE_WITH_APPROVED_FINGERPRINT",
      "authMode": "agent-key",
      "approvedKnownHostsReference": "known-hosts://example-service"
    }
  ]
}
```

For this profile, create `KnownHostsRoot\example-service.known_hosts`. Obtain
its host key and SHA-256 fingerprint from an independently approved operator
source, verify the two agree, and record the approved public host-key entry in
that file. Do not approve a key from an interactive first connection prompt or
copy a known-hosts file from an untrusted profile.

Immediately after creating or replacing either leaf, protect it before starting
Codex or the MCP server:

```powershell
Set-PrivateFileAcl (Join-Path $stateRoot 'connection-profiles.json') $false
Set-PrivateFileAcl (Join-Path $knownHostsRoot 'example-service.known_hosts') $false
```

If either ACL operation or the later MCP call fails, stop and diagnose the
current-user ownership, protected DACL, local NTFS location, and reparse-point
status. Never weaken the ACL or substitute a shared location.

## Configure an agent-key identity

Perform this procedure in a normal, non-administrative PowerShell session for
the same Windows user that runs Codex and the MCP server. Do not generate a
key from an elevated Codex session and then attempt to use it from a normal
session: the owner or DACL can differ, and the MCP must fail closed instead of
relaxing the ACL.

Create a dedicated private key beneath the already private per-user root. The
following command intentionally prompts for a passphrase without placing it on
a command line. If local policy explicitly permits a passphrase-free key for
unattended agent loading, use the corresponding OpenSSH option only after
ensuring the private-key ACL remains restricted to the current user.

```powershell
$keyRoot = Join-Path $root 'keys'
New-Item -ItemType Directory -Force $keyRoot | Out-Null
Set-PrivateFileAcl $keyRoot $true

$keyPath = Join-Path $keyRoot 'ssh-mcp-agent-ed25519'
if (Test-Path -LiteralPath $keyPath) {
  throw 'Refusing to overwrite an existing MCP agent key.'
}

& (Join-Path $openSsh 'ssh-keygen.exe') -t ed25519 -a 64 -f $keyPath -C 'ssh-mcp-agent'
Set-PrivateFileAcl $keyPath $false
Set-PrivateFileAcl "$keyPath.pub" $false
```

The public key may be added to the intended account's `authorized_keys` only
with explicit authorization from that environment's owner. Never copy, upload,
or record the private key, passphrase, key path, or a public-key fingerprint in
an MCP profile, Codex configuration, pull request, issue, or support record.

Load the key only into the same current-user OpenSSH agent that the MCP will
probe:

```powershell
& (Join-Path $openSsh 'ssh-add.exe') $keyPath
& (Join-Path $openSsh 'ssh-add.exe') -l
```

Keep the second command's identity output local; it is a readiness check, not
evidence to paste into a ticket. If the agent service is disabled or unavailable,
have the device administrator enable the supported Windows OpenSSH service.
Do not run Codex or the MCP elevated as a workaround.

Before adding an `agent-key` profile, obtain the target host key and SHA-256
fingerprint out of band, populate the approved known-hosts entry, and verify
the profile's host identity matches it. The profile contains only connection
metadata and an approved known-hosts reference; it contains no private-key
path, passphrase, or secret.

### Stop conditions and recovery

- If the key directory or either key leaf is not owned by the current user or
  lacks a protected private DACL, stop. Do not take ownership, loosen the ACL,
  or reuse that key from another Windows identity; recreate it from the
  intended user's normal session.
- If an elevated process created an unusable key, remove it only with the
  environment owner's explicit authorization. The removal is separate from
  generation and must target only the identified key pair.
- If no approved agent identity is loaded, do not generate an arbitrary key
  and claim success. The corresponding public key must first be authorized on
  the intended environment.
- If the MCP runs under a different Windows identity from the interactive
  user, configure and validate the key in the MCP process identity. Do not
  attempt to share agent state between users.

For a future `password` profile, use `"authMode": "password"` and add an
opaque `"credentialReference": "os://ssh/<opaque-locator>"`. Create the
matching Generic Credential in the current user's Windows Credential Manager
with target name `Vissoto/ssh-mcp-server/<opaque-locator>`. Enter the secret in
the Credential Manager UI; never use a command line, environment variable,
profile JSON, or Codex configuration for it.

## Register the stdio server with Codex

Use absolute, operator-approved executable paths. From a normal,
non-administrative PowerShell, replace the placeholders with the built checkout
and the intended supported x64 Node.js executable. Do not use a `node` command
resolved through `PATH`:

```powershell
$nodeExe = 'C:\Program Files\nodejs\node.exe'
& $nodeExe --version
codex mcp add ssh-mcp-server -- $nodeExe 'D:\path\to\ssh-mcp-server\dist\server.js'
codex mcp list
```

This creates the Codex user configuration entry for a local stdio server; it
does not copy profile state into Codex. An equivalent configuration has a
server name, a Node.js command, and the absolute `dist\server.js` argument:

```toml
[mcp_servers.ssh-mcp-server]
command = 'C:\Program Files\nodejs\node.exe'
args = ['D:\path\to\ssh-mcp-server\dist\server.js']
```

Restart Codex after changing its MCP configuration, then inspect the server's
listed tools. On a supported, fully configured Windows alpha host, the expected
tools are `list_approved_profiles` and `validate_connection`; on an unsupported
or incompletely configured host, `validate_connection` is omitted. If state is
missing or unsafe, discovery fails closed when called and returns no profile
data. Do not run `node dist/server.js` interactively to test it: its standard
input and output are reserved exclusively for MCP JSON-RPC.

## Diagnostics and safe operation

The MCP server writes only JSON-RPC to standard output. Diagnostics and audit
events go to standard error and are redacted to approved fields. When asking
for support, provide the failure category and runtime versions, but remove
hosts, usernames, profile IDs, credential references, paths, and all secrets.

The server accepts only approved profile identifiers. It does not accept
commands, arbitrary connection settings, filesystem paths, private keys,
passwords, or tokens from Codex. Keep the profile state, known-hosts data, and
Windows Credential Manager private to the same Windows user.
