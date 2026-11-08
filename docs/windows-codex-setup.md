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
native runtime and provider-composition boundaries are available, including
protected profile state and verified known-hosts storage. It validates only an
approved profile identifier; agent-key validation first uses the native
`ssh-add -l` probe and then a cancellable native no-command readiness check
with a private known-hosts snapshot. Password validation keeps the verified
known-hosts bytes in memory because it launches no SSH child. A listed tool
does not guarantee that a later validation succeeds: each call still fails
closed when, for example, the approved credential is unavailable, SSH
authentication fails, or host identity verification fails. If a required
composition boundary is unavailable, the tool is omitted; this is not an
invitation to pass hosts, credentials, paths, or commands to the MCP server.

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

## Provision one per-user approved profile

Use the repository's [Windows provisioning helper](../scripts/windows/provision-approved-profile.ps1)
to create exactly one approved profile, its known-hosts leaf, the fixed roots,
and the protected registry values. It is deliberately fail-closed: it accepts
only the fixed LocalAppData and HKCU locations, rejects an existing leaf or
root configuration instead of replacing it, and makes no network or SSH
connection. Run it only from the intended user's normal, non-administrative
PowerShell session.

Before running it, obtain one complete OpenSSH known-hosts line and its
SHA-256 fingerprint from independently approved operator material. The line
must name the configured host exactly (or `[host]:port` for a non-22 port).
The helper calculates the SHA-256 fingerprint from the decoded public-key
bytes and compares it before anything is written. Never use `ssh-keyscan`, an
interactive first-connection prompt, or TOFU to obtain this material.

From the trusted checkout, run one of the following illustrative commands
(replace every placeholder locally; do not place a password, passphrase,
private key, token, or other secret in the command):

```powershell
& .\scripts\windows\provision-approved-profile.ps1 `
  -ProfileId 'example-service' `
  -TargetHost 'approved.example.invalid' `
  -Port 22 `
  -User 'example-user' `
  -AuthMode 'agent-key' `
  -ExpectedHostFingerprint 'SHA256:REPLACE_WITH_APPROVED_FINGERPRINT' `
  -HostKeyLine 'approved.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIREPLACE_WITH_APPROVED_KEY'
```

For a password profile, pass `-AuthMode 'password'` and a non-secret opaque
`-CredentialLocator` that meets the helper's stated grammar. After it
completes, create the matching **Windows Generic Credential** manually in the
current user's Credential Manager UI with target name
`Vissoto/ssh-mcp-server/<opaque-locator>`, then enter the password only in
that UI. Do not use a command line, environment variable, profile JSON, or
Codex configuration for the password.

If the helper stops after creating partial local state, it intentionally does
not delete or overwrite anything. Do not relax ACLs or attempt cleanup just to
retry. Inspect the current-user owner, protected DACL, local NTFS location,
and reparse-point status; remove only the specifically identified partial
state with the environment owner's explicit authorization, then start again.

### Recovery is inspection-only

The helper intentionally refuses all existing provisioning roots, profile
leaves, and configuration keys. Do not create, edit, replace, or re-ACL state
by hand to retry it. The native boundary reads only
`HKCU\Software\Vissoto\ssh-mcp-server\StateRoot` and `KnownHostsRoot`; it
rejects unsafe ownership, DACLs, reparse points, non-NTFS locations, network
paths, and ambiguous state.

For a failed attempt, inspect only the named local paths and the current-user
registry key with your approved Windows administration procedure. Record the
failure category without copying hosts, profile IDs, credential references,
paths, keys, or secrets into support material. Any deletion or repair is a
separate environment-owner decision; after that decision, rerun the helper
from a clean state rather than hand-authoring configuration JSON or ACLs.

## Configure an agent-key identity

Perform this procedure in a normal, non-administrative PowerShell session for
the same Windows user that runs Codex and the MCP server. Do not generate a
key from an elevated Codex session and then attempt to use it from a normal
session: the owner or DACL can differ, and the MCP must fail closed instead of
relaxing the ACL.

This helper does not create, import, or store private keys. An `agent-key`
profile requires an identity already authorized by the environment owner and
loaded into the same current-user OpenSSH agent that the MCP will probe. Inspect
that agent with the fixed system executable:

```powershell
& (Join-Path ([System.Environment]::SystemDirectory) 'OpenSSH\ssh-add.exe') -l
```

Keep the second command's identity output local; it is a readiness check, not
evidence to paste into a ticket. If the agent service is disabled or unavailable,
have the device administrator enable the supported Windows OpenSSH service.
Do not run Codex or the MCP elevated as a workaround.

Before provisioning an `agent-key` profile, obtain the target host key and
SHA-256 fingerprint out of band. The helper validates and records them; never
hand-author the profile or known-hosts files.

See the [agent-key troubleshooting runbook](windows/agent-key-troubleshooting.md)
for fail-closed ownership, agent identity, remote authorization, and timeout
prerequisites.

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

For a `password` profile, use `"authMode": "password"` and add an opaque
`"credentialReference": "os://ssh/<opaque-locator>"`. Password readiness is
implemented only for the supported Windows alpha. The required runtime and
provider-composition boundaries determine whether `validate_connection` is
advertised; the Credential Manager lookup, host-identity verification, and
authentication happen during each validation request and can still return a
fail-closed tool error. Create the matching Generic Credential in the current
user's Windows Credential Manager with target name
`Vissoto/ssh-mcp-server/<opaque-locator>`. Enter the secret in the Credential
Manager UI; never use a command line, environment variable, profile JSON, or
Codex configuration for it.

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
listed tools. On a supported host with complete provider composition, the
expected tools are `list_approved_profiles` and `validate_connection`; on an
unsupported host or when composition is incomplete, `validate_connection` is
omitted. Its presence does not guarantee connection readiness: an individual
call can still fail closed. If state is missing or unsafe, discovery fails
closed when called and returns no profile data. Do not run
`node dist/server.js` interactively to test it: its standard input and output
are reserved exclusively for MCP JSON-RPC.

## Diagnostics and safe operation

The MCP server writes only JSON-RPC to standard output. Diagnostics and audit
events go to standard error and are redacted to approved fields. When asking
for support, provide the failure category and runtime versions, but remove
hosts, usernames, profile IDs, credential references, paths, and all secrets.

The server accepts only approved profile identifiers. It does not accept
commands, arbitrary connection settings, filesystem paths, private keys,
passwords, or tokens from Codex. Keep the profile state, known-hosts data, and
Windows Credential Manager private to the same Windows user.
