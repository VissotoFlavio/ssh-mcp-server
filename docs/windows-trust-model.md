# Windows trust model (alpha)

## Status and support boundary

This document is the authoritative security model for the native Windows
runtime proposed for `v0.1.0-alpha.1`. The native command boundary is present,
but production remote execution remains unavailable unless the trusted native
audit-journal provider is installed and injected.

The Windows runtime is **per-user only**. It never requires elevation, reads
no machine-wide configuration, and never shares approved profile or
known-hosts state between Windows users.

The alpha supports only all of the following:

- 64-bit Windows 11, version 23H2 or later, or Windows Server 2022 or later;
- 64-bit Node.js 22.0.0 or later; and
- Microsoft OpenSSH 9.5.0.0 or later installed in the system OpenSSH
  directory.

The runtime must fail closed on every other platform, architecture, version,
filesystem, or safety capability. It must not attempt a best-effort fallback
through POSIX checks, PowerShell, `cmd.exe`, WSL, user SSH configuration, or
`PATH`.

## Trust anchors

The Windows runtime has four distinct trust anchors:

1. The operator-approved profile-state root.
2. The operator-approved known-hosts root.
3. A private snapshot and temporary-state root created by the runtime.
4. The Microsoft system OpenSSH installation.

Profile state and known-hosts data are independent roots. Neither may be the
other root, an ancestor or descendant of the other, or resolve to the same
volume/file identity. A profile identifier is never converted into an
arbitrary path: it selects one fixed known-hosts leaf beneath the already
verified known-hosts root.

On Windows, root paths are read only from the current user's
`HKCU\\Software\\Vissoto\\ssh-mcp-server` configuration key by the native
boundary. The key supplies fixed `StateRoot` and `KnownHostsRoot` values; the
operator SID is derived from the current process token, never configured as a
value. Its inspected owner and protected DACL must belong to that SID and
reject `KEY_SET_VALUE`, `KEY_CREATE_SUB_KEY`, delete, `WRITE_DAC`,
`WRITE_OWNER`, generic, or equivalent mutation rights for every other
principal. Process environment variables, command-line arguments,
current-directory data, and other user-registry values must not override or
supply these roots. Missing, malformed, unreadable, or unsafe configuration
makes Windows discovery and validation unavailable.

The configuration key, both roots, and every accepted file must be owned by
that same token SID. A different user's hive, profile directory, root, SID, or
process is not a fallback and is rejected. This is an isolation boundary, not
a mechanism for sharing configuration between local accounts.

Only local NTFS volumes are supported. UNC paths, mapped or substituted
drives, device paths, alternate data streams, network filesystems, and any
path whose final identity cannot be verified are rejected.

## Required native boundary

Node.js file metadata and `realpath` are not sufficient evidence on Windows:
they do not expose SIDs, DACLs, reparse tags, handle identity, or an
open-by-handle no-follow guarantee. In particular, POSIX UID/mode checks and
`O_NOFOLLOW` must not be reused as Windows security checks.

Windows storage and executable trust therefore require a small, audited native
Win32 boundary. It must operate on handles and expose only allowlisted results
to TypeScript. The boundary is responsible for:

- opening each directory component and file with reparse-point-aware flags;
- rejecting every reparse point, including symbolic links, junctions, mount
  points, and unknown tags;
- obtaining the final path, volume serial, and file identifier from the open
  handle;
- reading owner and DACL information from the handle; and
- retaining enough identity information to detect replacement before trust is
  used.

No native dependency is selected or authorized by this document. The selected
binding and its review are required work for the owning implementation task.
Until that boundary is available and validated, Windows discovery and
validation remain unavailable.

## State, ACL, and race rules

For profile state, known-hosts files, snapshots, and temporary state, the
runtime must apply all of these rules before reading or trusting content:

- Each root and every traversed component is a directory, is not a reparse
  point, and remains the same volume/file identity throughout the operation.
  The terminal root is owned by the configured operator SID with a protected
  DACL; ancestors must reject untrusted replacement, deletion, ACL, ownership,
  attribute, and child-creation rights before traversal continues.
- A leaf is a regular file, is not a reparse point, and is opened before it is
  inspected or read. The opened handle identity must still match the pathname
  object after the open.
- The owner is the configured operator SID. `SYSTEM` and the local
  Administrators group are host-trusted principals; no other principal may
  receive write, modify, delete, create-child, or take-ownership rights.
- The DACL is protected from unsafe inheritance and grants no broad write
  rights to `Everyone`, `Users`, `Authenticated Users`, a service group, or
  an unknown SID. This includes `WRITE_DAC`, `WRITE_OWNER`, generic rights,
  and any standard or file right that can add permissions, alter attributes,
  replace, delete, or create children. An unreadable, absent,
  inherited-unsafely, or ambiguous DACL is unsafe.
- The configured process token must be able to read the root and leaf through
  the inspected DACL. Access-control evaluation failure is unsafe.
- A root is checked before opening a leaf and checked again after the leaf is
  opened. The final handle path must remain directly beneath the verified
  root, on the same local NTFS volume.

Known-hosts data is read through its verified source handle. Agent-key
validation copies those bytes into an immutable snapshot in a new private
directory before any SSH child starts. Only the verified snapshot pathname is
passed to OpenSSH; the source pathname is never passed to a child. Creation
uses exclusive handles, and the snapshot directory and leaf identities and
ACLs are verified before data is written, read, used, or removed. A
replacement of the source after capture cannot alter the snapshot supplied to
SSH. Password validation uses the verified bytes only in memory: it launches
no child process and never passes either source or snapshot pathname to a
transport.

Other temporary state is also created only through this boundary in a new,
private directory. Cleanup is handle/identity-aware and never recursively
follows a name that has been replaced.

Any unavailable API, unsupported volume, identity mismatch, ACL ambiguity,
handle error, race, or cleanup uncertainty is a hard failure. Diagnostics and
audit records expose only an allowlisted failure code.

## Trusted OpenSSH executables

`ssh.exe` and `ssh-add.exe` are resolved from the Windows system directory
returned by `GetSystemDirectoryW`, never from an environment variable,
registry value, caller input, current directory, App Paths entry, shell, or
`PATH`. On this x64-only alpha boundary, the resolved final paths must be
exactly the `OpenSSH\\ssh.exe` and `OpenSSH\\ssh-add.exe` children of that
system directory.

Before execution, the native boundary must verify every component from the
system directory through `OpenSSH` and the executable leaf. Each component
must be a non-reparse object with a stable handle identity and a DACL that
does not permit modification by an untrusted principal. The executable must
be a regular file on the system volume whose final handle path and identity
match the resolved path. Launch occurs only while that verified component
chain remains intact; an identity change or verification failure before launch
is unavailable. Authenticode verification must succeed for the executable's
catalog membership, and the signer accepted by WinTrust for that catalog must
match the Microsoft Windows publisher policy recorded with the release
evidence.

The alpha's approved signer allowlist is the Microsoft Windows certificate
with SHA-1 thumbprint `667BBA1E1F478221AA65DE4F75187A751B03A453`. Certificate
rotation is a fail-closed release change: it requires a reviewed update to the
native allowlist and this evidence before the new signer is accepted.

The runtime uses direct process APIs with `shell: false`, fixed executable
paths, POSIX argv quoting, bounded execution, and redacted output. It does not
load user or global SSH configuration, proxies, host aliases, or caller-supplied
connection options. Windows OpenSSH command execution is available only through the
native `agent-key` boundary; it is never inferred from an ambient `ssh2` agent
and never automates password prompts. Remote command execution also requires a
trusted native audit-journal provider and fails closed with an explicit audit
unavailable result before transport when it is absent.

## Authentication ordering

All authentication modes first verify the approved profile and read approved
known-hosts data through the storage boundary. `agent-key` validation then
uses its private snapshot with the verified Windows OpenSSH executables.
Password validation uses the verified bytes in an in-process transport and a
narrow Credential Manager boundary. The transport must complete the server
host-key handshake, compare the presented key with the approved data, and
signal verified identity before the Credential Manager is queried or a
password callback can release material. A host-key failure therefore requests
no credential. Passwords remain in memory and never enter arguments,
environment variables, files, logs, diagnostics, audit events, or MCP
responses.

Windows Credential Manager secrets are generic credentials whose target name
is fixed to `Vissoto/ssh-mcp-server/<opaque-locator>`. The TypeScript
Credential Manager wrapper is the approval boundary: it accepts only an
operator-approved `os://ssh/<opaque-locator>` reference and rejects it before
calling native code otherwise. The native boundary receives only that already
approved opaque locator, validates its narrow character grammar, derives the
fixed target name, and does not accept target names, shell commands, paths, or
profile fields as credential input. The `ssh2` 1.17.0 in-process client is the approved alpha
transport: its host verifier checks the approved SHA-256 fingerprint before
its authentication callback retrieves the password. It launches no child
process and does not request a shell, command, environment, or forwarding
channel.

## Required verification matrix

The Windows implementation must include deterministic tests for:

- each supported Windows, Node.js, and OpenSSH version combination;
- safe roots and files, wrong owners, broad or inherited unsafe DACLs, and
  unreadable security descriptors, including an untrusted `WRITE_DAC` ACE;
- environment, command-line, current-directory, and alternate-registry
  attempts to replace the fixed per-user root configuration,
  including untrusted `KEY_SET_VALUE`, `KEY_CREATE_SUB_KEY`, `WRITE_DAC`, and
  delete rights on the per-user configuration key. The registry DACL suite is
  table-driven and includes separate failing cases for `WRITE_OWNER`,
  `GENERIC_WRITE`, and every generic/equivalent mutation mapping;
- symbolic links, junctions, mount points, unknown reparse tags, substituted
  or mapped drives, and remote/unsupported volumes;
- replacement races for roots, state files, known-hosts files, snapshots, and
  temporary state, including replacement of the known-hosts source after the
  snapshot is captured and before SSH starts;
- executable lookup attempts through `PATH`, a substituted system directory,
  reparse points, an unsafe `OpenSSH` directory, altered identity, invalid
  signature, and unsafe DACLs; and
- host-key, agent, credential, transport, timeout, and invalid-input failures
  with redaction assertions, including an instrumented password flow proving
  no credential lookup before a successful remote host-key verification.

The controlled VPS test must exercise both successful and failing paths, but
it is not a substitute for these local security-boundary tests.

## Implementation consequences

- Issue #34 owns the handle-based storage boundary and its substitution tests.
- Issue #42 owns trusted executable verification and Windows OpenSSH
  agent-key readiness.
- Issue #38 owns the Credential Manager boundary and reviewed in-process
  password transport.
- Issue #36 composes providers only when each required boundary is available;
  otherwise it exposes no Windows validation capability.

## References

- [Node.js filesystem constants](https://nodejs.org/docs/latest-v22.x/api/fs.html#file-system-constants)
- [Win32 reparse-point operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations)
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
- [BY_HANDLE_FILE_INFORMATION](https://learn.microsoft.com/en-us/windows/desktop/api/fileapi/ns-fileapi-by_handle_file_information)
- [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/Wintrust/nf-wintrust-winverifytrust)
