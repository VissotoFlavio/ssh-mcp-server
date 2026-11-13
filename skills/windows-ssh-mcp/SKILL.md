---
name: windows-ssh-mcp
description: Safely discover and validate operator-approved Windows SSH MCP profiles.
---

# Windows SSH MCP safe operation

Use this skill only for local discovery, redacted Windows readiness diagnosis,
and readiness validation of an already approved profile. Readiness is not
authorization to run a remote command, open a shell, transfer a file, deploy,
change a VPS, or alter any remote state.

## Allowed MCP calls

Use only these MCP interfaces, with the exact inputs shown:

1. `list_approved_profiles` with `{}`. This is the only way to discover a
   profile ID. Never invent, normalize, or repeat a host-derived identifier.
2. `get_windows_readiness_status` with `{}` when it is advertised. It returns
   bounded local categories and never accepts a profile ID or connection data.
3. `validate_connection` with `{ "profileId": "<id returned by discovery>" }`
   only when it is advertised and the ID came from the current discovery
   result. Do not add any other field.

Never send or request a host, port, user, path, command, host key,
fingerprint, password, token, private key, credential value, or dynamic SSH
setting. If a caller supplies one, refuse it and continue with no MCP call.

## Procedure

1. Call `list_approved_profiles` with `{}`.
2. If discovery is unavailable, call `get_windows_readiness_status` with `{}`
   if that tool is advertised. Use only its enum values to choose local
   troubleshooting; never infer or disclose hidden connection metadata.
3. If discovery returns no profile ID, stop. Do not manufacture an ID or ask
   the operator to paste profile state into the conversation.
4. If `validate_connection` is absent, report that readiness validation is
   unavailable and follow the local status category. Do not pass connection
   settings as a workaround.
5. Call `validate_connection` once with only the discovered `profileId`.
   Report only the redacted success or failure category. Do not repeat secrets
   or connection details from errors.

## Readiness status contract

When `get_windows_readiness_status` is advertised, inspect only this fixed
schema and its enum values; ignore unknown fields and never print the object
verbatim:

- `runtime`: `ready` or `unsupported` (`unsupported` maps to the
  `unsupported` action below).
- `registry`: `ready`, `unavailable`, `invalid`, or `not-checked` (maps to
  `registry`).
- `filesystem`: `ready`, `unavailable`, `invalid`, or `not-checked` (maps to
  `filesystem`).
- `configuration`: `ready`, `unavailable`, `invalid`, or `not-checked` (maps
  to `configuration`).
- `knownHosts`: `ready`, `unavailable`, `invalid`, or `not-checked` (maps to
  `known-hosts`).
- `credentials`: `ready`, `unavailable`, or `not-checked` (maps to
  `credential`).
- `validationProvider`: `ready`, `unavailable`, `invalid`, or `not-checked`
  (maps to `provider`).
- `remoteAuthentication`: always `not-checked`; it never authorizes a remote
  operation.

Do not reinterpret enum values as connection details. A `ready` local field is
not proof that a remote connection or authentication succeeded.

## Redacted category actions

Use this table as a local decision path. Actions involving a VPS or network
must be performed by the environment owner through the normal administration
process, not by this MCP skill.

| Category                 | Safe next action                                                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `unsupported`            | Stop and consult the Windows setup guide for the supported x64 Windows, Node.js, and OpenSSH envelope. Do not bypass the runtime gate.                                   |
| `registry`               | Inspect the current user's protected registry readiness using the setup guide. Do not hand-edit keys or relax ACLs.                                                      |
| `filesystem`             | Inspect the fixed protected roots, ownership, DACL, NTFS, and reparse status. Do not replace or re-ACL state without explicit environment-owner authorization.           |
| `configuration`          | Inspect the fixed profile state through the documented local procedure. Do not hand-author JSON or add connection fields.                                                |
| `known-hosts`            | Re-check independently approved host-key material and its fingerprint locally. Do not use TOFU, `ssh-keyscan`, or paste key material into support.                       |
| `credential`             | Create or verify the matching Windows Generic Credential in Credential Manager UI for the opaque reference. Enter the password only there; never expose it to the skill. |
| `provider`               | Check the supported native provider composition and restart/reload the MCP client. Do not supply dynamic connection settings.                                            |
| `authentication-failure` | Check the matching Credential Manager entry and the Windows identity running the MCP. Do not copy or export the password.                                                |
| `host-key-failure`       | Stop and correct the approved local host-identity material through the environment owner's process. Do not accept a first-connection prompt.                             |
| `timeout`                | Investigate bounded local runtime health and, separately, authorized VPS/network availability. Do not increase timeouts blindly or start an interactive SSH command.     |
| `connection-failure`     | Have the environment owner inspect authorized network reachability and SSH service state. Do not change host, port, options, or known-hosts policy in the MCP request.   |

## Credential and evidence rules

Credential Manager is the only password-entry surface for Windows password
profiles. Keep passwords, private keys, host keys, fingerprints, hosts,
usernames, paths, profile IDs, credential locators, and raw diagnostics out of
chat, tickets, logs, prompts, and skill output. Retain only the redacted
category and non-sensitive runtime information needed for local support.

The skill must never claim that a successful readiness result authorizes a
remote operation. A successful result means only that the approved profile's
bounded readiness check completed.
