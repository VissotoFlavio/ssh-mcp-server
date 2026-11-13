# Windows password-profile setup and troubleshooting

This runbook covers the password authentication path for the supported native
Windows runtime. It does not replace the [Windows installation and Codex
setup](../windows-codex-setup.md) guide or the [Windows trust model](../windows-trust-model.md).

## Safe setup sequence

1. Provision the approved profile with the repository's Windows helper. Supply
   the approved host-key line and SHA-256 fingerprint only in that local,
   operator-controlled command. The helper verifies the host identity before
   it writes protected state.
2. Create a Windows **Generic Credential** in the current user's Credential
   Manager UI. If the profile uses the opaque locator `os://ssh/<locator>`, the
   matching Credential Manager target is exactly
   `Vissoto/ssh-mcp-server/<locator>`.
3. Enter the password only in Credential Manager. The password must not appear
   in a command, environment variable, profile JSON, Codex configuration, or
   support record.
4. Restart or reload the MCP client, call `list_approved_profiles`, and use a
   returned `profileId` with `validate_connection`. Do not supply a host, user,
   port, path, key, fingerprint, or command to the MCP tool.

Password validation verifies the approved host identity first and reads the
Credential Manager secret only after that check succeeds. A host-key failure
therefore must never be worked around by entering or sharing a password.

## Redacted decision path

Use the stable result category to choose the next local action. The MCP result
is deliberately redacted; it is not evidence that a remote command is
authorized.

| Result category          | First action                                                                                                                                                                            | Do not do                                                                                                             |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `host-key-failure`       | Stop and re-check the independently approved host-key material and the protected local known-hosts leaf.                                                                                | Do not accept a first-connection prompt, use `ssh-keyscan`, or enter a password to test a different identity.         |
| `authentication-failure` | Confirm that the matching Generic Credential exists for the opaque locator and that the intended Windows user owns the MCP process.                                                     | Do not paste or export the password, change the profile to a different user, or weaken Credential Manager/ACL policy. |
| `provider-failure`       | Check that the supported Windows runtime, native addon, Credential Manager provider, and protected registry/filesystem state are available.                                             | Do not pass connection settings to the tool or replace state by hand.                                                 |
| `timeout`                | Check local runtime health and the authorized VPS/network availability through the environment's normal administration process. Retry only after the bounded local issue is understood. | Do not increase an MCP timeout blindly or launch an interactive SSH command from the agent.                           |
| `connection-failure`     | Check the approved environment's network reachability and SSH service status through the operator's normal, authorized VPS process.                                                     | Do not change the host, port, SSH options, or known-hosts policy in the MCP request.                                  |

The distinction is intentional: host identity and local provider checks are
performed by the MCP boundary; VPS-side service, firewall, routing, account
authorization, and command permissions belong to the environment owner. The
MCP can execute only bounded, non-interactive commands from an approved
profile; `validate_connection` itself never authorizes or runs a command.

For a controlled execution check, validate the approved profile first, then
use `execute_remote_command` with a fixed executable and argv such as
`docker` with `args: ["ps"]`. Treat timeout or cancellation after handoff as
`outcome-unknown` and do not retry automatically. Privilege-escalation
commands still require the separate trusted `request_sudo_approval` flow.

## Safe support record

Record only the category, the MCP/server version, Node.js major version,
Windows version, and whether the required local tool was present. Never copy a
password, host key, fingerprint, username, host, profile ID, credential
locator, filesystem path, registry path, or raw diagnostic text into a ticket
or chat. If a failure requires repair, stop and have the environment owner
inspect the named local state using the approved Windows administration
procedure; do not hand-edit profile JSON or ACLs.
