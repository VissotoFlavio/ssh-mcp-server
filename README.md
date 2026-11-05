# ssh-mcp-server

A secure, policy-driven Model Context Protocol server for approved SSH operations.

The planned native Windows alpha has a separate, fail-closed
[Windows trust model](docs/windows-trust-model.md), including its
per-user configuration boundary. Windows configuration and approved state are
never shared across local users, and the MCP does not require administrator
execution. The current production runtime remains supported on Linux and macOS
only.

For the Windows alpha's supported host envelope, per-user installation, secure
state layout, and Codex stdio configuration, see
[Windows installation and Codex setup](docs/windows-codex-setup.md). The
current Windows composition intentionally exposes discovery only; it does not
advertise connection validation until every required trusted boundary can be
composed.

## Runtime configuration

Set `SSH_MCP_STATE_ROOT` to the absolute operator-owned directory containing the fixed `connection-profiles.json` state file. Set `SSH_MCP_KNOWN_HOSTS_ROOT` to a separate absolute operator-owned directory containing one `<profile-id>.known_hosts` file for each approved `known-hosts://<profile-id>` reference. On supported POSIX hosts, both roots and their files must be owned by the MCP process user, have no group/other write bits, and contain no symbolic links. Discovery returns only approved profile identifiers and a fixed `operator-approved` classification; it never returns connection, credential, path, or host-identity details.

`validate_connection` is registered only by an embedding that injects a trusted validation provider. The standard entrypoint injects the POSIX agent-key provider on Linux and macOS; Windows remains fail-closed until its native agent-key readiness operation is cancellable and all profile prerequisites can be proven before tool registration. It accepts only `{ "profileId": "..." }`; the provider authorizes that identifier through policy, validates `ssh-add -l`, snapshots the approved known-hosts file privately, and uses an OpenSSH ControlMaster readiness check without a remote command. The MCP server does not accept commands, connection settings, credentials, or filesystem paths. Password profiles require a separately trusted credential composition; no credential source is inferred from MCP input or environment configuration.
