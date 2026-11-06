# ssh-mcp-server

A secure, policy-driven Model Context Protocol server for approved SSH operations.

The planned native Windows alpha has a separate, fail-closed
[Windows trust model](docs/windows-trust-model.md), including its
per-user configuration boundary. Windows configuration and approved state are
never shared across local users, and the MCP does not require administrator
execution. Linux and macOS use the standard provider; on the supported Windows
alpha envelope, validation is additionally available only when every native
trust, OpenSSH-agent, known-hosts, and Credential Manager boundary is present.

For the Windows alpha's supported host envelope, per-user installation, secure
state layout, and Codex stdio configuration, see
[Windows installation and Codex setup](docs/windows-codex-setup.md). The
Windows runtime advertises `validate_connection` only when every required
trusted boundary is available; otherwise it omits the tool and fails closed.

The internal alpha distribution decision, reproducible build process, and
protected delivery boundary are recorded in
[Native Windows alpha delivery boundary](docs/windows-alpha-delivery.md).

## Runtime configuration

Set `SSH_MCP_STATE_ROOT` to the absolute operator-owned directory containing the fixed `connection-profiles.json` state file. Set `SSH_MCP_KNOWN_HOSTS_ROOT` to a separate absolute operator-owned directory containing one `<profile-id>.known_hosts` file for each approved `known-hosts://<profile-id>` reference. On supported POSIX hosts, both roots and their files must be owned by the MCP process user, have no group/other write bits, and contain no symbolic links. Discovery returns only approved profile identifiers and a fixed `operator-approved` classification; it never returns connection, credential, path, or host-identity details.

`validate_connection` is registered only when its complete trusted provider is available. The standard entrypoint injects the POSIX agent-key provider on Linux and macOS and the native Windows provider on its supported envelope. It accepts only `{ "profileId": "..." }`; the provider authorizes that identifier through policy, validates `ssh-add -l`, snapshots the approved known-hosts file privately, and uses a cancellable native OpenSSH ControlMaster readiness check without a remote command. The MCP server does not accept commands, connection settings, credentials, or filesystem paths. Password profiles require a separately trusted credential composition; no credential source is inferred from MCP input or environment configuration.
