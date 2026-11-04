# ssh-mcp-server

A secure, policy-driven Model Context Protocol server for approved SSH operations.

## Runtime configuration

Set `SSH_MCP_STATE_ROOT` to the absolute operator-owned directory containing the fixed `connection-profiles.json` state file. Discovery returns only approved profile identifiers and a fixed `operator-approved` classification; it never returns connection, credential, path, or host-identity details.

`validate_connection` is registered only by an embedding that injects a trusted validation provider. It accepts only `{ "profileId": "..." }`; the provider must authorize that identifier through policy and pass its immutable authorized plan directly to a readiness adapter. The MCP server does not accept commands, connection settings, credentials, or filesystem paths, and readiness adapters must not execute remote commands. Password profiles require a separately trusted credential composition; no credential source is inferred from MCP input or environment configuration. Standard POSIX runtime composition is tracked separately in #26.
