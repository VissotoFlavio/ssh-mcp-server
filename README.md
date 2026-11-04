# ssh-mcp-server

A secure, policy-driven Model Context Protocol server for approved SSH operations.

## Runtime profile discovery

Set `SSH_MCP_STATE_ROOT` to the absolute operator-owned directory containing the fixed `connection-profiles.json` state file. The production server refuses to start when this setting is absent or invalid. Discovery returns only approved profile identifiers and a fixed `operator-approved` classification; it never returns connection, credential, path, or host-identity details.
