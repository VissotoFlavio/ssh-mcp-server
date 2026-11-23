# SSH MCP test guidance

- Keep unit tests deterministic and free of real hosts, profiles, credentials,
  keys or production infrastructure.
- Treat the integration suite as opt-in and never point it at a VPS without
  explicit environment-owner authorization.
- Add focused coverage for fail-closed, redaction, approval and audit behavior
  when those boundaries change.
