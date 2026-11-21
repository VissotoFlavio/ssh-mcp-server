# SSH MCP source guidance

- Preserve the fail-closed boundary and the deliberately small MCP surface.
- Do not add a shell, persistent session, dynamic connection inputs, general
  file browsing, forwarding or weaker host-verification behavior.
- Keep public results redacted, bounded and stable; never emit credentials,
  keys, host identity material or raw audit data.
- Read the relevant trust-model and execution document before changing a
  security-sensitive boundary.
