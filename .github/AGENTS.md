# SSH MCP workflow guidance

- Preserve the distinction between CI validation, internal package candidates
  and any future distribution decision.
- Do not add production SSH access, operator profile state, credentials or
  remote execution to workflows.
- Candidate generation must preserve its exact branch, check and immutable
  commit requirements. Keep workflow permissions minimal.
