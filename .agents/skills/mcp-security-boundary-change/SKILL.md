---
name: mcp-security-boundary-change
description: Change SSH MCP tool, approval, audit, profile, command, or upload security behavior. Use when modifying the public MCP boundary or its fail-closed controls.
---

# MCP security boundary change

Read `README.md`, `docs/remote-execution.md`, `docs/posix-setup.md` and the
applicable tests before changing a public MCP boundary. Preserve approved
profile discovery, host verification, bounded non-interactive execution,
redaction, durable audit and request-bound human approval.

Do not use a development change as authority to connect, execute remotely,
transfer files or alter local profile state. Update the canonical document and
focused tests with the implementation.
