---
name: windows-native-trust-change
description: Change the native Windows SSH trust or approval boundary. Use when modifying registry, Credential Manager, native addon, host verification, audit journal, or approver behavior.
---

# Windows native trust change

Read `docs/windows-trust-model.md`, `docs/windows-codex-setup.md`,
`docs/windows-execution-audit-journal.md` and relevant tests before changing
the Windows boundary. Preserve the supported native envelope, protected state,
Credential Manager isolation, host-key verification and redacted audit rules.

Never use real Windows profile, credential, host or audit-key material in
tests, logs, documentation or pull requests.
