# Changelog

All notable project changes are recorded here. This file does not announce or
publish a release.

## Unreleased

### Fixed

- Windows password validation now reports redacted host-key, authentication,
  connection, and timeout failures with their stable MCP diagnostic codes.
- Windows agent-key readiness now selects the protected dedicated public key
  and its matching current-user `ssh-agent` identity without using a private-key path.
- Windows agent-key readiness uses the TypeScript non-interactive transport
  runner and its bounded authentication marker instead of ControlMaster sockets.

### Added

- README onboarding for approved SSH profile discovery and connection-readiness
  checks, including safe MCP tool examples and platform-specific guidance.
- Documentation for the native Windows alpha support boundary, internal
  source-checkout distribution decision, and reproducible local build process.
- A protected `master` branch based on `develop`, with the repository CI
  baseline required before changes can merge.
