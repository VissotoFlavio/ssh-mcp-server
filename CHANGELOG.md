# Changelog

All notable project changes are recorded here. This file does not announce or
publish a release.

## Unreleased

### Fixed

- Windows password validation now reports redacted host-key, authentication,
  connection, and timeout failures with their stable MCP diagnostic codes.
- Windows agent-key readiness now permits the approved current-user
  `ssh-agent` identity when no private-key path is available to the MCP.

### Added

- Documentation for the native Windows alpha support boundary, internal
  source-checkout distribution decision, and reproducible local build process.
- A protected `master` branch based on `develop`, with the repository CI
  baseline required before changes can merge.
