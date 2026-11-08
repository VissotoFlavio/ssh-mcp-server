# Changelog

All notable project changes are recorded here. This file does not announce or
publish a release.

## Unreleased

### Added

- A redacted `get_windows_readiness_status` MCP tool reports bounded local
  Windows readiness categories, including local credential availability and
  known-hosts identity compatibility, without returning credential material or
  contacting a remote host.
- Operational documentation and a contract test now cover the repository-scoped
  `BACKPORT_TOKEN` required by automated release and hotfix backports.
- Backport retries now recognize already merged pull requests and fail closed
  on closed, unmerged matches instead of creating duplicate pull requests.

### Fixed

- Automated backport retries now verify the existing pull request's source
  repository and deterministic branch before treating it as reusable or complete.
- Package-candidate workflow metadata validation now reads the npm lockfile's
  empty root-package key with Node.js, allowing Windows candidate packaging to proceed.
- Package-candidate reporting now gates checks and marked PR-comment mutation to
  authorized requests, uses the minimum report permissions, isolates check
  completion failures from comment publication, and fails explicitly with
  actionable guidance when reporting is unavailable.
- Windows password validation now reports redacted host-key, authentication,
  connection, and timeout failures with their stable MCP diagnostic codes.
- Windows agent-key readiness now selects the protected dedicated public key
  and its matching current-user `ssh-agent` identity without using a private-key path.
- Windows agent-key readiness uses the TypeScript non-interactive transport
  runner and its bounded authentication marker instead of ControlMaster sockets.

### Added

- An authorized `/generate-candidate` workflow for immutable Windows runtime
  package candidates on qualifying release and hotfix pull requests.
- README onboarding and a reproducible POSIX setup guide for approved SSH
  profile discovery and connection-readiness checks, including safe MCP tool
  examples and platform-specific guidance.
- Documentation for the native Windows alpha support boundary, internal
  source-checkout distribution decision, and reproducible local build process.
- A protected `master` branch based on `develop`, with the repository CI
  baseline required before changes can merge.
