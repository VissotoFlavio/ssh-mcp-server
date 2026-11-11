# Changelog

All notable project changes are recorded here. This file does not announce or
publish a release.

## Unreleased

### Added

- Added the native Windows execution-audit provider with Credential Manager
  HMAC keys, explicit operator initialization/rotation, session-aware recovery,
  durable rotation events, bounded mutex acquisition, stable SSH failure codes,
  and key-buffer cleanup.
- Added authenticated POSIX `ssh-mcp-approver` framing with an owner-only
  installation secret, request/response HMACs, fragmented-frame coverage, and
  cross-process audit-journal locking. The authenticated local request now
  carries the immutable destination presentation for human confirmation.
- Bound the POSIX production execution factory to the same validated
  authorization lease used for readiness, and preserved native Windows
  host-key, authentication, connection, and remote failure classifications.
- Added approval gating for common privilege-escalation executables, preserved
  `outcome-unknown` after an interrupted SSH session, kept fallback approvals
  on immutable profile snapshots, and redacted compact password flags such as
  `-psecret` from local audit records.
- Bound sudo approval tokens to the validated execution authorization lease and
  report missing approval infrastructure as `failure` with
  `approval-unavailable` before transport.
- Added the separate POSIX `ExecutionAuditJournal` with explicit versioned
  256-bit HMAC key handling, durable intent/finished JSONL events, chained
  integrity checks, and fail-closed behavior for missing, rotated, or invalid
  audit state. Remote results now carry opaque operation IDs and expose
  `outcome-unknown` without automatic retry.
- Added the typed `ssh-mcp-approver` IPC contract for request-bound human sudo
  approval (Unix socket on POSIX or SID-protected named pipe on Windows). A
  real authenticated host component is still required; the server remains fail
  closed when no trusted callback is present.
- Documented that timeout/cancellation closes the server-controlled SSH
  session without promising termination of detached remote processes; the
  first delivery targets POSIX hosts from POSIX or Windows clients, excludes
  remote Windows-host quoting, shells/scripts/redirection/pipes, file transfer,
  and port forwarding, and leaves file transfer to issue #94.
- Bounded audit journals at 4 MiB with durable short-write checks, preserved
  public host-key/authentication failure classes from authorization, and
  classified timeout or cancellation after command handoff as
  `outcome-unknown`.
- Hardened POSIX chain validation against orphaned/unknown events, made
  Windows audit-key replacement atomic, and preserved `outcome-unknown` when
  the native Windows command process fails after launch.

- The remote execution candidate now accepts an explicit host-injected human
  approval provider, binds approvals to the complete approved profile identity,
  fails closed when durable audit state is unavailable, bounds validation as
  well as transport, rejects shell/script interpreters and control syntax, and
  records only allowlisted argument shapes plus an HMAC digest of the original
  vector.
- Windows agent-key command execution now uses the exported native OpenSSH
  command boundary with an opaque approved known-hosts snapshot, bounded
  output, cancellation, and process-tree cleanup; it never uses an ambient
  ssh2 agent. Windows password execution retains the existing Credential
  Manager and host-verification boundary.
- Bounded `execute_remote_command` and `request_sudo_approval` MCP tools now
  execute only through approved SSH profiles, enforce timeout/cancellation and
  output limits, require request-bound expiring one-time human approval for
  `sudo`, and emit redacted local command audit records. Interactive persistent
  shells, file transfer, and port forwarding remain explicitly excluded.
- POSIX and Windows runtime composition now reuses the existing host-identity,
  Credential Manager, trusted executable, and approved-profile boundaries for
  non-interactive SSH execution, with focused unit coverage and operational
  documentation.
- A fail-closed Windows operator provisioning helper creates one protected
  approved profile and verified known-hosts leaf from fixed per-user roots,
  without accepting secrets or contacting a remote host.
- A redacted `get_windows_readiness_status` MCP tool reports bounded local
  Windows readiness categories, including local credential availability and
  known-hosts identity compatibility, without returning credential material or
  contacting a remote host.
- Operational documentation and a contract test now cover the repository-scoped
  `BACKPORT_TOKEN` required by automated release and hotfix backports.
- Windows password-profile setup and troubleshooting now document host-identity
  ordering, Credential Manager target derivation, redacted failure decisions,
  and safe support-record boundaries.
- A versioned Codex skill now guides Windows SSH MCP discovery, redacted local
  readiness diagnosis, and approved-profile validation without accepting
  dynamic connection settings or authorizing remote commands.
- Backport retries now recognize already merged pull requests and fail closed
  on closed, unmerged matches instead of creating duplicate pull requests.

### Fixed

- Automated backport retries now verify the existing pull request's source
  repository and deterministic branch before treating it as reusable or complete.
- Package-candidate workflow metadata validation now reads the npm lockfile's
  empty root-package key with Node.js, allowing Windows candidate packaging to proceed.
- Package-candidate generation now gates packaging on the four exact successful
  CI check-runs for the immutable pull-request SHA, reports actionable blockers,
  and avoids repeating general validation while retaining Windows Node.js 22 and
  24 build, inspection, and packaging.
- Candidate check selection now requires canonical GitHub Actions workflow
  provenance, chooses the newest attempt by start time and id, and uses a
  trusted package gate before Windows packaging plus an immediate publication
  revalidation. The trusted verifier also requires the canonical workflow blob
  and content to match the trusted default-branch revision and each workflow run to belong to
  the exact same-repository pull request.
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
