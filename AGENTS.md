# SSH MCP Server project rules

## Agent guidance hierarchy

- Keep universal repository policy in this root `AGENTS.md`; use scoped files
  only for directory-specific guidance.
- Keep implemented security and operating behavior in `docs/`, and narrow
  reusable workflows in `.agents/skills/`.
- Read `docs/agent-guidance.md` before adding or changing rules or skills.
- Do not put local settings, profiles, credentials, MCP configuration or hooks
  in versioned agent guidance.

## GitHub, branches and CI

- Use only `gh` for GitHub operations and run `gh auth status` before them.
- Every delivery requires a GitHub issue, except releases. Never commit
  directly to `develop` or `master`.
- Feature branches use `feature/<issue-id>-<slug>` from and to `develop`.
  Releases use `release/<version>` from `develop` to `master`; hotfixes use
  `hotfix/<issue-id>-<slug>` from `master` to `master`.
- Confirm the base branch explicitly before creating a non-release branch.
  Pull requests require `Closes #<issue-number>` except releases.
- Before opening a PR, inspect the final diff, run relevant validation and
  update `CHANGELOG.md` when a change is release-facing.
- CI validates pull requests and may generate approved package candidates; it
  never authorizes remote SSH operations, changes an operator profile, deploys
  a VPS or publishes an npm package. Keep permissions minimal and secrets out
  of workflows, logs and pull requests.
- Merge, release publication and any remote or infrastructure mutation require
  explicit user authorization.

## Security boundaries

- The server is fail-closed. Preserve approved-profile discovery, host identity
  verification, redaction, bounded non-interactive execution, durable audit and
  request-bound human approval boundaries.
- Never accept, request, log or document agent-supplied connection settings,
  hosts, credentials, private keys, host keys, tokens or real profile data.
- Read the applicable document under `docs/` before changing behavior that
  affects Windows trust, POSIX state, remote execution, uploads or audit.
