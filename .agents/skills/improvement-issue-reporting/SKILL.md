---
name: improvement-issue-reporting
description: Create public GitHub improvement and suggestion issues for SSH MCP Server with safe optional context and the enhancement label. Do not use for bug reports, implementation work, or suspected vulnerabilities.
---

# Public improvement issue reporting

Use this skill to draft or open a public GitHub issue proposing an improvement,
new capability, or user-facing suggestion for this repository. The objective is
to describe the need and desired outcome without presuming a solution. All
context fields are optional: include what is known and omit what is not. More
safe context makes discussion and prioritization more useful.

## Discover the repository and its requirements

1. Work from the repository root. Read the applicable `AGENTS.md` files and
   any issue templates or issue configuration under `.github/`.
2. Before a GitHub operation, run `gh auth status`. Use only `gh` for GitHub
   operations and run it outside the sandbox when the environment requires it.
3. Resolve the target from the current checkout with `gh repo view --json
nameWithOwner,url`. Do not assume or hard-code an owner or repository name.
4. Search open and closed issues for a likely duplicate before creating a new
   proposal. If one appears to match, present it to the requester rather than
   opening a duplicate unless they explicitly want a separate discussion.
5. Verify that the repository has the `enhancement` label. If it does not,
   report that blocker; do not silently substitute another label or create a
   label without authorization.

## Collect safe context

Use the following structure when the information is available:

- **Summary:** a short description of the suggestion.
- **Need or user scenario:** the problem, limitation, or use case it would
  address.
- **Desired outcome:** what would be improved without treating a proposed
  implementation as the only solution.
- **Proposed approach:** an idea for the change, if one exists.
- **Alternatives and workarounds:** existing approaches considered and why they
  do not fully meet the need.
- **Constraints or non-goals:** important boundaries, compatibility concerns,
  or intentionally excluded behavior.
- **Safe evidence and examples:** sanitized screenshots, examples, references,
  or prior discussion that explains the request.
- **Technical context, when relevant:** operating system and version;
  environment; SSH MCP Server and MCP client versions; AI agent/tool; LLM model
  and version or snapshot; and relevant runtime versions.
- **Security relevance:** whether the proposal concerns approval, audit, remote
  execution, upload, or host-identity verification.

Do not assign priority, severity, or urgency classifications. Omit empty
sections rather than filling them with placeholders.

## Public-report safety boundary

Public issues must not contain credentials, tokens, private keys, host names,
IP addresses, host fingerprints, real profile names, connection details,
unredacted configuration files, or unsanitized logs. Remove or generalize
those details before drafting the proposal.

If the proposal could describe a vulnerability or a way to bypass approval,
identity verification, redaction, audit, or another security boundary, do not
open a public issue. Check the repository's documented private security
reporting channel, including `SECURITY.md` or the repository security policy.
If no suitable channel is documented, explain the limitation and ask the
maintainer for a private reporting route. Do not reproduce exploitable details
in the title, body, or comments.

## Draft and open the issue

Use a concise, outcome-oriented title, such as `enhancement: show audit-journal
health in readiness results`. Use real Markdown paragraphs and headings in the
body, then review the final title and body for sensitive information and
duplicate reporting.

When opening a normal proposal, apply exactly the `enhancement` label in
addition to any label explicitly requested by the requester:

```text
gh issue create --repo <owner/repository> --title <title> --label enhancement --body-file <markdown-file>
```

Report the created issue URL and the `enhancement` label after a successful
creation.
