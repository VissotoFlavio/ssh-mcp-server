---
name: bug-issue-reporting
description: Create public GitHub bug reports for SSH MCP Server with safe optional diagnostic context and the bug label. Do not use for feature requests, implementation work, or suspected vulnerabilities.
---

# Public bug issue reporting

Use this skill to draft or open a public GitHub issue for unexpected behavior
in this repository. The objective is a concise, reproducible report with
enough safe context to investigate it. All diagnostic fields are optional:
include what is known and omit what is not. Never invent a version, an
environment detail, or a reproduction step.

## Discover the repository and its requirements

1. Work from the repository root. Read the applicable `AGENTS.md` files and
   any issue templates or issue configuration under `.github/`.
2. Before a GitHub operation, run `gh auth status`. Use only `gh` for GitHub
   operations and run it outside the sandbox when the environment requires it.
3. Resolve the target from the current checkout with `gh repo view --json
   nameWithOwner,url`. Do not assume or hard-code an owner or repository name.
4. Search open and closed issues for a likely duplicate before creating a new
   report. If one appears to match, present it to the requester rather than
   opening a duplicate unless they explicitly want a separate report.
5. Verify that the repository has the `bug` label. If it does not, report that
   blocker; do not silently substitute another label or create a label without
   authorization.

## Collect safe context

Use the following structure when the information is available. State near the
top that every field is optional and that more safe context improves the
accuracy of the investigation.

- **Summary:** a short statement of the problem.
- **Expected behavior:** what should have happened.
- **Observed behavior:** what happened instead, including a safe error summary.
- **Reproduction steps:** the smallest repeatable sequence, prerequisites, and
  frequency if known.
- **Safe evidence:** sanitized logs, stack traces, or screenshots.
- **Technical context:** operating system and version; local, CI, or other
  execution environment; SSH MCP Server version; MCP client and version; AI
  agent/tool; LLM model and version or snapshot when available; and relevant
  runtime versions such as Node.js, npm, or PowerShell.
- **Affected area, hypotheses, and attempts:** the suspected component and
  troubleshooting already tried, clearly marked as non-confirmed.
- **Security relevance:** whether it concerns approval, audit, remote
  execution, upload, or host-identity verification.
- **Safe workaround:** a temporary mitigation, if one exists.

Do not add priority, severity, or urgency classifications. Do not add
acceptance criteria to a problem report.

## Public-report safety boundary

Public issues must not contain credentials, tokens, private keys, host names,
IP addresses, host fingerprints, real profile names, connection details,
unredacted configuration files, or unsanitized logs. Remove or generalize
those details before drafting the report.

If the report could describe a vulnerability or a way to bypass approval,
identity verification, redaction, audit, or another security boundary, do not
open a public issue. Check the repository's documented private security
reporting channel, including `SECURITY.md` or the repository security policy.
If no suitable channel is documented, explain the limitation and ask the
maintainer for a private reporting route. Do not reproduce exploitable details
in the title, body, or comments.

## Draft and open the issue

Use a factual title, such as `bug: command approval is rejected after restart`.
Avoid assertions about root cause unless evidence establishes it. Omit empty
sections rather than filling them with placeholders.

Use real Markdown paragraphs and headings in the issue body. Review the final
title and body for sensitive information and duplicate-reporting before
submitting. When opening a normal problem report, apply exactly the `bug`
label in addition to any label explicitly requested by the requester:

```text
gh issue create --repo <owner/repository> --title <title> --label bug --body-file <markdown-file>
```

Report the created issue URL and the `bug` label after a successful creation.
