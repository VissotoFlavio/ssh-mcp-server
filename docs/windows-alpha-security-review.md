# Windows alpha security review

## Candidate and scope

This review covers the native Windows alpha candidate at
`91afc14c769b1aaeeb54f4f3bb4f186e2e5b11d4` on `develop`. It assesses the
MCP boundary and the Windows-specific controls for approved profile storage,
known-hosts snapshots, OpenSSH executable resolution, agent-key readiness,
Credential Manager password access, host-key verification, process handling,
and diagnostic redaction.

It is a security review record, not release approval. A controlled
non-production VPS acceptance run remains separate work.

## Review conclusion

No confirmed security finding was identified in the reviewed candidate.

The review confirmed that the implementation fails closed for unsafe ACLs,
reparse points, identity changes, unsupported volumes, untrusted executables,
malformed credential locators, and caller-controlled connection input. Both
authentication paths verify host identity before using a credential. MCP
responses and diagnostics are allowlisted, and standard output remains
reserved for JSON-RPC.

## Evidence

- Independent behavioral review: approved, with no actionable finding.
- Independent security review: approved, with no confirmed vulnerability.
- Local Windows validation completed with Node.js 24.13.0:
  - `npm run format:check`
  - `npm run lint`
  - `npm test`
  - `npm run build`
  - `npm run build:native`

The native production and test addons were built successfully. Two symlink
test cases were skipped because this local Windows host does not permit
symlink creation for the current user; all executable test cases passed.

## Residual risk and exclusions

The candidate relies on Windows ACL and kernel guarantees plus the pinned
Microsoft signing policy described in the Windows trust model. This review did
not connect to a VPS, create test credentials, modify any VPS, merge a pull
request, create a tag, or publish a release.
