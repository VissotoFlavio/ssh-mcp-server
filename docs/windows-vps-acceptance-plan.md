# Controlled Windows-to-VPS acceptance plan

## Purpose and boundary

This plan validates the native Windows MCP runtime against a dedicated,
non-production VPS. It is intentionally limited to SSH readiness validation:
it does not run a remote command, transfer files, modify the VPS, create
accounts, alter SSH configuration, or persist credentials outside Windows
Credential Manager.

Execution requires a separately designated non-production VPS and approved
operator profiles. Do not record the VPS address, user, profile identifier,
credential reference, host key, or any secret in this document, test output,
or pull request.

## Preconditions

- Use a supported x64 Windows host with the native addons built and the
  supported Microsoft OpenSSH installation.
- Use a non-production VPS and a least-privilege account that has already
  been provisioned by its owner. No test step changes the VPS.
- Create two locally approved profiles: one `agent-key` profile and one
  `password` profile. Store only the password profile's opaque locator in
  `connection-profiles.json`; enter its secret through the Windows Credential
  Manager UI.
- Verify the local profile and known-hosts roots meet the documented NTFS,
  ownership, DACL, and reparse-point requirements before starting Codex.
- Obtain the host key and SHA-256 fingerprint from an independent approved
  source, then create the approved local known-hosts entry. Never learn or
  accept it interactively during a test connection.
- Capture a local baseline of the MCP process's standard error audit stream
  and the non-production VPS's existing SSH audit source, if available. The
  latter is read-only evidence; do not alter VPS logging to perform this test.

## Test matrix

| Scenario               | Local setup                                                                                                              | Expected MCP result                                 | Required evidence                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Agent-key success      | Approved `agent-key` profile and loaded current-user agent key                                                           | `{ "profileId": "…", "ready": true }`               | Redacted audit record; no command argument or remote-command evidence                    |
| Password success       | Approved `password` profile and existing matching Generic Credential                                                     | `{ "profileId": "…", "ready": true }`               | Redacted audit record; Credential Manager access occurs only after host-key verification |
| Host-key mismatch      | Local test profile with a deliberately nonmatching approved fingerprint or known-hosts entry                             | Fixed `host-key-failure` result                     | No Credential Manager lookup; no secret, host, user, or key material in MCP/audit output |
| Unavailable credential | Locally approved password profile whose matching Generic Credential is absent                                            | Fixed redacted failure                              | No password is logged, passed as an argument, or returned by MCP                         |
| Timeout                | Locally approved profile targeting a pre-existing unavailable endpoint in the designated non-production test environment | Fixed `timeout` result within the configured budget | Redacted timeout audit; child/client cleanup completes                                   |
| Invalid MCP input      | Extra argument, non-object input, or invalid profile identifier                                                          | Fixed `invalid-input` result                        | No profile lookup, credential access, child process, or network connection               |

Do not replace the timeout case with an arbitrary caller-supplied host,
command, path, credential, or connection setting. Every destination is
selected only by an operator-approved local profile.

## Execution procedure

1. Start the built server through Codex using the documented absolute
   executable paths. Keep standard output reserved for JSON-RPC and collect
   standard error separately.
2. List approved profiles with an empty input object and retain only the
   count and classifications as evidence.
3. Run each matrix case through `validate_connection` with exactly one
   approved `profileId` argument, except the invalid-input case.
4. After every case, verify the MCP response and audit stream contain only
   allowlisted fields. Remove identifiers and operational metadata from the
   evidence before it is stored.
5. Compare the VPS's read-only SSH audit evidence, where available, with the
   local timestamps. Confirm there was authentication/readiness activity but
   no remote command execution.
6. Close Codex and confirm temporary snapshot and native readiness cleanup
   completed. Do not remove or alter VPS resources as part of cleanup.

## Sanitized evidence record

Record only the following fields for each case: test date, Windows/Node/OpenSSH
versions, MCP build commit, authentication mode, expected outcome, observed
fixed result code, elapsed-time bucket, redaction check, and no-remote-command
check. Mark unavailable evidence as unavailable rather than substituting
identifiers or raw logs.

The acceptance report may state whether each case passed, failed, or was not
run. It must never include raw JSON-RPC transcripts, hostnames, IP addresses,
usernames, profile IDs, Credential Manager target names, fingerprints,
known-hosts data, executable paths, or secrets.
