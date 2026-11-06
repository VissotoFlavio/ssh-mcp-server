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
- For `agent-key` success, the key must be generated and loaded by the same
  normal Windows user that runs Codex. Stop on an ownership, protected-DACL,
  agent-service, or identity-loading failure; do not run Codex elevated or
  weaken local security controls as a workaround.
- For timeout, obtain an owner-designated, pre-existing unavailable
  non-production endpoint and an approved local profile before testing. Do
  not invent an address, repurpose production, or make an endpoint unavailable
  to create this case.

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

When a prerequisite is unavailable, record only its category (for example,
current-user key ownership, agent identity, or approved timeout endpoint) and
mark the case as not run. Do not include raw ACL output, key material, service
configuration, or connection details.

## Sanitized execution evidence

On 2026-11-06, a controlled password-authentication readiness check completed
against the designated non-production VPS. The local environment was Windows
build 26200, Node.js 24.13.0, and Microsoft OpenSSH 9.5p2. The operator
independently confirmed the host-key fingerprint before it entered the private
known-hosts store.

Approved-profile discovery returned one password profile. The MCP
`validate_connection` call returned `ready: true` and emitted the allowlisted
success audit event. The in-process password transport opened no session,
channel, command, file transfer, or forwarding request, so it made no change
to the VPS.

On the same environment, controlled non-secret local profiles were added only
for the duration of three negative checks and the original profile state was
restored after the run. A deliberately different host fingerprint returned
`host-key-failure` in less than one second. An approved password profile with
no matching Generic Credential returned `authentication-failure` in less than
one second. Invalid MCP input returned `invalid-input` in less than one
second. Each result had the same allowlisted audit code, and no test output or
audit record retained connection identifiers, credential references,
fingerprints, paths, or secrets. The negative checks issue no remote command;
the host-key check stops before credential lookup, the unavailable-credential
check cannot release a password, and invalid input stops before profile lookup
or network activity.

The agent-key success path and timeout matrix entry remain pending. They
require a pre-authorized current-user agent identity and a pre-existing
unavailable non-production endpoint; this evidence does not claim those cases
passed.
