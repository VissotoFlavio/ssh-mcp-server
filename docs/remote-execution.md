# Remote operations

This increment adds bounded command execution and exact SFTP upload for an
already approved SSH profile. The profile remains the source of truth for host identity,
authentication mode, known-hosts data, and credential references. MCP callers
cannot supply any of those values.

The server enforces request validation, approved-profile authorization, host
identity checks, execution bounds, mandatory durable auditing, and fail-closed
behavior. It does not maintain an allowlist of remote executables or argument
shapes. Recognized privilege-escalation executables (`sudo`, `sudoedit`, `su`,
`doas`, `dzdo`, `runuser`, and `pkexec`) additionally require exact,
request-bound, one-use human approval. Command evaluators and wrappers that
can invoke a child command, such as shells, language runtimes, `env`, `xargs`,
and `ssh`, require the same approval rather than being blocked. A command that
mutates remote state without recognized privilege escalation is not given a
second server-enforced human approval gate; it runs only with the remote
account's existing permissions. The MCP does not classify every command as
destructive, and client-side confirmation conventions are not server
authorization.

All advertised tools expose output schemas. Structured JSON results are returned
through `structuredContent` in addition to the existing JSON text content;
legacy plain-text availability errors remain text-only for compatibility.

Invalid remote-command requests fail before profile lookup or transport access.
Their stable codes distinguish an invalid request shape, command, arguments,
timeout, and output limit. The result retains a syntactically valid requested
profile ID solely for correlation; otherwise it reports `unknown`. Neither the
rejected payload nor its values are written to audit.

## Operator workflow

1. Configure and verify a profile with the [POSIX setup guide](posix-setup.md)
   or the [Windows setup guide](windows-codex-setup.md).
2. Discover the profile with `list_approved_profiles` and validate it with
   `validate_connection`.
3. Call `execute_remote_command` with `profileId`, one executable `command`,
   and an `args` array. The server treats every supplied value as a literal
   remote argument; it does not use a local shell.
4. For a command containing a privilege-escalation executable such as `sudo`,
   `sudoedit`, `su`, `doas`, `dzdo`, `runuser`, or `pkexec`, or a command
   evaluator/wrapper, call `request_action_approval` with
   `action: "remote-command"`. The MCP client must obtain explicit user
   confirmation; use the returned opaque one-time capability only with the
   unchanged request. The capability is bound to the full authorization lease
   and expires after one minute. If the request or authorization fails, the
   response preserves only its stable validation, connection, host-key,
   authentication, timeout, cancellation, or provider-failure code; it never
   exposes the underlying provider diagnostic.
5. To upload one exact Base64 file, first call `request_action_approval` with
   `action: "file-upload"`, then call `upload_remote_file` with the unchanged
   profile, absolute path, content, timeout, and one-use capability. The
   transport verifies the SHA-256 of the temporary remote file before rename.
6. Inspect the redacted local audit stream on standard error when diagnosing a
   result. It contains the bounded command/arguments, profile, approval state,
   duration, exit status, outcome, and stable code, but never stdout/stderr,
   passwords, private keys, tokens, or credential blobs.

## Safety bounds

- Default timeout: 30 seconds; maximum: 60 seconds.
- Default combined stdout/stderr limit: 64 KiB; maximum: 1 MiB.
- Cancellation aborts the channel and closes the SSH client.
- Timeout or cancellation closes the server-controlled channel/session but
  does not promise to kill a process already detached on the remote host.
- If timeout, cancellation, or transport closure happens after the command is
  handed to the remote session, the result is `outcome: "unknown"` with code
  `outcome-unknown`; callers must not retry automatically.
- Timeout, transport failure, authentication failure, host-key failure, and
  output-limit completion all close the SSH client before returning.
- Local execution uses direct process APIs or the in-process SSH2 client; a
  caller cannot enable a local shell, proxy, forwarding, or persistent session.
- Privileged-execution approval is bound to profile, command, arguments,
  timeout, and output limit plus the approved host, port, user, fingerprint,
  authentication mode, credential reference, and known-hosts reference; it
  expires after one minute and is consumed once. A second simultaneous
  approval request returns `approval-busy` without opening an SSH session.
- The durable execution journal records the intent, approval transition, and
  handoff immediately before the irreversible SSH action. Cancellation or
  expiry before handoff is `cancelled`; after handoff it is
  `outcome-unknown` and must not be retried automatically.
- If the durable audit journal cannot accept an event, the command result is
  reported as `execution-audit-unavailable`; remote success is never attempted
  without a durable intent record. A secondary diagnostic sink failure cannot
  replace `outcome-unknown` after a failed journal finalization.
- Production also requires the separate POSIX journal: set
  `SSH_MCP_AUDIT_ROOT` to an absolute operator-owned directory with no
  group/other write permission and `SSH_MCP_AUDIT_KEY_FILE` to a separate
  operator-owned `0600` file containing `v1:` plus 64 lowercase hex characters.
  The key is never generated automatically. Intent is durable before SSH and
  finished events are versioned, HMAC chained, and fdatasynced. Missing or
  interrupted finishes are `outcome-unknown` with null exit code and empty
  output; clients must not retry automatically. The POSIX journal is bounded
  at 4 MiB, rotates HMAC-linked segments before the next append, retains them
  indefinitely, and fails closed for a missing or inconsistent manifest.

## Supported operations and exclusions

The remote account's existing permissions determine whether Docker, services,
directories, or users can be administered. This server does not change those
privileges. Commands may be used for those operator-authorized tasks, subject
to the normal SSH profile and human approval boundaries.

This increment excludes interactive or persistent SSH sessions, a local shell,
download, directory listing, port forwarding, and VPS changes during automated
tests. It supports only the bounded upload described above. Shells, scripts,
redirection, and pipes can be
used only through a remote command evaluator and therefore require human
approval. The first delivery supports POSIX VPS targets from POSIX or Windows
clients; remote Windows-host quoting is future work. Integration tests are
opt-in and must use a disposable, non-production endpoint owned by the test
operator.

## Windows authentication

The Windows runtime keeps the existing trust boundary. `password` execution
continues to read only the approved Windows Credential Manager reference after
host identity verification, but remote execution also requires the trusted
native Windows audit-journal boundary. `agent-key` readiness and command
execution use the native verified OpenSSH/snapshot boundary and fail closed if
either native boundary is unavailable; they never fall back to an ambient ssh2
agent. No password, private key,
executable path, or known-hosts path is accepted from MCP input or written to
audit.

Windows `password` profiles can use the SFTP upload transport after the same
action approval and audit setup. Windows `agent-key` upload remains unavailable
until a native verified SFTP boundary exists.

Windows execution audit setup is separate from profile provisioning: an
operator must explicitly initialize the protected native journal key before
the first remote command. Rotation is an explicit native operation and is
never performed by the execution path. See
[`windows-execution-audit-journal.md`](windows-execution-audit-journal.md) for
the protected files, chain fields, durability guarantees, and recovery rule.
