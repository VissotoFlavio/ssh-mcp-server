# Remote command execution

This increment adds one bounded MCP execution tool for an already approved SSH
profile. The profile remains the source of truth for host identity,
authentication mode, known-hosts data, and credential references. MCP callers
cannot supply any of those values.

## Operator workflow

1. Configure and verify a profile with the [POSIX setup guide](posix-setup.md)
   or the [Windows setup guide](windows-codex-setup.md).
2. Discover the profile with `list_approved_profiles` and validate it with
   `validate_connection`.
3. Call `execute_remote_command` with `profileId`, one executable `command`,
   and an `args` array. Do not put an entire shell script in `command`.
4. For a command containing `sudo`, call `request_sudo_approval`. A trusted
   `HumanSudoApprovalProvider` callback injected by the host/runtime must
   confirm the exact request. The MCP caller cannot provide an approval
   boolean. Use the returned opaque one-time capability only with the
   unchanged request. The supported local integration is the typed
   `ssh-mcp-approver` IPC contract: a private authenticated Unix socket on
   POSIX or a SID-protected named pipe on Windows. The production entrypoint
   reads the POSIX socket location only from the trusted local environment
   (`SSH_MCP_APPROVER_SOCKET`), never from MCP input. Frames are versioned and
   bound to a one-use nonce, operation ID, lease identity digest, and canonical
   request. The current Windows native addon does not expose the required
   authenticated named-pipe/SID boundary, so Windows remains unavailable until
   that explicit native dependency is supplied; it is not simulated. The
   server fails closed with `approval-unavailable` when the component is absent.
5. Inspect the redacted local audit stream on standard error when diagnosing a
   result. It contains the bounded command/arguments, profile, approval state,
   duration, exit status, outcome, and stable code, but never stdout/stderr,
   passwords, private keys, tokens, or credential blobs.

## Safety bounds

- Default timeout: 30 seconds; maximum: 60 seconds.
- Default combined stdout/stderr limit: 64 KiB; maximum: 1 MiB.
- Cancellation aborts the channel and closes the SSH client.
- Timeout or cancellation closes the server-controlled channel/session but
  does not promise to kill a process already detached on the remote host.
- Timeout, transport failure, authentication failure, host-key failure, and
  output-limit completion all close the SSH client before returning.
- Local execution uses direct process APIs or the in-process SSH2 client; a
  caller cannot enable a local shell, proxy, forwarding, or persistent session.
- `sudo` approval is bound to profile, command, arguments, timeout, and output
  limit plus the approved host, port, user, fingerprint, authentication mode,
  credential reference, and known-hosts reference; it expires after one minute
  and is consumed once.
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
  output; clients must not retry automatically.

## Supported operations and exclusions

The remote account's existing permissions determine whether Docker, services,
directories, or users can be administered. This server does not change those
privileges. Commands may be used for those operator-authorized tasks, subject
to the normal SSH profile and human approval boundaries.

This increment explicitly excludes interactive or persistent shells, scripts,
free-form redirection or pipes, file transfer, port forwarding, SSH
configuration changes, and VPS changes during automated tests. File transfer
is owned by issue #94. The first delivery supports POSIX VPS targets from
POSIX or Windows clients; remote Windows-host quoting is future work.
Integration tests are opt-in and must use a disposable,
non-production endpoint owned by the test operator.

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

Windows execution audit setup is separate from profile provisioning: an
operator must explicitly initialize the protected native journal key before
the first remote command. Rotation is an explicit native operation and is
never performed by the execution path. See
[`windows-execution-audit-journal.md`](windows-execution-audit-journal.md) for
the protected files, chain fields, durability guarantees, and recovery rule.
