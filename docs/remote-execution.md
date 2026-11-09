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
   boolean. Use the returned one-time token only with the unchanged request.
5. Inspect the redacted local audit stream on standard error when diagnosing a
   result. It contains the bounded command/arguments, profile, approval state,
   duration, exit status, outcome, and stable code, but never stdout/stderr,
   passwords, private keys, tokens, or credential blobs.

## Safety bounds

- Default timeout: 30 seconds; maximum: 60 seconds.
- Default combined stdout/stderr limit: 64 KiB; maximum: 1 MiB.
- Cancellation aborts the channel and closes the SSH client.
- Timeout, transport failure, authentication failure, host-key failure, and
  output-limit completion all close the SSH client before returning.
- Local execution uses direct process APIs or the in-process SSH2 client; a
  caller cannot enable a local shell, proxy, forwarding, or persistent session.
- `sudo` approval is bound to profile, command, arguments, timeout, and output
  limit plus the approved host, port, user, fingerprint, authentication mode,
  credential reference, and known-hosts reference; it expires after one minute
  and is consumed once.
- If the local audit sink cannot accept an event, the command result is
  reported as `provider-failure`; remote success is never reported without a
  delivered audit record.

## Supported operations and exclusions

The remote account's existing permissions determine whether Docker, services,
directories, or users can be administered. This server does not change those
privileges. Commands may be used for those operator-authorized tasks, subject
to the normal SSH profile and human approval boundaries.

This increment explicitly excludes interactive or persistent shells, file
transfer, port forwarding, SSH configuration changes, and VPS changes during
automated tests. Integration tests are opt-in and must use a disposable,
non-production endpoint owned by the test operator.

## Windows authentication

The Windows runtime keeps the existing trust boundary. `password` execution
continues to read only the approved Windows Credential Manager reference after
host identity verification. `agent-key` readiness continues to use the native
verified OpenSSH/identity boundary, but command execution fails closed with
`windows-agent-key-unsupported` until a command-capable native path exists; it
never falls back to an ambient ssh2 agent. No password, private key,
executable path, or known-hosts path is accepted from MCP input or written to
audit.
