# POSIX setup for Linux and macOS

This guide prepares operator-owned SSH profile state for the Linux and macOS
runtime. It is intentionally limited to profile discovery and connection
readiness; it does not authorize a remote command, deployment, file transfer,
or SSH server change.

All paths and host details below are illustrative. Replace them only with
operator-approved local paths and an already authorized destination. Do not
paste private keys, passwords, host keys, usernames, or production paths into
issues, pull requests, logs, or chat.

## Prerequisites

- Node.js 22 or later.
- An approved source checkout, built with `npm ci` followed by `npm run build`.
- Executable OpenSSH binaries at `/usr/bin/ssh` and `/usr/bin/ssh-add`. The
  POSIX runtime invokes these fixed paths; it does not select binaries through
  `PATH`.
- An operator-approved `agent-key` identity loaded in the same user's
  `ssh-agent`. POSIX production validation does not provide password
  readiness.

In the intended non-root user session, confirm the fixed client tools exist:

```sh
test -x /usr/bin/ssh
test -x /usr/bin/ssh-add
```

If either command fails, stop and fix the local prerequisite. Do not substitute
a wrapper, an arbitrary binary, or a different runtime.

## Prepare private local state

Choose two separate absolute directories owned by the same user that will run
Codex and the MCP server. Do not make either root the other's ancestor or
descendant; neither root nor its files may be symbolic links, group-writable,
or world-writable.

```sh
state_root=/absolute/path/to/ssh-mcp-state
known_hosts_root=/absolute/path/to/ssh-mcp-known-hosts

install -d -m 700 "$state_root"
install -d -m 700 "$known_hosts_root"
```

Create exactly one `connection-profiles.json` file in `$state_root`. It
contains approved connection metadata only—never a password, private key,
passphrase, token, or arbitrary filesystem path. This is an illustrative
`agent-key` profile:

```json
{
  "profiles": [
    {
      "profileId": "staging-api",
      "host": "staging-api.example.invalid",
      "port": 22,
      "user": "example-user",
      "expectedHostFingerprint": "SHA256:REPLACE_WITH_APPROVED_FINGERPRINT",
      "authMode": "agent-key",
      "approvedKnownHostsReference": "known-hosts://staging-api"
    }
  ]
}
```

Restrict the state file after writing it:

```sh
chmod 600 "$state_root/connection-profiles.json"
```

## Approve host identity out of band

For each approved profile, obtain its public host key and SHA-256 fingerprint
from an independently trusted operator source. Verify that source against the
profile metadata, then place the approved public host-key entry in the fixed
leaf:

```text
$known_hosts_root/staging-api.known_hosts
```

Restrict that leaf:

```sh
chmod 600 "$known_hosts_root/staging-api.known_hosts"
```

Do not use `ssh-keyscan`, an interactive first-connection prompt, or an
unverified user SSH configuration to approve a host key. If the approved key or
fingerprint is unavailable or inconsistent, stop rather than weakening host
verification.

## Prepare the approved agent identity

Load only a key already approved for the target environment into the
current user's agent. This action requires the environment owner's
authorization; it is not performed by the MCP server.

```sh
/usr/bin/ssh-add /absolute/path/to/an-operator-approved-private-key
/usr/bin/ssh-add -l
```

Keep the identity listing local. Do not add a key solely to make a readiness
test pass, and do not copy a key, passphrase, or agent socket path into profile
state or Codex configuration.

## Register and verify the MCP server

Register the POSIX roots explicitly so Codex passes them to the stdio process
every time it starts:

```sh
codex mcp add ssh-mcp-server \
  --env SSH_MCP_STATE_ROOT=/absolute/path/to/ssh-mcp-state \
  --env SSH_MCP_KNOWN_HOSTS_ROOT=/absolute/path/to/ssh-mcp-known-hosts \
  -- /absolute/path/to/node /absolute/path/to/ssh-mcp-server/dist/server.js

codex mcp list
```

Restart Codex if its client requires it, then first call
`list_approved_profiles` with `{}`. Call `validate_connection` only with a
`profileId` returned by discovery (for example, `staging-api`) and only when
the operator has authorized that readiness check. The MCP request contains no
host, user, path, credential, SSH option, or command.

Treat an absent tool, an error result, or `ready: false` as a hard stop. Do
not retry with a guessed profile ID or convert the result into permission for a
remote change.

## Windows is different

This guide does not apply to native Windows alpha. Windows reads its state and
known-hosts roots only from protected per-user registry values, not
`SSH_MCP_STATE_ROOT` or `SSH_MCP_KNOWN_HOSTS_ROOT`. Follow the
[Windows installation and Codex setup](windows-codex-setup.md) instead.
