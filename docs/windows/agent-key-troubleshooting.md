# Windows agent-key troubleshooting

Use this runbook when the Windows MCP cannot advertise or complete
`agent-key` readiness. It is intentionally per-user: run every local step in
the same normal Windows session that starts Codex and the MCP server.

This runbook does not authorize VPS changes. Adding a public key to a remote
account requires separate authorization from that environment's owner.

## Safe sequence

1. Confirm the supported Windows, Node.js, and Microsoft OpenSSH envelope in
   the [installation guide](../windows-codex-setup.md).
2. Confirm that `ssh-agent` is running for the intended Windows user. If a
   device administrator must enable the service, do that once; never run Codex
   or the MCP elevated as a workaround.
3. Create or select a dedicated key pair in a current-user-owned NTFS
   directory with a protected DACL. The private key and its parent directory
   must not be shared with another Windows identity.
4. Load that key into the same current-user agent and keep `ssh-add -l`
   output local. It is not ticket evidence.
5. Obtain the remote host identity out of band, create the approved
   known-hosts entry, and create an `agent-key` profile containing only
   approved connection metadata.
6. Only after explicit remote-owner authorization, add the public key to the
   intended account. Never copy the private key, passphrase, or agent socket
   to the VPS or any MCP profile.
7. Run `validate_connection` with only the approved `profileId` and retain
   only sanitized evidence.

## Fail-closed cases

Stop instead of weakening controls when any of these occur:

- The key directory or either key file has a different owner, inherited ACL,
  or an ACE for an unapproved Windows identity.
- Codex and the loaded SSH agent run under different Windows users.
- `ssh-agent` has no loaded identity, is disabled, or its verified OpenSSH
  probe fails.
- The profile, known-hosts reference, or independently confirmed host
  fingerprint is missing or inconsistent.
- The remote key authorization has not been explicitly approved.

Recreate a problematic key only from the intended user's normal session. Do
not take ownership, make ACLs broader, share agent state, or bypass host-key
verification. Remove an unusable key pair only with the environment owner's
explicit authorization and target only that pair.

## Safe evidence

Keep only the date, build commit, runtime versions, authentication mode, fixed
result code, elapsed-time bucket, redaction result, cleanup result, and
no-remote-command result. Do not retain hostnames, addresses, usernames,
profile IDs, credential references, key paths, public-key fingerprints, raw
transcripts, private keys, passphrases, or passwords.
