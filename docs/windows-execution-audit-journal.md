# Windows execution audit journal

The Windows runtime stores its execution journal under the protected native
`StateRoot` configured at `HKCU\Software\Vissoto\ssh-mcp-server`. The native
provider stores HMAC keys as Windows Generic Credentials under the fixed
`Vissoto/ssh-mcp-server/execution-audit/<key-id>` target prefix and never
returns key bytes to JavaScript, MCP, or an SSH transport. It records only
redacted intent metadata, `argsHmac`, and a finished outcome; stdout, stderr,
passwords, private keys, and credential blobs are not journal data.

Before the first execution on a newly provisioned profile, an operator must
explicitly call the native `initializeExecutionAuditKey()` operation. Key
rotation is also explicit through `rotateExecutionAuditKey()`. The server
never creates or rotates a key while handling an execution. Rotation retains
prior Windows Generic Credentials so the complete HMAC chain remains
verifiable.

From the repository or an installed candidate package, the operator can run:

```powershell
npm run windows:audit:init
npm run windows:audit:rotate
```

Initialization is required once per protected state root; rotation is only for
an already initialized journal. Both commands fail closed if the existing
configuration is unsafe or the requested state already exists.

Each append validates the fixed root and leaf owner/DACL, rejects reparse
points, checks file identity, serializes access through a named mutex, and
calls `FlushFileBuffers` before returning. The JSONL chain contains `keyId`,
`previousEventHmac`, and `eventHmac`. An interrupted intent is closed with
`outcome: "unknown"` and `code: "outcome-unknown"` before the next intent is
accepted. Any missing key, unsafe file, tampered line, lock, write, or flush
failure returns `execution-audit-unavailable` before SSH is attempted.

The journal and its matching Windows Generic Credentials are operational
security records. Preserve them together when collecting evidence; do not copy
key bytes into tickets or logs.
