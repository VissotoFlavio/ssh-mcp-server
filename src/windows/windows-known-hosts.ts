import { createHash } from 'node:crypto';

import type { ApprovedKnownHostsEntry } from '../policy/host-identity-credential-policy.js';

/**
 * Parse protected local known-hosts bytes through a caller-owned fail-closed
 * error boundary. Raw contents are never returned.
 */
export function parseWindowsKnownHosts(bytes: Buffer, unavailable: () => never): readonly ApprovedKnownHostsEntry[] {
  const contents = bytes.toString('utf8');
  if (!Buffer.from(contents, 'utf8').equals(bytes)) return unavailable();

  const entries: ApprovedKnownHostsEntry[] = [];
  for (const line of contents.split(/\r?\n/u)) {
    const value = line.trim();
    if (value === '' || value.startsWith('#')) continue;
    const fields = value.split(/\s+/u);
    const endpoint = /^(?:\[([^\]]+)\]:(\d+)|([A-Za-z0-9.-]+))$/u.exec(fields[0] ?? '');
    const encodedKey = fields[2];
    if (
      fields.length !== 3 ||
      endpoint === null ||
      !/^[A-Za-z0-9@._+-]+$/u.test(fields[1] ?? '') ||
      !/^[A-Za-z0-9+/]+={0,2}$/u.test(encodedKey ?? '')
    ) {
      return unavailable();
    }
    const key = Buffer.from(encodedKey, 'base64');
    const host = endpoint[1] ?? endpoint[3];
    const port = endpoint[2] === undefined ? 22 : Number(endpoint[2]);
    if (host === undefined || key.byteLength === 0 || !Number.isInteger(port) || port < 1 || port > 65_535) return unavailable();
    entries.push({
      host,
      port,
      fingerprint: `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`,
    });
  }
  return entries;
}
