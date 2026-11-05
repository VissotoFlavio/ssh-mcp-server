import { createHash, timingSafeEqual } from 'node:crypto';

import { Client, type ConnectConfig } from 'ssh2';

import type { PasswordCredential } from '../credentials/credential-store.js';

export interface WindowsPasswordValidationRequest {
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly expectedHostFingerprint: string;
  readonly credentialReference: string;
  readonly timeoutMs: number;
}

export interface WindowsPasswordCredentialSource {
  getPassword(reference: string): PasswordCredential;
}

export interface InMemorySshClient {
  on(event: 'ready' | 'error', listener: (...args: readonly unknown[]) => void): this;
  connect(config: ConnectConfig): this;
  end(): this;
  destroy(): this;
}

export type InMemorySshClientFactory = () => InMemorySshClient;

export class WindowsPasswordTransportError extends Error {
  constructor() {
    super('Windows password transport is unavailable');
    this.name = 'WindowsPasswordTransportError';
  }
}

function boundedTimeout(value: number): number {
  return Number.isInteger(value) && value > 0 && value <= 60_000 ? value : 10_000;
}

function matchesFingerprint(key: Buffer, expected: string): boolean {
  const actual = `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`;
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  return actualBytes.byteLength === expectedBytes.byteLength && timingSafeEqual(actualBytes, expectedBytes);
}

/**
 * Establishes an in-memory password validation connection. `hostVerifier` is
 * reached during the SSH handshake before `authHandler` reads the credential.
 */
export class WindowsInMemoryPasswordTransport {
  constructor(
    private readonly credentials: WindowsPasswordCredentialSource,
    private readonly clients: InMemorySshClientFactory = () => new Client(),
  ) {}

  connect(request: WindowsPasswordValidationRequest, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(new WindowsPasswordTransportError());
    return new Promise((resolve, reject) => {
      const client = this.clients();
      let finished = false;
      let hostVerified = false;
      const finish = (error?: Error) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        try {
          client.end();
        } catch {
          client.destroy();
        }
        if (error === undefined) resolve();
        else reject(error);
      };
      const abort = () => {
        try {
          client.destroy();
        } finally {
          finish(new WindowsPasswordTransportError());
        }
      };
      const timer = setTimeout(abort, boundedTimeout(request.timeoutMs));
      signal?.addEventListener('abort', abort, { once: true });
      client.on('ready', () => finish());
      client.on('error', () => finish(new WindowsPasswordTransportError()));
      try {
        client.connect({
          host: request.host,
          port: request.port,
          username: request.user,
          readyTimeout: boundedTimeout(request.timeoutMs),
          hostVerifier: (key: Buffer) => {
            hostVerified = matchesFingerprint(key, request.expectedHostFingerprint);
            return hostVerified;
          },
          authHandler: (_methodsLeft, _partialSuccess, callback) => {
            const rejectAuthentication = callback as unknown as (value: false) => void;
            if (finished || signal?.aborted || !hostVerified) return rejectAuthentication(false);
            let password = '';
            try {
              password = this.credentials.getPassword(request.credentialReference).password;
              if (finished || signal?.aborted) return rejectAuthentication(false);
              if (password.length === 0 || password.includes('\u0000')) return rejectAuthentication(false);
              callback({ type: 'password', username: request.user, password });
            } catch {
              rejectAuthentication(false);
            } finally {
              password = '';
            }
          },
        });
      } catch {
        finish(new WindowsPasswordTransportError());
      }
    });
  }
}
