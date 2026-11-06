import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import test from 'node:test';

import type { ConnectConfig } from 'ssh2';

import { mapConnectionError } from '../../src/diagnostics/redacted-diagnostics-audit.js';
import {
  WindowsInMemoryPasswordTransport,
  WindowsPasswordTransportError,
  type InMemorySshClient,
} from '../../src/windows/windows-password-transport.js';

class FakeClient implements InMemorySshClient {
  config: ConnectConfig | undefined;
  destroyed = false;
  private readonly listeners = new Map<string, (...args: readonly unknown[]) => void>();

  on(event: 'ready' | 'error', listener: (...args: readonly unknown[]) => void): this {
    this.listeners.set(event, listener);
    return this;
  }

  connect(config: ConnectConfig): this {
    this.config = config;
    return this;
  }

  end(): this {
    return this;
  }

  destroy(): this {
    this.destroyed = true;
    return this;
  }

  emit(event: 'ready' | 'error'): void {
    this.listeners.get(event)?.();
  }
}

const key = Buffer.from('approved-host-key');
const fingerprint = `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/u, '')}`;
const request = {
  host: 'approved.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: fingerprint,
  credentialReference: 'os://ssh/production-api',
  timeoutMs: 1_000,
};

test('retrieves an in-memory password only after the approved host key verifies', async () => {
  const client = new FakeClient();
  let lookups = 0;
  const transport = new WindowsInMemoryPasswordTransport(
    {
      getPassword: () => {
        lookups += 1;
        return { password: 'not-logged' };
      },
    },
    () => client,
  );
  const connected = transport.connect(request);
  assert.equal((client.config!.hostVerifier as (key: Buffer) => boolean)(key), true);
  assert.equal(lookups, 0);
  assert.equal(typeof client.config?.authHandler, 'function');
  let authentication: unknown;
  (client.config!.authHandler as unknown as (left: unknown, partial: unknown, callback: (value: unknown) => void) => void)(null, null, (value) => {
    authentication = value;
  });
  assert.deepEqual(authentication, { type: 'password', username: 'deploy', password: 'not-logged' });
  assert.equal(lookups, 1);
  client.emit('ready');
  await connected;
});

test('rejects an unapproved host before any credential lookup and redacts transport errors', async () => {
  const client = new FakeClient();
  let lookups = 0;
  const transport = new WindowsInMemoryPasswordTransport({ getPassword: () => ({ password: (++lookups, 'not-logged') }) }, () => client);
  const connected = transport.connect(request);
  assert.equal((client.config!.hostVerifier as (key: Buffer) => boolean)(Buffer.from('wrong-key')), false);
  let authentication: unknown;
  (client.config!.authHandler as unknown as (left: unknown, partial: unknown, callback: (value: unknown) => void) => void)(null, null, (value) => {
    authentication = value;
  });
  assert.equal(authentication, false);
  assert.equal(lookups, 0);
  client.emit('error');
  await assert.rejects(connected, (error) => error instanceof WindowsPasswordTransportError && mapConnectionError(error).code === 'host-key-failure');
});

test('classifies an unavailable credential as an authentication failure without releasing a password', async () => {
  const client = new FakeClient();
  const transport = new WindowsInMemoryPasswordTransport(
    {
      getPassword: () => {
        throw new Error('credential=private');
      },
    },
    () => client,
  );
  const connected = transport.connect(request);
  assert.equal((client.config!.hostVerifier as (key: Buffer) => boolean)(key), true);
  let authentication: unknown;
  (client.config!.authHandler as unknown as (left: unknown, partial: unknown, callback: (value: unknown) => void) => void)(null, null, (value) => {
    authentication = value;
  });
  assert.equal(authentication, false);
  client.emit('error');
  await assert.rejects(
    connected,
    (error) => error instanceof WindowsPasswordTransportError && mapConnectionError(error).code === 'authentication-failure',
  );
});

test('classifies a transport error after password submission as a connection failure', async () => {
  const client = new FakeClient();
  const transport = new WindowsInMemoryPasswordTransport({ getPassword: () => ({ password: 'private' }) }, () => client);
  const connected = transport.connect(request);
  assert.equal((client.config!.hostVerifier as (key: Buffer) => boolean)(key), true);
  let authentication: unknown;
  (client.config!.authHandler as unknown as (left: unknown, partial: unknown, callback: (value: unknown) => void) => void)(null, null, (value) => {
    authentication = value;
  });
  assert.deepEqual(authentication, { type: 'password', username: 'deploy', password: 'private' });
  client.emit('error');
  await assert.rejects(
    connected,
    (error) =>
      error instanceof WindowsPasswordTransportError && mapConnectionError(error).code === 'connection-failure' && !error.message.includes('private'),
  );
});

test('does not start a connection or retrieve credentials after cancellation', async () => {
  const client = new FakeClient();
  let lookups = 0;
  const controller = new AbortController();
  controller.abort();
  const transport = new WindowsInMemoryPasswordTransport({ getPassword: () => ({ password: (++lookups, 'not-logged') }) }, () => client);
  await assert.rejects(transport.connect(request, controller.signal), WindowsPasswordTransportError);
  assert.equal(client.config, undefined);
  assert.equal(lookups, 0);
});

test('does not retrieve a credential when cancellation follows host-key verification', async () => {
  const client = new FakeClient();
  let lookups = 0;
  const controller = new AbortController();
  const transport = new WindowsInMemoryPasswordTransport({ getPassword: () => ({ password: (++lookups, 'private') }) }, () => client);
  const connected = transport.connect(request, controller.signal);
  assert.equal((client.config!.hostVerifier as (key: Buffer) => boolean)(key), true);
  controller.abort();
  let authentication: unknown;
  (client.config!.authHandler as unknown as (left: unknown, partial: unknown, callback: (value: unknown) => void) => void)(null, null, (value) => {
    authentication = value;
  });
  assert.equal(authentication, false);
  assert.equal(lookups, 0);
  await assert.rejects(connected, WindowsPasswordTransportError);
});

test('does not release a password when credential lookup triggers cancellation', async () => {
  const client = new FakeClient();
  const controller = new AbortController();
  const transport = new WindowsInMemoryPasswordTransport(
    {
      getPassword: () => {
        controller.abort();
        return { password: 'private' };
      },
    },
    () => client,
  );
  const connected = transport.connect(request, controller.signal);
  assert.equal((client.config!.hostVerifier as (key: Buffer) => boolean)(key), true);
  let authentication: unknown;
  (client.config!.authHandler as unknown as (left: unknown, partial: unknown, callback: (value: unknown) => void) => void)(null, null, (value) => {
    authentication = value;
  });
  assert.equal(authentication, false);
  await assert.rejects(connected, WindowsPasswordTransportError);
});

test('times out with a redacted error and destroys the client before credential lookup', async () => {
  const client = new FakeClient();
  let lookups = 0;
  const transport = new WindowsInMemoryPasswordTransport({ getPassword: () => ({ password: (++lookups, 'private') }) }, () => client);
  await assert.rejects(
    transport.connect({ ...request, timeoutMs: 5 }),
    (error) => error instanceof WindowsPasswordTransportError && mapConnectionError(error).code === 'timeout' && !error.message.includes('private'),
  );
  assert.equal(client.destroyed, true);
  assert.equal(lookups, 0);
});
