import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { PosixExecutionAuditJournal, WindowsExecutionAuditJournal } from '../../src/execution/execution-audit-journal.js';

async function fixture(): Promise<{ root: string; keyFile: string }> {
  const root = join(tmpdir(), `ssh-mcp-audit-${randomBytes(8).toString('hex')}`);
  await mkdir(root, { mode: 0o700 });
  const keyFile = join(root, 'audit-key');
  await writeFile(keyFile, `v1:${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
  await chmod(keyFile, 0o600);
  return { root, keyFile };
}

const intent = {
  operationId: '0123456789abcdef0123456789abcdef',
  profileId: 'production-api',
  command: 'systemctl',
  args: ['status', 'api'],
  argsHmac: '0000000000000000000000000000000000000000000000000000000000000000',
  approvalState: 'not-required',
} as const;

test('writes durable chained intent and finished events without output', async (t) => {
  if (process.platform === 'win32') return t.skip('POSIX journal permission checks require a POSIX filesystem');
  const fixtureState = await fixture();
  const journal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  const handle = await journal.begin(intent);
  await handle.approval?.('approval-approved');
  await handle.handoff?.();
  await handle.finish({ outcome: 'success', code: 'success', exitCode: 0, durationMs: 2 });
  const serialized = await readFile(join(fixtureState.root, 'execution-audit.v1.jsonl'), 'utf8');
  assert.equal(serialized.split('\n').filter(Boolean).length, 4);
  assert.deepEqual(JSON.parse(await readFile(join(fixtureState.root, 'execution-audit.v1.manifest'), 'utf8')), {
    version: 1,
    files: ['execution-audit.v1.jsonl'],
  });
  assert.equal(serialized.includes('stdout'), false);
  assert.equal(serialized.includes('password'), false);
});

test('rotates POSIX journal segments before the next durable append and rejects manifest drift', async (t) => {
  if (process.platform === 'win32') return t.skip('POSIX journal permission checks require a POSIX filesystem');
  const fixtureState = await fixture();
  const journal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  const oversizedArgs = ['x'.repeat(4096)];
  for (let index = 0; index < 1_000; index += 1) {
    const handle = await journal.begin({ ...intent, operationId: index.toString(16).padStart(32, '0'), args: oversizedArgs });
    await handle.finish({ outcome: 'success', code: 'success', exitCode: 0, durationMs: 1 });
  }
  const names = (await readdir(fixtureState.root)).filter((name) => /^execution-audit\.v1\./u.test(name));
  assert.ok(names.some((name) => /\.\d{6}\.jsonl$/u.test(name)));
  await writeFile(join(fixtureState.root, 'execution-audit.v1.manifest'), '{"version":1,"files":[]}\n', { mode: 0o600 });
  const freshJournal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  await assert.rejects(() => freshJournal.begin({ ...intent, operationId: 'abcdefabcdefabcdefabcdefabcdefab' }), /manifest|chain/u);
});

test('fails closed for missing, rotated, and invalid chain keys', async (t) => {
  if (process.platform === 'win32') return t.skip('POSIX journal permission checks require a POSIX filesystem');
  const fixtureState = await fixture();
  const journal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  await assert.rejects(() => new PosixExecutionAuditJournal({ root: fixtureState.root, keyFile: join(fixtureState.root, 'missing') }).begin(intent));
  const handle = await journal.begin(intent);
  await writeFile(fixtureState.keyFile, `v1:${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
  await chmod(fixtureState.keyFile, 0o600);
  await assert.rejects(() => handle.finish({ outcome: 'unknown', code: 'outcome-unknown', exitCode: null, durationMs: 1 }));
  await assert.rejects(() => journal.begin({ ...intent, operationId: 'fedcba9876543210fedcba9876543210' }));
});

test('fails closed when the journal chain is altered', async (t) => {
  if (process.platform === 'win32') return t.skip('POSIX journal permission checks require a POSIX filesystem');
  const fixtureState = await fixture();
  const journal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  await journal.begin(intent);
  const path = join(fixtureState.root, 'execution-audit.v1.jsonl');
  const contents = await readFile(path, 'utf8');
  await writeFile(path, contents.replace('systemctl', 'tampered'), { mode: 0o600 });
  await assert.rejects(() => journal.begin({ ...intent, operationId: 'fedcba9876543210fedcba9876543210' }));
});

test('recovers an interrupted intent as outcome-unknown before the next attempt', async (t) => {
  if (process.platform === 'win32') return t.skip('POSIX journal permission checks require a POSIX filesystem');
  const fixtureState = await fixture();
  const journal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  await journal.begin(intent);
  await journal.begin({ ...intent, operationId: 'fedcba9876543210fedcba9876543210' });
  const contents = await readFile(join(fixtureState.root, 'execution-audit.v1.jsonl'), 'utf8');
  assert.equal(contents.includes('"outcome":"unknown"'), false);
  const freshJournal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  await freshJournal.begin({ ...intent, operationId: 'abcdefabcdefabcdefabcdefabcdefab' });
  const recovered = await readFile(join(fixtureState.root, 'execution-audit.v1.jsonl'), 'utf8');
  assert.match(recovered, /"operationId":"0123456789abcdef0123456789abcdef"[\s\S]*?"outcome":"unknown"/u);
});

test('finishes concurrent operations against the current chain head', async (t) => {
  if (process.platform === 'win32') return t.skip('POSIX journal permission checks require a POSIX filesystem');
  const fixtureState = await fixture();
  const journal = new PosixExecutionAuditJournal({ ...fixtureState, uid: process.getuid?.() });
  const first = await journal.begin(intent);
  const second = await journal.begin({ ...intent, operationId: 'fedcba9876543210fedcba9876543210' });
  await first.finish({ outcome: 'success', code: 'success', exitCode: 0, durationMs: 1 });
  await second.finish({ outcome: 'success', code: 'success', exitCode: 0, durationMs: 1 });
  const contents = await readFile(join(fixtureState.root, 'execution-audit.v1.jsonl'), 'utf8');
  assert.equal(contents.match(/"event":"finished"/gu)?.length, 2);
  assert.equal(contents.includes('"outcome":"unknown"'), false);
});

test('adapts the native Windows journal without receiving key material', async () => {
  const events: unknown[] = [];
  const journal = new WindowsExecutionAuditJournal({
    digestExecutionAuditArguments: (args) => {
      events.push({ kind: 'digest', args });
      return 'a'.repeat(64);
    },
    appendExecutionAuditIntent: (event) => {
      events.push({ kind: 'intent', event });
      return { keyId: 'b'.repeat(32), previousEventHmac: null, eventHmac: 'c'.repeat(64) };
    },
    appendExecutionAuditFinished: (event) => {
      events.push({ kind: 'finished', event });
      return { keyId: 'b'.repeat(32), previousEventHmac: 'c'.repeat(64), eventHmac: 'd'.repeat(64) };
    },
  });
  assert.equal(await journal.digestArguments(['status', 'ssh']), 'a'.repeat(64));
  const handle = await journal.begin(intent);
  await handle.finish({ outcome: 'success', code: 'success', exitCode: 0, durationMs: 1 });
  await handle.finish({ outcome: 'failure', code: 'ignored', exitCode: 1, durationMs: 2 });
  assert.deepEqual(
    events.map((event) => (event as { kind: string }).kind),
    ['digest', 'intent', 'finished'],
  );
  assert.equal('key' in (events[1] as object), false);
});

test('adapts durable approval and handoff events through the native journal boundary', async () => {
  const events: unknown[] = [];
  const journal = new WindowsExecutionAuditJournal({
    digestExecutionAuditArguments: () => 'a'.repeat(64),
    appendExecutionAuditIntent: () => ({ keyId: 'b'.repeat(32), previousEventHmac: null, eventHmac: 'c'.repeat(64) }),
    appendExecutionAuditApproval: (event) => {
      events.push({ kind: 'approval', event });
      return { keyId: 'b'.repeat(32), previousEventHmac: 'c'.repeat(64), eventHmac: 'd'.repeat(64) };
    },
    appendExecutionAuditHandoff: (event) => {
      events.push({ kind: 'handoff', event });
      return { keyId: 'b'.repeat(32), previousEventHmac: 'd'.repeat(64), eventHmac: 'e'.repeat(64) };
    },
    appendExecutionAuditFinished: (event) => {
      events.push({ kind: 'finished', event });
      return { keyId: 'b'.repeat(32), previousEventHmac: 'e'.repeat(64), eventHmac: 'f'.repeat(64) };
    },
  });
  const handle = await journal.begin(intent);
  await handle.approval?.('approval-approved');
  await handle.handoff?.();
  await handle.finish({ outcome: 'success', code: 'success', exitCode: 0, durationMs: 1 });
  assert.deepEqual(
    events.map((event) => (event as { kind: string }).kind),
    ['approval', 'handoff', 'finished'],
  );
});
