import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { PosixExecutionAuditJournal } from '../../src/execution/execution-audit-journal.js';

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
  await handle.finish({ outcome: 'success', code: 'success', exitCode: 0, durationMs: 2 });
  const serialized = await readFile(join(fixtureState.root, 'execution-audit.v1.jsonl'), 'utf8');
  assert.equal(serialized.split('\n').filter(Boolean).length, 2);
  assert.equal(serialized.includes('stdout'), false);
  assert.equal(serialized.includes('password'), false);
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
