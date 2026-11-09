import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

export type ExecutionAuditOutcome = 'success' | 'failure' | 'timeout' | 'cancelled' | 'approval-required' | 'unknown';

export interface ExecutionAuditIntent {
  readonly operationId: string;
  readonly profileId: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly argsHmac: string;
  readonly approvalState: string;
}

export interface ExecutionAuditFinished {
  readonly outcome: ExecutionAuditOutcome;
  readonly code: string;
  readonly exitCode: number | null;
  readonly durationMs: number;
}

export interface ExecutionAuditHandle {
  readonly operationId: string;
  finish(event: ExecutionAuditFinished): Promise<void>;
}

export interface ExecutionAuditJournal {
  begin(intent: ExecutionAuditIntent): Promise<ExecutionAuditHandle>;
  digestArguments(args: readonly string[]): Promise<string>;
}

export interface PosixAuditJournalOptions {
  readonly root: string;
  readonly keyFile: string;
  readonly uid?: number;
  readonly now?: () => number;
}

const JOURNAL_VERSION = 1;
const JOURNAL_FILE = 'execution-audit.v1.jsonl';
const PRIVATE_FILE_MODE = 0o600;
const UNSAFE_WRITE_BITS = 0o022;
const OPERATION_ID_PATTERN = /^[a-f0-9]{32}$/u;

function canonical(value: Record<string, unknown>): string {
  return JSON.stringify(value);
}

function assertSafeFile(
  stats: { readonly mode: number; readonly uid?: number; isFile(): boolean; isSymbolicLink(): boolean },
  uid: number | undefined,
): void {
  if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & UNSAFE_WRITE_BITS) !== 0 || (uid !== undefined && stats.uid !== uid)) {
    throw new Error('execution audit storage is unavailable');
  }
}

function assertSafeRoot(
  stats: { readonly mode: number; readonly uid?: number; isDirectory(): boolean; isSymbolicLink(): boolean },
  uid: number | undefined,
): void {
  if (!stats.isDirectory() || stats.isSymbolicLink() || (stats.mode & UNSAFE_WRITE_BITS) !== 0 || (uid !== undefined && stats.uid !== uid)) {
    throw new Error('execution audit storage is unavailable');
  }
}

function parseKey(value: Buffer): Buffer {
  const text = value.toString('utf8');
  const match = /^v1:([0-9a-f]{64})\n?$/u.exec(text);
  if (match === null) throw new Error('execution audit key is invalid');
  return Buffer.from(match[1], 'hex');
}

interface JournalLine {
  readonly version: 1;
  readonly event: 'intent' | 'finished';
  readonly operationId: string;
  readonly timestamp: number;
  readonly previousHmac: string | null;
  readonly hmac: string;
  readonly sessionId?: string;
  readonly [key: string]: unknown;
}

/**
 * POSIX journal. The key is deliberately supplied separately and is never
 * generated, returned, or included in an event. Every append is exclusive to
 * the opened descriptor and is followed by fdatasync before the call returns.
 */
export class PosixExecutionAuditJournal implements ExecutionAuditJournal {
  private readonly now: () => number;
  private readonly journalPath: string;
  private queue: Promise<void> = Promise.resolve();
  private readonly sessionId = randomBytes(16).toString('hex');
  private readonly unfinished = new Map<string, string | undefined>();

  constructor(private readonly options: PosixAuditJournalOptions) {
    if (!isAbsolute(options.root) || !isAbsolute(options.keyFile) || options.root === options.keyFile) {
      throw new Error('execution audit storage is unavailable');
    }
    this.now = options.now ?? Date.now;
    this.journalPath = join(options.root, JOURNAL_FILE);
  }

  async begin(intent: ExecutionAuditIntent): Promise<ExecutionAuditHandle> {
    if (!OPERATION_ID_PATTERN.test(intent.operationId)) throw new Error('execution audit operation is invalid');
    return this.exclusive(async () => {
      const key = await this.loadKey();
      await this.verifyRoot();
      let chain = await this.verifyChain(key);
      for (const [interruptedOperationId, sessionId] of this.unfinished) {
        if (sessionId === this.sessionId) continue;
        const recovered = await this.append(key, chain, {
          event: 'finished',
          operationId: interruptedOperationId,
          sessionId: this.sessionId,
          outcome: 'unknown',
          code: 'outcome-unknown',
          exitCode: null,
          durationMs: 0,
        });
        chain = recovered.hmac;
        this.unfinished.delete(interruptedOperationId);
      }
      await this.append(key, chain, {
        event: 'intent',
        operationId: intent.operationId,
        profileId: intent.profileId,
        command: intent.command,
        args: [...intent.args],
        argsHmac: intent.argsHmac,
        approvalState: intent.approvalState,
        sessionId: this.sessionId,
      });
      this.unfinished.set(intent.operationId, this.sessionId);
      let finished = false;
      return {
        operationId: intent.operationId,
        finish: async (finishedEvent: ExecutionAuditFinished) => {
          if (finished) return;
          await this.exclusive(async () => {
            if (finished) return;
            finished = true;
            const currentKey = await this.loadKey();
            const currentPreviousHmac = await this.verifyChain(currentKey);
            await this.append(currentKey, currentPreviousHmac, {
              event: 'finished',
              operationId: intent.operationId,
              sessionId: this.sessionId,
              ...finishedEvent,
            });
            this.unfinished.delete(intent.operationId);
          });
        },
      };
    });
  }

  async digestArguments(args: readonly string[]): Promise<string> {
    const key = await this.loadKey();
    return createHmac('sha256', key)
      .update(JSON.stringify([...args]))
      .digest('hex');
  }

  private async exclusive<T>(work: () => Promise<T>): Promise<T> {
    const previous = this.queue;
    let release!: () => void;
    this.queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await work();
    } finally {
      release();
    }
  }

  private async verifyRoot(): Promise<void> {
    const stats = await lstat(this.options.root);
    assertSafeRoot(stats, this.options.uid);
    if ((await realpath(this.options.root)) !== this.options.root) throw new Error('execution audit storage is unavailable');
  }

  private async loadKey(): Promise<Buffer> {
    const stats = await lstat(this.options.keyFile);
    assertSafeFile(stats, this.options.uid);
    if ((await realpath(this.options.keyFile)) !== this.options.keyFile || (stats.mode & 0o777) !== PRIVATE_FILE_MODE) {
      throw new Error('execution audit key is invalid');
    }
    return parseKey(await readFile(this.options.keyFile));
  }

  private async verifyChain(key: Buffer): Promise<string | null> {
    let previous: string | null = null;
    let contents: Buffer;
    try {
      contents = await readFile(this.journalPath);
    } catch (error: unknown) {
      if ((error as { code?: unknown }).code === 'ENOENT') return null;
      throw new Error('execution audit journal is unavailable');
    }
    for (const line of contents.toString('utf8').split('\n')) {
      if (line === '') continue;
      let parsed: JournalLine;
      try {
        parsed = JSON.parse(line) as JournalLine;
      } catch {
        throw new Error('execution audit chain is invalid');
      }
      if (
        parsed.version !== JOURNAL_VERSION ||
        !OPERATION_ID_PATTERN.test(parsed.operationId) ||
        parsed.previousHmac !== previous ||
        (parsed.event === 'intent' && (typeof parsed.argsHmac !== 'string' || !/^[a-f0-9]{64}$/u.test(parsed.argsHmac)))
      ) {
        throw new Error('execution audit chain is invalid');
      }
      const { hmac, ...unsigned } = parsed;
      const expected = createHmac('sha256', key).update(canonical(unsigned)).digest('hex');
      const actual = Buffer.from(hmac, 'hex');
      const expectedBytes = Buffer.from(expected, 'hex');
      if (actual.length !== expectedBytes.length || !timingSafeEqual(actual, expectedBytes)) throw new Error('execution audit chain is invalid');
      if (parsed.event === 'intent') this.unfinished.set(parsed.operationId, parsed.sessionId);
      else if (parsed.event === 'finished') this.unfinished.delete(parsed.operationId);
      previous = hmac;
    }
    return previous;
  }

  private async append(key: Buffer, previousHmac: string | null, event: Record<string, unknown>): Promise<{ readonly hmac: string }> {
    const unsigned = { version: JOURNAL_VERSION, ...event, timestamp: this.now(), previousHmac };
    const hmac = createHmac('sha256', key).update(canonical(unsigned)).digest('hex');
    const line = `${canonical({ ...unsigned, hmac })}\n`;
    let existing;
    try {
      existing = await lstat(this.journalPath);
      assertSafeFile(existing, this.options.uid);
      if ((existing.mode & 0o777) !== PRIVATE_FILE_MODE || (await realpath(this.journalPath)) !== this.journalPath)
        throw new Error('execution audit storage is unavailable');
    } catch (error: unknown) {
      if ((error as { code?: unknown }).code !== 'ENOENT') throw error;
    }
    const handle = await open(
      this.journalPath,
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE,
    );
    try {
      await handle.chmod(PRIVATE_FILE_MODE);
      assertSafeFile(await handle.stat(), this.options.uid);
      await handle.write(line, undefined, 'utf8');
      await handle.datasync();
    } finally {
      await handle.close();
    }
    assertSafeFile(await lstat(this.journalPath), this.options.uid);
    return { hmac };
  }
}

/** Explicitly unavailable runtime boundary used where a native Windows audit provider is not installed. */
export class UnavailableExecutionAuditJournal implements ExecutionAuditJournal {
  async digestArguments(): Promise<string> {
    throw new Error('execution audit journal is unavailable');
  }

  async begin(): Promise<ExecutionAuditHandle> {
    throw new Error('execution audit journal is unavailable');
  }
}
