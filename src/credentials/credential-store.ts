import { spawn } from 'node:child_process';

/**
 * An opaque reference to a credential held by an operating-system credential
 * store. The branded type prevents callers from accidentally passing a
 * password (or another arbitrary string) after validation.
 */
export type CredentialReference = string & {
  readonly __credentialReference: unique symbol;
};

export interface PasswordCredential {
  readonly password: string;
}

/**
 * The only secret-bearing boundary in the server. Implementations must never
 * include the returned password in logs, errors, or diagnostics.
 */
export interface CredentialStore {
  getPassword(reference: CredentialReference): Promise<PasswordCredential>;
}

export interface CredentialStoreResolver {
  resolve(reference: string): CredentialStore;
}

export type CredentialStoreErrorCode =
  | 'invalid-reference'
  | 'unsupported-platform'
  | 'unsupported-provider'
  | 'unapproved-reference'
  | 'credential-unavailable'
  | 'credential-store-failure';

/**
 * Public errors deliberately contain no credential reference, command output,
 * or secret material. The code is safe to expose to an operator or MCP client.
 */
export class CredentialStoreError extends Error {
  readonly code: CredentialStoreErrorCode;

  constructor(code: CredentialStoreErrorCode, message: string) {
    super(message);
    this.name = 'CredentialStoreError';
    this.code = code;
  }
}

const REFERENCE_PATTERN = /^os:\/\/([a-z][a-z0-9-]{0,31})\/([a-z0-9][a-z0-9._:-]{0,127})$/u;
const SECRET_MATERIAL_PATTERN = /(?:password|passphrase|private[\s_-]*key|secret|token)\s*[:=]/iu;
const SECRET_LOCATOR_PATTERN = /^(?:password|passphrase|private[\s_-]*key|secret|token)$/iu;
const PEM_PATTERN = /-----begin\s+(?:open\s+)?ssh|-----begin\s+private\s+key/iu;
const FORBIDDEN_CONTROL_PATTERN = /[\u0000-\u001F\u007F]/u;

export interface ParsedCredentialReference {
  readonly provider: string;
  readonly locator: string;
  readonly reference: CredentialReference;
}

/**
 * Validate and parse the deliberately small credential-reference grammar.
 *
 * References are opaque lookup keys, not URLs supplied to a command or paths
 * on disk: `os://<provider>/<locator>`. Query strings, fragments, credentials,
 * path traversal, control characters, and secret material are rejected.
 */
export function parseCredentialReference(value: unknown): ParsedCredentialReference {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
    throw new CredentialStoreError('invalid-reference', 'Invalid credential reference');
  }

  if (FORBIDDEN_CONTROL_PATTERN.test(value) || SECRET_MATERIAL_PATTERN.test(value) || PEM_PATTERN.test(value)) {
    throw new CredentialStoreError('invalid-reference', 'Invalid credential reference');
  }

  const match = REFERENCE_PATTERN.exec(value);
  if (match === null) {
    throw new CredentialStoreError('invalid-reference', 'Invalid credential reference');
  }

  const [, provider, locator] = match;
  if (locator === '.' || locator === '..' || locator.includes('..') || SECRET_LOCATOR_PATTERN.test(locator)) {
    throw new CredentialStoreError('invalid-reference', 'Invalid credential reference');
  }

  return {
    provider,
    locator,
    reference: value as CredentialReference,
  };
}

export function validateCredentialReference(value: unknown): CredentialReference {
  return parseCredentialReference(value).reference;
}

/**
 * A store implementation can be injected for tests or for a future native
 * provider. The runner accepts an executable selected by the platform adapter,
 * never a command string from a credential reference.
 */
export interface CredentialStoreCommandResult {
  readonly stdout: string;
}

export type CredentialStoreExecutable = '/usr/bin/security' | '/usr/bin/secret-tool';

export interface CredentialStoreCommandRunner {
  run(executable: CredentialStoreExecutable, args: readonly string[]): Promise<CredentialStoreCommandResult>;
}

export interface PlatformCredentialStoreResolverOptions {
  readonly platform?: string;
  readonly runner?: CredentialStoreCommandRunner;
  readonly timeoutMs?: number;
  /** References configured by the operator; absent means no reference is approved. */
  readonly approvedReferences?: readonly string[] | ReadonlySet<string>;
}

export type SupportedCredentialStorePlatform = 'darwin' | 'linux';

function isSupportedPlatform(platform: string): platform is SupportedCredentialStorePlatform {
  return platform === 'darwin' || platform === 'linux';
}

function requirePassword(stdout: string): PasswordCredential {
  // Native command providers conventionally append one line terminator. Only
  // remove that framing terminator; the password itself is otherwise opaque.
  const password = stdout.endsWith('\r\n') ? stdout.slice(0, -2) : stdout.endsWith('\n') ? stdout.slice(0, -1) : stdout;
  if (password.length === 0 || password.includes('\u0000')) {
    throw new CredentialStoreError('credential-unavailable', 'Credential is unavailable');
  }

  return { password };
}

/**
 * Platform adapter for the two OS stores whose command-line clients expose a
 * read operation. The provider and locator become data arguments only after
 * reference and approval validation.
 */
class NativeCommandCredentialStore implements CredentialStore {
  private readonly platform: SupportedCredentialStorePlatform;
  private readonly parsedReference: ParsedCredentialReference;
  private readonly runner: CredentialStoreCommandRunner;

  constructor(
    platform: SupportedCredentialStorePlatform,
    parsedReference: ParsedCredentialReference,
    runner: CredentialStoreCommandRunner,
  ) {
    this.platform = platform;
    this.parsedReference = parsedReference;
    this.runner = runner;
  }

  async getPassword(reference: CredentialReference): Promise<PasswordCredential> {
    const parsed = parseCredentialReference(reference);
    if (parsed.reference !== this.parsedReference.reference) {
      throw new CredentialStoreError('invalid-reference', 'Invalid credential reference');
    }

    const args =
      this.platform === 'darwin'
        ? ['find-generic-password', '-a', parsed.locator, '-s', parsed.provider, '-w']
        : ['lookup', 'service', parsed.provider, 'account', parsed.locator];
    const executable = this.platform === 'darwin' ? '/usr/bin/security' : '/usr/bin/secret-tool';

    let result: CredentialStoreCommandResult;
    try {
      result = await this.runner.run(executable, args);
    } catch {
      throw new CredentialStoreError('credential-store-failure', 'Credential store lookup failed');
    }

    if (typeof result.stdout !== 'string') {
      throw new CredentialStoreError('credential-store-failure', 'Credential store response is invalid');
    }

    return requirePassword(result.stdout);
  }
}

/**
 * Resolve a validated opaque reference to the OS-backed credential store for
 * the current platform. Unsupported platforms fail closed before any process
 * can be started.
 */
export class PlatformCredentialStoreResolver implements CredentialStoreResolver {
  private readonly platform: string;
  private readonly runner: CredentialStoreCommandRunner;
  private readonly approvedReferences: ReadonlySet<string>;

  constructor(options: PlatformCredentialStoreResolverOptions = {}) {
    this.platform = options.platform ?? (typeof process === 'undefined' ? 'unknown' : process.platform);
    this.runner = options.runner ?? new DirectSpawnCredentialStoreCommandRunner(options.timeoutMs);
    this.approvedReferences = new Set(
      [...(options.approvedReferences ?? [])].map(reference => parseCredentialReference(reference).reference),
    );
  }

  resolve(reference: string): CredentialStore {
    const parsed = parseCredentialReference(reference);
    if (parsed.provider !== 'ssh') {
      throw new CredentialStoreError('unsupported-provider', 'Credential store provider is unsupported');
    }
    if (!this.approvedReferences.has(parsed.reference)) {
      throw new CredentialStoreError('unapproved-reference', 'Credential reference is not approved');
    }
    if (!isSupportedPlatform(this.platform)) {
      throw new CredentialStoreError('unsupported-platform', 'OS credential store is unavailable');
    }

    return new NativeCommandCredentialStore(this.platform, parsed, this.runner);
  }
}

/**
 * Injectable default runner. It uses direct process APIs with shell execution
 * disabled; credential-reference data is passed as argv values only.
 */
export class DirectSpawnCredentialStoreCommandRunner implements CredentialStoreCommandRunner {
  private readonly timeoutMs: number;

  constructor(timeoutMs = 10_000) {
    this.timeoutMs = Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 60_000 ? timeoutMs : 10_000;
  }

  run(
    executable: CredentialStoreExecutable,
    args: readonly string[],
  ): Promise<CredentialStoreCommandResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, [...args], {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'] as const,
      });

      const stdout: Buffer[] = [];
      let byteLength = 0;
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill();
        reject(new CredentialStoreError('credential-store-failure', 'Credential store lookup timed out'));
      }, this.timeoutMs);

      child.stdout.on('data', (chunk: Buffer | string) => {
        const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        byteLength += data.byteLength;
        if (byteLength > 64 * 1024) {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            child.kill();
            reject(new CredentialStoreError('credential-store-failure', 'Credential store response is invalid'));
          }
          return;
        }
        stdout.push(data);
      });

      // Always drain stderr, but never retain or surface it: native tools may
      // echo sensitive data in diagnostics.
      child.stderr.resume();
      child.once('error', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new CredentialStoreError('credential-store-failure', 'Credential store lookup failed'));
      });
      child.once('close', code => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (code !== 0) {
          reject(new CredentialStoreError('credential-unavailable', 'Credential is unavailable'));
          return;
        }
        resolve({ stdout: Buffer.concat(stdout).toString('utf8') });
      });
    });
  }
}

export function createPlatformCredentialStoreResolver(
  options: PlatformCredentialStoreResolverOptions = {},
): CredentialStoreResolver {
  return new PlatformCredentialStoreResolver({
    platform: options.platform ?? (typeof process === 'undefined' ? 'unknown' : process.platform),
    runner: options.runner,
    timeoutMs: options.timeoutMs,
    approvedReferences: options.approvedReferences,
  });
}
