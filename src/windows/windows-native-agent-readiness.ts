import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

import { WindowsOpenSshResolver } from './windows-openssh.js';
import { supportsWindowsAlphaRuntime } from './windows-runtime-support.js';

const require = createRequire(import.meta.url);
const MAX_TIMEOUT_MS = 60_000;
const WINDOWS_PATH = /^[A-Za-z]:\\(?:[^\\/:*?"<>|]+\\)*[^\\/:*?"<>|]+$/u;
const AUTHENTICATED_MARKER = 'authenticated to ';
const MARKER_TAIL_LENGTH = AUTHENTICATED_MARKER.length - 1;

export interface NativeAgentKeyReadinessDescriptor {
  readonly host: string;
  readonly port: number;
  readonly user: string;
}

export interface WindowsAgentKeyReadinessPaths {
  readonly knownHostsPath: string;
  readonly identityFile: string;
}

export interface WindowsNativeAgentReadinessBinding {
  prepareAgentKeyReadiness(capability: object): WindowsAgentKeyReadinessPaths;
}

export interface WindowsAgentKeyReadinessCommandRunner {
  run(executable: string, args: readonly string[], timeoutMs: number, signal?: AbortSignal): Promise<void>;
}

export class WindowsNativeAgentReadinessError extends Error {
  constructor() {
    super('Windows connection validation is unavailable');
    this.name = 'WindowsNativeAgentReadinessError';
  }
}

function unavailable(): never {
  throw new WindowsNativeAgentReadinessError();
}

function boundedTimeout(value: number): number {
  if (!Number.isInteger(value) || value <= 0 || value > MAX_TIMEOUT_MS) return unavailable();
  return value;
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => character.codePointAt(0)! < 0x20);
}

function validDescriptor(value: unknown): value is NativeAgentKeyReadinessDescriptor {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === 3 &&
    keys.includes('host') &&
    keys.includes('port') &&
    keys.includes('user') &&
    typeof (value as { host?: unknown }).host === 'string' &&
    typeof (value as { user?: unknown }).user === 'string' &&
    typeof (value as { port?: unknown }).port === 'number' &&
    Object.isFrozen(value)
  );
}

function validPreparedPaths(value: unknown): value is WindowsAgentKeyReadinessPaths {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const knownHostsPath = (value as { knownHostsPath?: unknown }).knownHostsPath;
  const identityFile = (value as { identityFile?: unknown }).identityFile;
  return (
    keys.length === 2 &&
    keys.includes('knownHostsPath') &&
    keys.includes('identityFile') &&
    typeof knownHostsPath === 'string' &&
    typeof identityFile === 'string' &&
    WINDOWS_PATH.test(knownHostsPath) &&
    WINDOWS_PATH.test(identityFile) &&
    !hasControlCharacter(knownHostsPath) &&
    !hasControlCharacter(identityFile)
  );
}

function loadNativeBinding(): WindowsNativeAgentReadinessBinding {
  if (!supportsWindowsAlphaRuntime()) return unavailable();
  let candidate: unknown;
  try {
    candidate = require('../../build/Release/windows_trust.node') as unknown;
  } catch {
    return unavailable();
  }
  if (
    typeof candidate !== 'object' ||
    candidate === null ||
    typeof (candidate as { prepareAgentKeyReadiness?: unknown }).prepareAgentKeyReadiness !== 'function'
  )
    return unavailable();
  return candidate as WindowsNativeAgentReadinessBinding;
}

function readinessArgs(paths: WindowsAgentKeyReadinessPaths, descriptor: NativeAgentKeyReadinessDescriptor): readonly string[] {
  return Object.freeze([
    '-F',
    'none',
    '-vv',
    '-N',
    '-T',
    '-n',
    '-o',
    'ControlPersist=no',
    '-o',
    'CanonicalizeHostname=no',
    '-o',
    'ProxyCommand=none',
    '-o',
    'ProxyJump=none',
    '-o',
    `HostName=${descriptor.host}`,
    '-o',
    'BatchMode=yes',
    '-o',
    'StrictHostKeyChecking=yes',
    '-o',
    `UserKnownHostsFile=${paths.knownHostsPath}`,
    '-o',
    'GlobalKnownHostsFile=NUL',
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    '-o',
    'NumberOfPasswordPrompts=0',
    '-o',
    `IdentityFile=${paths.identityFile}`,
    '-o',
    'IdentitiesOnly=yes',
    '-p',
    String(descriptor.port),
    '--',
    `${descriptor.user}@${descriptor.host}`,
  ]);
}

/** Runs a non-interactive transport probe and retains only a bounded marker tail. */
export class DirectWindowsAgentKeyReadinessCommandRunner implements WindowsAgentKeyReadinessCommandRunner {
  run(executable: string, args: readonly string[], timeoutMs: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(executable, [...args], { shell: false, windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
      } catch {
        reject(new WindowsNativeAgentReadinessError());
        return;
      }
      let settled = false;
      let authenticated = false;
      let tail = '';
      const settle = (action: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        signal?.removeEventListener('abort', abort);
        action();
      };
      const stop = () => {
        try {
          child.kill('SIGKILL');
        } catch {
          /* Close determines cleanup. */
        }
      };
      const fail = () => settle(() => reject(new WindowsNativeAgentReadinessError()));
      const abort = () => stop();
      const deadline = setTimeout(stop, boundedTimeout(timeoutMs));
      if (signal?.aborted) {
        stop();
        fail();
        return;
      }
      signal?.addEventListener('abort', abort, { once: true });
      child.stderr.on('data', (chunk: Buffer) => {
        tail = (tail + chunk.toString('utf8')).slice(-MARKER_TAIL_LENGTH - 4_096);
        if (tail.toLowerCase().includes(AUTHENTICATED_MARKER)) {
          authenticated = true;
          stop();
        }
      });
      child.once('error', fail);
      child.once('close', () => {
        if (authenticated && !signal?.aborted) settle(resolve);
        else fail();
      });
    });
  }
}

/**
 * Starts Microsoft OpenSSH from TypeScript only after native code has verified
 * the executable, snapshot and dedicated public key. The MCP protocol never
 * accepts or returns either path or OpenSSH output.
 */
export class WindowsNativeAgentReadiness {
  constructor(
    private readonly binding: WindowsNativeAgentReadinessBinding = loadNativeBinding(),
    private readonly resolver: Pick<WindowsOpenSshResolver, 'resolve'> = new WindowsOpenSshResolver(),
    private readonly commands: WindowsAgentKeyReadinessCommandRunner = new DirectWindowsAgentKeyReadinessCommandRunner(),
  ) {}

  async validate(capability: object, descriptor: NativeAgentKeyReadinessDescriptor, timeoutMs: number, signal?: AbortSignal): Promise<void> {
    if (typeof capability !== 'object' || capability === null || !validDescriptor(descriptor) || signal?.aborted) return unavailable();
    let paths: WindowsAgentKeyReadinessPaths;
    let executable: string;
    try {
      paths = this.binding.prepareAgentKeyReadiness(capability);
      executable = this.resolver.resolve();
    } catch {
      return unavailable();
    }
    if (!validPreparedPaths(paths) || !WINDOWS_PATH.test(executable) || hasControlCharacter(executable)) return unavailable();
    try {
      await this.commands.run(executable, readinessArgs(paths, descriptor), boundedTimeout(timeoutMs), signal);
    } catch {
      return unavailable();
    }
    if (signal?.aborted) return unavailable();
  }
}
