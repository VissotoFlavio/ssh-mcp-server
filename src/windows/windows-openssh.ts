import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

import type { OpenSshExecutableResolver } from '../adapters/ssh-connection-adapters.js';

import { supportsWindowsAlphaRuntime } from './windows-runtime-support.js';

const require = createRequire(import.meta.url);
const WINDOWS_EXECUTABLE = /^[A-Za-z]:\\(?:[^\\/:*?"<>|]+\\)*[^\\/:*?"<>|]+\.exe$/u;

export interface WindowsOpenSshPaths {
  readonly ssh: string;
  readonly sshAdd: string;
  readonly version: string;
}

export interface WindowsOpenSshBinding {
  resolveOpenSsh(): WindowsOpenSshPaths;
  probeSshAdd(timeoutMs: number): number;
  startSshAddProbe(timeoutMs: number): { readonly promise: Promise<boolean>; readonly cancel: () => void };
}

export interface WindowsOpenSshCommandRunner {
  run(executable: string, args: readonly string[], timeoutMs: number, verifyBeforeLaunch?: () => string, signal?: AbortSignal): Promise<number>;
}

const MAX_TIMEOUT_MS = 60_000;

function boundedTimeout(timeoutMs: number): number {
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) return unavailable();
  return timeoutMs;
}

/**
 * The only production subprocess boundary for the Windows `ssh-add -l` probe.
 * It discards all child output and never accepts shell options from callers.
 */
export class DirectWindowsOpenSshCommandRunner implements WindowsOpenSshCommandRunner {
  run(executable: string, args: readonly string[], timeoutMs: number, verifyBeforeLaunch?: () => string, signal?: AbortSignal): Promise<number> {
    return new Promise((resolve, reject) => {
      try {
        if (verifyBeforeLaunch !== undefined && verifyBeforeLaunch() !== executable) return reject(new WindowsOpenSshError());
      } catch {
        return reject(new WindowsOpenSshError());
      }
      let settled = false;
      const child = spawn(executable, [...args], {
        shell: false,
        windowsHide: true,
        stdio: 'ignore',
      });
      const settle = (action: () => void) => {
        if (settled) return;
        settled = true;
        if (deadline !== undefined) clearTimeout(deadline);
        action();
      };
      const stop = () => {
        try {
          child.kill('SIGKILL');
        } catch {
          /* Child creation or termination may already have failed. */
        }
      };
      const deadline = setTimeout(() => {
        stop();
      }, boundedTimeout(timeoutMs));
      const onAbort = () => stop();
      if (signal?.aborted) return settle(() => reject(new WindowsOpenSshError()));
      signal?.addEventListener('abort', onAbort, { once: true });
      child.once('error', () => settle(() => reject(new WindowsOpenSshError())));
      child.once('close', (code) => {
        signal?.removeEventListener('abort', onAbort);
        settle(() => resolve(code ?? 1));
      });
    });
  }
}

export class WindowsOpenSshError extends Error {
  constructor() {
    super('Windows OpenSSH is unavailable');
    this.name = 'WindowsOpenSshError';
  }
}

function unavailable(): never {
  throw new WindowsOpenSshError();
}

function validPaths(value: unknown): value is WindowsOpenSshPaths {
  const ssh = (value as { ssh?: unknown }).ssh;
  const sshAdd = (value as { sshAdd?: unknown }).sshAdd;
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Reflect.ownKeys(value).length === 3 &&
    typeof ssh === 'string' &&
    typeof sshAdd === 'string' &&
    typeof (value as { version?: unknown }).version === 'string' &&
    supportedVersion((value as { version: string }).version) &&
    !hasControlCharacter(ssh) &&
    !hasControlCharacter(sshAdd) &&
    WINDOWS_EXECUTABLE.test(ssh) &&
    WINDOWS_EXECUTABLE.test(sshAdd)
  );
}

function supportedVersion(value: string): boolean {
  const match = /^(\d+)\.(\d+)\.\d+\.\d+$/u.exec(value);
  if (match === null) return false;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  return Number.isSafeInteger(major) && Number.isSafeInteger(minor) && (major > 9 || (major === 9 && minor >= 5));
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => character.codePointAt(0)! < 0x20);
}

function loadNativeBinding(): WindowsOpenSshBinding {
  if (!supportsWindowsAlphaRuntime()) return unavailable();
  let candidate: unknown;
  try {
    candidate = require('../../build/Release/windows_trust.node');
  } catch {
    return unavailable();
  }
  if (
    typeof candidate !== 'object' ||
    candidate === null ||
    typeof (candidate as { resolveOpenSsh?: unknown }).resolveOpenSsh !== 'function' ||
    typeof (candidate as { probeSshAdd?: unknown }).probeSshAdd !== 'function' ||
    typeof (candidate as { startSshAddProbe?: unknown }).startSshAddProbe !== 'function'
  ) {
    return unavailable();
  }
  return candidate as WindowsOpenSshBinding;
}

/**
 * Resolves only the native-verified system OpenSSH pair. The addon owns path,
 * ACL, reparse, stable-identity, catalog-signature, and publisher checks.
 */
export class WindowsOpenSshResolver implements OpenSshExecutableResolver {
  constructor(private readonly binding: WindowsOpenSshBinding = loadNativeBinding()) {}

  paths(): WindowsOpenSshPaths {
    try {
      const paths = this.binding.resolveOpenSsh();
      if (!validPaths(paths)) return unavailable();
      return Object.freeze({ ssh: paths.ssh, sshAdd: paths.sshAdd, version: paths.version });
    } catch {
      return unavailable();
    }
  }

  resolve(): string {
    return this.paths().ssh;
  }

  probeSshAdd(timeoutMs: number): number {
    try {
      return this.binding.probeSshAdd(boundedTimeout(timeoutMs));
    } catch {
      return unavailable();
    }
  }

  async probeSshAddAsync(timeoutMs: number, signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return unavailable();
    try {
      const operation = this.binding.startSshAddProbe(boundedTimeout(timeoutMs));
      if (!operation || typeof operation.cancel !== 'function' || !(operation.promise instanceof Promise)) return unavailable();
      const cancel = () => operation.cancel();
      signal?.addEventListener('abort', cancel, { once: true });
      try {
        const available = await operation.promise;
        if (signal?.aborted || typeof available !== 'boolean') return unavailable();
        return available;
      } finally {
        signal?.removeEventListener('abort', cancel);
      }
    } catch {
      return unavailable();
    }
  }
}

/** Probes the agent through the verified ssh-add executable without exposing key material. */
export class WindowsSshAddIdentity {
  constructor(
    private readonly resolver: WindowsOpenSshResolver,
    private readonly timeoutMs: number,
    private readonly commands: WindowsOpenSshCommandRunner = new DirectWindowsOpenSshCommandRunner(),
  ) {}

  async isAvailable(signal?: AbortSignal): Promise<boolean> {
    try {
      return this.commands instanceof DirectWindowsOpenSshCommandRunner
        ? await this.resolver.probeSshAddAsync(this.timeoutMs, signal)
        : (await this.commands.run(this.resolver.paths().sshAdd, ['-l'], this.timeoutMs, () => this.resolver.paths().sshAdd, signal)) === 0 &&
            !signal?.aborted;
    } catch {
      return false;
    }
  }
}
