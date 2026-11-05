import { createRequire } from 'node:module';

import { supportsWindowsAlphaRuntime } from './windows-runtime-support.js';

const require = createRequire(import.meta.url);
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;

export interface NativeAgentKeyReadinessDescriptor {
  readonly host: string;
  readonly port: number;
  readonly user: string;
}

export interface WindowsNativeAgentReadinessBinding {
  startAgentKeyReadiness(
    capability: object,
    descriptor: NativeAgentKeyReadinessDescriptor,
    timeoutMs: number,
  ): {
    readonly promise: Promise<void>;
    readonly cancel: () => void;
  };
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
  return Number.isInteger(value) && value > 0 && value <= MAX_TIMEOUT_MS ? value : DEFAULT_TIMEOUT_MS;
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

function loadNativeBinding(): WindowsNativeAgentReadinessBinding {
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
    typeof (candidate as { startAgentKeyReadiness?: unknown }).startAgentKeyReadiness !== 'function'
  ) {
    return unavailable();
  }
  return candidate as WindowsNativeAgentReadinessBinding;
}

/**
 * Invokes the native-only OpenSSH ControlMaster readiness flow. The addon
 * accepts the opaque snapshot capability and constructs every SSH argument;
 * TypeScript never observes the snapshot pathname or a command line.
 */
export class WindowsNativeAgentReadiness {
  constructor(private readonly binding: WindowsNativeAgentReadinessBinding = loadNativeBinding()) {}

  async validate(capability: object, descriptor: NativeAgentKeyReadinessDescriptor, timeoutMs: number, signal?: AbortSignal): Promise<void> {
    if (typeof capability !== 'object' || capability === null || !validDescriptor(descriptor)) return unavailable();
    try {
      const operation = this.binding.startAgentKeyReadiness(capability, descriptor, boundedTimeout(timeoutMs));
      if (!operation || typeof operation.cancel !== 'function' || !(operation.promise instanceof Promise)) return unavailable();
      const cancel = () => operation.cancel();
      if (signal?.aborted) cancel();
      signal?.addEventListener('abort', cancel, { once: true });
      try {
        await operation.promise;
      } finally {
        signal?.removeEventListener('abort', cancel);
      }
    } catch {
      return unavailable();
    }
  }
}
