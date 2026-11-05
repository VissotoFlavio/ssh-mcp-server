import { createRequire } from 'node:module';

import { parseCredentialReference, type PasswordCredential } from '../credentials/credential-store.js';

import { supportsWindowsAlphaRuntime } from './windows-runtime-support.js';

const require = createRequire(import.meta.url);

export interface WindowsCredentialBinding {
  readCredential(locator: string): string;
}

export class WindowsCredentialManagerError extends Error {
  constructor() {
    super('Windows credential manager is unavailable');
    this.name = 'WindowsCredentialManagerError';
  }
}

function unavailable(): never {
  throw new WindowsCredentialManagerError();
}

function loadNativeBinding(): WindowsCredentialBinding {
  if (!supportsWindowsAlphaRuntime()) return unavailable();
  let candidate: unknown;
  try {
    candidate = require('../../build/Release/windows_trust.node');
  } catch {
    return unavailable();
  }
  if (typeof candidate !== 'object' || candidate === null || typeof (candidate as { readCredential?: unknown }).readCredential !== 'function') {
    return unavailable();
  }
  return candidate as WindowsCredentialBinding;
}

/** Reads only an approved `os://ssh/<locator>` Credential Manager secret. */
export class WindowsCredentialManager {
  private readonly approvedReferences: ReadonlySet<string>;

  constructor(
    private readonly binding: WindowsCredentialBinding = loadNativeBinding(),
    approvedReferences: readonly string[] | ReadonlySet<string> = [],
  ) {
    this.approvedReferences = new Set([...approvedReferences].map((reference) => parseCredentialReference(reference).reference));
  }

  getPassword(reference: string): PasswordCredential {
    try {
      const parsed = parseCredentialReference(reference);
      if (parsed.provider !== 'ssh' || !this.approvedReferences.has(parsed.reference)) return unavailable();
      return this.read(parsed.locator);
    } catch {
      return unavailable();
    }
  }

  private read(locator: string): PasswordCredential {
    try {
      const password = this.binding.readCredential(locator);
      if (typeof password !== 'string' || password.length === 0 || password.includes('\u0000')) return unavailable();
      return { password };
    } catch {
      return unavailable();
    }
  }
}
