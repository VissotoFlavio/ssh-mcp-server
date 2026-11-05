import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  WindowsCredentialManager,
  WindowsCredentialManagerError,
  type WindowsCredentialBinding,
} from '../../src/windows/windows-credential-manager.js';

function binding(password = 'not-logged'): WindowsCredentialBinding {
  return { readCredential: (locator) => (locator === 'production-api' ? password : '') };
}

test('reads only the opaque approved ssh credential locator through the native boundary', () => {
  const credentials = new WindowsCredentialManager(binding(), ['os://ssh/production-api']);
  assert.deepEqual(credentials.getPassword('os://ssh/production-api'), { password: 'not-logged' });
});

test('rejects a valid but unapproved locator before native credential lookup', () => {
  let calls = 0;
  const credentials = new WindowsCredentialManager({ readCredential: () => ((calls += 1), 'not-logged') }, ['os://ssh/production-api']);
  assert.throws(() => credentials.getPassword('os://ssh/staging-api'), WindowsCredentialManagerError);
  assert.equal(calls, 0);
});

test('rejects malformed ssh locators before native credential lookup', () => {
  let calls = 0;
  const credentials = new WindowsCredentialManager({ readCredential: () => ((calls += 1), 'not-logged') }, ['os://ssh/production-api']);
  assert.throws(() => credentials.getPassword('os://ssh/../production-api'), WindowsCredentialManagerError);
  assert.throws(() => credentials.getPassword('os://ssh/production-api?target=other'), WindowsCredentialManagerError);
  assert.equal(calls, 0);
});

test('rejects arbitrary providers, malformed references, native failures, and empty credential material', () => {
  const credentials = new WindowsCredentialManager(binding(), ['os://ssh/production-api']);
  assert.throws(() => credentials.getPassword('os://other/production-api'), WindowsCredentialManagerError);
  assert.throws(() => credentials.getPassword('os://ssh/password'), WindowsCredentialManagerError);
  assert.throws(
    () => new WindowsCredentialManager({ readCredential: () => '' }, ['os://ssh/production-api']).getPassword('os://ssh/production-api'),
    WindowsCredentialManagerError,
  );
  assert.throws(
    () =>
      new WindowsCredentialManager(
        {
          readCredential: () => {
            throw new Error('credential=private');
          },
        },
        ['os://ssh/production-api'],
      ).getPassword('os://ssh/production-api'),
    WindowsCredentialManagerError,
  );
});
