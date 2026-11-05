import { strict as assert } from 'node:assert';
import test from 'node:test';

import { supportsWindowsAlphaRuntime } from '../../src/windows/windows-runtime-support.js';

const facts = (osRelease: string, nodeVersion = '22.0.0') => ({ platform: 'win32', architecture: 'x64', nodeVersion, osRelease });

test('accepts only the documented Windows Server 2022 and Windows 11 23H2-or-newer builds', () => {
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.20348')), true);
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.22631')), true);
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.26100')), true);
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.22000')), false);
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.22621')), false);
});

test('fails closed outside the Windows x64 Node 22 envelope', () => {
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.22631', '21.9.0')), false);
  assert.equal(supportsWindowsAlphaRuntime({ ...facts('10.0.22631'), architecture: 'arm64' }), false);
  assert.equal(supportsWindowsAlphaRuntime({ ...facts('10.0.22631'), platform: 'linux' }), false);
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.22631invalid')), false);
  assert.equal(supportsWindowsAlphaRuntime(facts('10.0.22631', '22invalid')), false);
});
