import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  WindowsNativeAgentReadiness,
  WindowsNativeAgentReadinessError,
  type NativeAgentKeyReadinessDescriptor,
} from '../../src/windows/windows-native-agent-readiness.js';

const descriptor: NativeAgentKeyReadinessDescriptor = Object.freeze({ host: 'api.internal.example', port: 22, user: 'deploy' });

test('passes only an opaque capability, a frozen descriptor, and bounded timeout to the native readiness boundary', () => {
  const capability = {};
  const calls: unknown[] = [];
  const readiness = new WindowsNativeAgentReadiness({
    validateAgentKeyReadiness: (...values) => {
      calls.push(values);
    },
  });
  readiness.validate(capability, descriptor, 10_000);
  assert.deepEqual(calls, [[capability, descriptor, 10_000]]);
});

test('rejects mutable or caller-shaped descriptors before native readiness', () => {
  const readiness = new WindowsNativeAgentReadiness({ validateAgentKeyReadiness: () => assert.fail('must not run') });
  assert.throws(() => readiness.validate({}, { ...descriptor }, 10_000), WindowsNativeAgentReadinessError);
  assert.throws(
    () => readiness.validate({}, Object.freeze({ ...descriptor, command: 'id' }) as NativeAgentKeyReadinessDescriptor, 10_000),
    WindowsNativeAgentReadinessError,
  );
});

test('maps native failures to the fixed non-sensitive validation error', () => {
  const readiness = new WindowsNativeAgentReadiness({
    validateAgentKeyReadiness: () => {
      throw new Error('C:\\private\\known_hosts deploy@api.internal.example');
    },
  });
  assert.throws(() => readiness.validate({}, descriptor, 10_000), WindowsNativeAgentReadinessError);
});
