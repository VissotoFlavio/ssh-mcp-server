import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  WindowsNativeAgentReadiness,
  WindowsNativeAgentReadinessError,
  type NativeAgentKeyReadinessDescriptor,
} from '../../src/windows/windows-native-agent-readiness.js';

const descriptor: NativeAgentKeyReadinessDescriptor = Object.freeze({ host: 'api.internal.example', port: 22, user: 'deploy' });

test('passes only an opaque capability, a frozen descriptor, and bounded timeout to the native readiness boundary', async () => {
  const capability = {};
  const calls: unknown[] = [];
  const readiness = new WindowsNativeAgentReadiness({
    startAgentKeyReadiness: (...values) => {
      calls.push(values);
      return { promise: Promise.resolve(), cancel: () => undefined };
    },
  });
  await readiness.validate(capability, descriptor, 10_000);
  assert.deepEqual(calls, [[capability, descriptor, 10_000]]);
});

test('rejects mutable or caller-shaped descriptors before native readiness', async () => {
  const readiness = new WindowsNativeAgentReadiness({ startAgentKeyReadiness: () => assert.fail('must not run') });
  await assert.rejects(() => readiness.validate({}, { ...descriptor }, 10_000), WindowsNativeAgentReadinessError);
  await assert.rejects(
    () => readiness.validate({}, Object.freeze({ ...descriptor, command: 'id' }) as NativeAgentKeyReadinessDescriptor, 10_000),
    WindowsNativeAgentReadinessError,
  );
});

test('maps native failures to the fixed non-sensitive validation error', async () => {
  const readiness = new WindowsNativeAgentReadiness({
    startAgentKeyReadiness: () => {
      throw new Error('C:\\private\\known_hosts deploy@api.internal.example');
    },
  });
  await assert.rejects(() => readiness.validate({}, descriptor, 10_000), WindowsNativeAgentReadinessError);
});

test('forwards cancellation to the native operation and redacts its rejection', async () => {
  const controller = new AbortController();
  let cancelled = 0;
  let rejectOperation!: (reason?: unknown) => void;
  const readiness = new WindowsNativeAgentReadiness({
    startAgentKeyReadiness: () => ({
      promise: new Promise<void>((_resolve, reject) => {
        rejectOperation = reject;
      }),
      cancel: () => {
        cancelled += 1;
        rejectOperation(new Error('C:\\private\\known_hosts deploy@api.internal.example'));
      },
    }),
  });

  const validation = readiness.validate({}, descriptor, 10_000, controller.signal);
  controller.abort();
  await assert.rejects(validation, WindowsNativeAgentReadinessError);
  assert.equal(cancelled, 1);
});
