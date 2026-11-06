import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  WindowsNativeAgentReadiness,
  WindowsNativeAgentReadinessError,
  type NativeAgentKeyReadinessDescriptor,
} from '../../src/windows/windows-native-agent-readiness.js';

const descriptor: NativeAgentKeyReadinessDescriptor = Object.freeze({ host: 'api.internal.example', port: 22, user: 'deploy' });
const prepared = Object.freeze({ knownHostsPath: 'C:\\safe\\known_hosts', identityFile: 'C:\\safe\\agent.pub' });

test('runs only fixed non-interactive OpenSSH arguments from native-verified paths', async () => {
  const calls: unknown[] = [];
  const readiness = new WindowsNativeAgentReadiness(
    {
      prepareAgentKeyReadiness: (capability) => {
        calls.push(capability);
        return prepared;
      },
    },
    { resolve: () => 'C:\\Windows\\System32\\OpenSSH\\ssh.exe' },
    {
      run: async (...values) => {
        calls.push(values);
      },
    },
  );
  await readiness.validate({}, descriptor, 10_000);
  assert.equal(calls.length, 2);
  const [, args] = calls[1] as [string, readonly string[]];
  assert.ok(args.includes('-N') && args.includes('-T') && args.includes('BatchMode=yes'));
  assert.ok(!args.some((value) => value === 'exec' || value === 'shell' || value.includes('Forward')));
});

test('rejects mutable descriptors and untrusted native preparation', async () => {
  const readiness = new WindowsNativeAgentReadiness(
    { prepareAgentKeyReadiness: () => ({ knownHostsPath: 'relative', identityFile: 'C:\\safe\\agent.pub' }) },
    { resolve: () => 'C:\\Windows\\System32\\OpenSSH\\ssh.exe' },
    { run: async () => assert.fail('must not run') },
  );
  await assert.rejects(() => readiness.validate({}, { ...descriptor }, 10_000), WindowsNativeAgentReadinessError);
  await assert.rejects(() => readiness.validate({}, descriptor, 10_000), WindowsNativeAgentReadinessError);
});

test('redacts runner failures and forwards cancellation', async () => {
  let signal: AbortSignal | undefined;
  const readiness = new WindowsNativeAgentReadiness(
    { prepareAgentKeyReadiness: () => prepared },
    { resolve: () => 'C:\\Windows\\System32\\OpenSSH\\ssh.exe' },
    {
      run: async (_executable, _args, _timeout, received) => {
        signal = received;
        throw new Error('sensitive transcript');
      },
    },
  );
  const controller = new AbortController();
  await assert.rejects(() => readiness.validate({}, descriptor, 10_000, controller.signal), WindowsNativeAgentReadinessError);
  assert.equal(signal, controller.signal);
});
