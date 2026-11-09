import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  RemoteCommandExecutionProvider,
  RemoteExecutionError,
  SudoApprovalStore,
  WindowsRemoteCommandTransport,
  serializeRemoteAuditEvent,
  type RemoteCommandTransport,
  type RemoteCommandTransportResult,
} from '../../src/execution/remote-command-execution.js';
import type { ConnectionProfile } from '../../src/profiles/connection-profile.js';

const profile: ConnectionProfile = {
  profileId: 'production-api',
  host: 'api.internal.example',
  port: 22,
  user: 'deploy',
  expectedHostFingerprint: 'SHA256:1111111111111111111111111111111111111111111',
  authMode: 'agent-key',
  approvedKnownHostsReference: 'known-hosts://production-api',
};

class FakeTransport implements RemoteCommandTransport {
  calls: unknown[] = [];
  result = { exitCode: 0, stdout: 'ok', stderr: '', outputTruncated: false };
  error: Error | undefined;
  never = false;

  async execute(request: Parameters<RemoteCommandTransport['execute']>[0]): Promise<RemoteCommandTransportResult> {
    this.calls.push(request);
    if (this.never) return new Promise<RemoteCommandTransportResult>(() => undefined);
    if (this.error !== undefined) throw this.error;
    return this.result;
  }
}

function createProvider(transport = new FakeTransport(), options: { now?: () => number; audit?: string[]; approvals?: SudoApprovalStore } = {}) {
  return {
    provider: new RemoteCommandExecutionProvider({
      profiles: { getProfile: async (profileId: string) => (profileId === profile.profileId ? profile : undefined) },
      connectionValidation: {
        validateConnection: async (input: unknown) => ({ profileId: (input as { profileId: string }).profileId, ready: true as const }),
      },
      transport,
      sudoApprovals: options.approvals,
      humanApproval: { approve: async () => true },
      auditSink: options.audit === undefined ? undefined : (event) => options.audit!.push(event),
      now: options.now,
    }),
    transport,
  };
}

const command = { profileId: 'production-api', command: 'uname', args: ['-a'] };

test('executes the strict contract and returns bounded structured output', async () => {
  const { provider, transport } = createProvider();
  const result = await provider.execute(command);
  assert.deepEqual(result, {
    profileId: 'production-api',
    outcome: 'success',
    code: 'success',
    exitCode: 0,
    stdout: 'ok',
    stderr: '',
    outputTruncated: false,
  });
  assert.equal(transport.calls.length, 1);
});

test('rejects extra local execution controls before profile or transport access', async () => {
  let validated = false;
  const audit: string[] = [];
  const { provider, transport } = createProvider(undefined, { audit });
  const result = await provider.execute({ ...command, shell: true });
  validated = transport.calls.length > 0;
  assert.equal(result.code, 'invalid-input');
  assert.equal(validated, false);
  assert.equal(JSON.stringify(audit).includes('shell'), false);
});

test('maps authentication, host-key, timeout and cancellation failures safely', async (t) => {
  for (const [name, error, code] of [
    ['authentication', new RemoteExecutionError('authentication-failure', 'hidden'), 'authentication-failure'],
    ['host key', new RemoteExecutionError('host-key-failure', 'hidden'), 'host-key-failure'],
    ['connection', new RemoteExecutionError('connection-failure', 'hidden'), 'connection-failure'],
    ['timeout', new RemoteExecutionError('timeout', 'hidden'), 'timeout'],
    ['cancel', new RemoteExecutionError('cancelled', 'hidden'), 'cancelled'],
  ] as const) {
    await t.test(name, async () => {
      const transport = new FakeTransport();
      transport.error = error;
      const { provider } = createProvider(transport);
      const result = await provider.execute(command);
      assert.equal(result.code, code);
      assert.equal(result.stdout, '');
      assert.equal(JSON.stringify(result).includes('hidden'), false);
    });
  }
});

test('blocks sudo without a server-issued approval and records a redacted audit event', async () => {
  const audit: string[] = [];
  const { provider, transport } = createProvider(undefined, { audit });
  const result = await provider.execute({ profileId: profile.profileId, command: 'sudo', args: ['--password=secret'] });
  assert.equal(result.code, 'approval-required');
  assert.equal(transport.calls.length, 0);
  assert.equal(audit.length, 1);
  assert.equal(audit[0].includes('secret'), false);
  assert.equal(JSON.parse(audit[0]).approvalState, 'blocked');
});

test('binds sudo approval to exact request, expiry and one-time use', async () => {
  let now = 1_000;
  const approvals = new SudoApprovalStore();
  const { provider, transport } = createProvider(undefined, { approvals, now: () => now });
  const sudo = { profileId: profile.profileId, command: 'sudo', args: ['systemctl', 'restart', 'api'] };
  const approval = await provider.requestSudoApproval(sudo);
  assert.equal(approval.approved, true);
  assert.equal(typeof approval.token, 'string');

  const altered = await provider.execute({ ...sudo, args: ['systemctl', 'stop', 'api'], approvalToken: approval.token });
  assert.equal(altered.code, 'approval-altered');
  assert.equal(transport.calls.length, 0);

  const executed = await provider.execute({ ...sudo, approvalToken: approval.token });
  assert.equal(executed.code, 'success');
  assert.equal(transport.calls.length, 1);

  const reused = await provider.execute({ ...sudo, approvalToken: approval.token });
  assert.equal(reused.code, 'approval-reused');

  const second = await provider.requestSudoApproval(sudo);
  now += 60_001;
  const expired = await provider.execute({ ...sudo, approvalToken: second.token });
  assert.equal(expired.code, 'approval-expired');
});

test('honors an already-cancelled request before remote transport', async () => {
  const { provider, transport } = createProvider();
  const controller = new AbortController();
  controller.abort();
  const result = await provider.execute(command, controller.signal);
  assert.equal(result.code, 'cancelled');
  assert.equal(transport.calls.length, 0);
});

test('enforces the output limit and transport deadline at the provider boundary', async () => {
  const transport = new FakeTransport();
  transport.result = { exitCode: 0, stdout: '123456', stderr: 'stderr', outputTruncated: false };
  const { provider } = createProvider(transport);
  const limited = await provider.execute({ ...command, maxOutputBytes: 4 });
  assert.equal(limited.outputTruncated, true);
  assert.equal(Buffer.byteLength(limited.stdout) + Buffer.byteLength(limited.stderr), 4);

  transport.never = true;
  const timedOut = await provider.execute({ ...command, timeoutMs: 10 });
  assert.equal(timedOut.code, 'timeout');

  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5);
  const cancelled = await provider.execute({ ...command, timeoutMs: 100 }, controller.signal);
  assert.equal(cancelled.code, 'cancelled');
});

test('rejects shell wrappers, control flags, metacharacters, and background helpers', async () => {
  const { provider, transport } = createProvider();
  for (const request of [
    { ...command, command: 'sh', args: ['-c', 'sudo id'] },
    { ...command, command: 'env', args: ['sudo', 'id'] },
    { ...command, command: 'nohup', args: ['sudo', 'id'] },
    { ...command, command: 'echo', args: ['ok; sudo id'] },
    { ...command, command: 'echo', args: ['ok &'] },
    { ...command, command: 'bash', args: ['-c', 'id'] },
  ]) {
    const result = await provider.execute(request);
    assert.equal(result.code, 'invalid-input');
  }
  assert.equal(transport.calls.length, 0);
});

test('redacts separated flags, headers, URL credentials, and shell assignments in audit records', () => {
  const serialized = serializeRemoteAuditEvent({
    profileId: 'production-api',
    command: 'curl',
    args: [
      '--password',
      'super-secret',
      '--header',
      'Authorization: Bearer bearer-secret',
      'https://user:password@example.invalid/api',
      'PASSWORD=assignment-secret',
      'Cookie: session=secret-cookie',
    ],
    approvalState: 'not-required',
    durationMs: 1,
    exitCode: 0,
    outcome: 'success',
    code: 'success',
  });
  assert.equal(serialized.includes('super-secret'), false);
  assert.equal(serialized.includes('bearer-secret'), false);
  assert.equal(serialized.includes('password@example.invalid'), false);
  assert.equal(serialized.includes('assignment-secret'), false);
  assert.equal(serialized.includes('secret-cookie'), false);
});

test('times out a hung profile validation and records audit failure if the sink fails', async () => {
  const audit: string[] = [];
  const transport = new FakeTransport();
  const provider = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => profile },
    connectionValidation: { validateConnection: async () => new Promise(() => undefined) },
    transport,
    auditSink: (event) => audit.push(event),
  });
  const timedOut = await provider.execute({ ...command, timeoutMs: 10 });
  assert.equal(timedOut.code, 'timeout');
  assert.equal(transport.calls.length, 0);
  assert.equal(audit.length, 1);

  const sinkFailure = createProvider(new FakeTransport());
  const audited = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => profile },
    connectionValidation: { validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }) },
    transport: sinkFailure.transport,
    auditSink: () => {
      throw new Error('sink unavailable');
    },
  });
  const result = await audited.execute(command);
  assert.equal(result.code, 'provider-failure');
});

test('rejects a sudo approval when the approved profile identity changes', async () => {
  const changed = { ...profile, host: 'changed.internal.example' };
  let current = profile;
  const provider = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => current },
    connectionValidation: { validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }) },
    transport: new FakeTransport(),
    humanApproval: { approve: async () => true },
  });
  const sudo = { profileId: profile.profileId, command: 'sudo', args: ['id'] };
  const approval = await provider.requestSudoApproval(sudo);
  current = changed;
  const result = await provider.execute({ ...sudo, approvalToken: approval.token });
  assert.equal(result.code, 'approval-altered');
});

test('blocks Windows agent-key execution while retaining the password transport boundary', async () => {
  const passwordTransport: RemoteCommandTransport = {
    async execute() {
      return { exitCode: 0, stdout: 'ok', stderr: '', outputTruncated: false };
    },
  };
  const transport = new WindowsRemoteCommandTransport(passwordTransport);
  await assert.rejects(
    transport.execute({ profile: { ...profile, authMode: 'agent-key' }, command: 'id', args: [], timeoutMs: 100, maxOutputBytes: 100 }),
    (error: unknown) => error instanceof RemoteExecutionError && error.code === 'windows-agent-key-unsupported',
  );
  const result = await transport.execute({
    profile: { ...profile, authMode: 'password', credentialReference: 'os://ssh/production-api' },
    command: 'id',
    args: [],
    timeoutMs: 100,
    maxOutputBytes: 100,
  });
  assert.equal(result.stdout, 'ok');
});
