import { strict as assert } from 'node:assert';
import test from 'node:test';

import {
  RemoteCommandExecutionProvider,
  RemoteExecutionError,
  SudoApprovalStore,
  WindowsRemoteCommandTransport,
  createExecutionAuthorization,
  serializeRemoteAuditEvent,
  type RemoteCommandTransport,
  type RemoteCommandTransportResult,
} from '../../src/execution/remote-command-execution.js';
import { HostIdentityCredentialPolicyError } from '../../src/policy/host-identity-credential-policy.js';
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
  startOnExecute = false;

  async execute(request: Parameters<RemoteCommandTransport['execute']>[0]): Promise<RemoteCommandTransportResult> {
    this.calls.push(request);
    if (this.startOnExecute) request.onCommandStarted?.();
    if (this.never) return new Promise<RemoteCommandTransportResult>(() => undefined);
    if (this.error !== undefined) throw this.error;
    return this.result;
  }
}

function createProvider(
  transport = new FakeTransport(),
  options: { now?: () => number; audit?: string[]; approvals?: SudoApprovalStore; humanApproval?: boolean; authorizationError?: unknown } = {},
) {
  return {
    provider: new RemoteCommandExecutionProvider({
      profiles: { getProfile: async (profileId: string) => (profileId === profile.profileId ? profile : undefined) },
      connectionValidation: {
        validateConnection: async (input: unknown) => ({ profileId: (input as { profileId: string }).profileId, ready: true as const }),
        authorizeExecution: async () => {
          if (options.authorizationError !== undefined) throw options.authorizationError;
          return { profile };
        },
      },
      transport,
      sudoApprovals: options.approvals,
      humanApproval: options.humanApproval === false ? undefined : { approve: async () => true },
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

test('preserves public host-key and authentication failure classes from authorization', async () => {
  const hostKey = createProvider(undefined, { authorizationError: new HostIdentityCredentialPolicyError('known-hosts-entry-mismatch', 'private') });
  assert.equal((await hostKey.provider.execute(command)).code, 'host-key-failure');

  const authentication = createProvider(undefined, {
    authorizationError: new HostIdentityCredentialPolicyError('agent-identity-unavailable', 'private'),
  });
  assert.equal((await authentication.provider.execute(command)).code, 'authentication-failure');
});

test('blocks sudo without a server-issued approval and records a redacted audit event', async () => {
  const audit: string[] = [];
  const { provider, transport } = createProvider(undefined, { audit });
  const result = await provider.execute({ profileId: profile.profileId, command: 'sudo', args: ['--password=secret'] });
  assert.equal(result.outcome, 'approval-required');
  assert.equal(result.code, 'approval-required');
  assert.equal(transport.calls.length, 0);
  assert.equal(audit.length, 1);
  assert.equal(audit[0].includes('secret'), false);
  assert.equal(JSON.parse(audit[0]).approvalState, 'blocked');
});

test('reports unavailable sudo approval as a failure before transport', async () => {
  const { provider, transport } = createProvider(undefined, { humanApproval: false });
  const result = await provider.execute({ profileId: profile.profileId, command: 'sudo', args: ['id'] });
  assert.equal(result.outcome, 'failure');
  assert.equal(result.code, 'approval-unavailable');
  assert.equal(transport.calls.length, 0);
});

test('requires approval for common privilege-escalation executables', async () => {
  for (const command of ['doas', 'pkexec', 'runuser', 'su']) {
    const { provider, transport } = createProvider(undefined, { humanApproval: false });
    const result = await provider.execute({ profileId: profile.profileId, command, args: ['id'] });
    assert.equal(result.code, 'approval-unavailable');
    assert.equal(transport.calls.length, 0);
  }
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

test('preserves unknown outcome when the transport cannot establish completion', async () => {
  const transport = new FakeTransport();
  transport.error = new RemoteExecutionError('outcome-unknown', 'unknown');
  const { provider } = createProvider(transport);
  const result = await provider.execute(command);
  assert.equal(result.outcome, 'unknown');
  assert.equal(result.code, 'outcome-unknown');
  assert.equal(result.exitCode, null);
});

test('reports unknown outcome when cancellation occurs after command handoff', async () => {
  const transport = new FakeTransport();
  transport.never = true;
  transport.startOnExecute = true;
  const { provider } = createProvider(transport);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5);
  const result = await provider.execute({ ...command, timeoutMs: 100 }, controller.signal);
  assert.equal(result.outcome, 'unknown');
  assert.equal(result.code, 'outcome-unknown');
  assert.equal(result.exitCode, null);
});

test('rejects shell interpreters and control syntax but leaves remote wrappers to the target', async () => {
  const { provider, transport } = createProvider();
  for (const request of [
    { ...command, command: 'sh', args: ['-c', 'sudo id'] },
    { ...command, command: 'env', args: ['sudo', 'id'] },
    { ...command, command: 'nohup', args: ['sudo', 'id'] },
    { ...command, command: 'sudoedit', args: ['id'] },
    { ...command, command: '/usr/bin/sudoedit', args: ['id'] },
    { ...command, command: 'echo', args: ['ok; sudo id'] },
    { ...command, command: 'echo', args: ['ok &'] },
    { ...command, command: 'bash', args: ['-c', 'id'] },
  ]) {
    const result = await provider.execute(request);
    assert.equal(
      result.code,
      ['nohup', 'env'].includes(request.command) || request.command.includes('sudoedit') ? 'approval-required' : 'invalid-input',
    );
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
      '-psecret',
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
    argsHmac: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  });
  assert.equal(serialized.includes('super-secret'), false);
  assert.equal(serialized.includes('bearer-secret'), false);
  assert.equal(serialized.includes('password@example.invalid'), false);
  assert.equal(serialized.includes('assignment-secret'), false);
  assert.equal(serialized.includes('secret-cookie'), false);
  assert.equal(serialized.includes('"argsHmac"'), true);
  assert.equal(
    JSON.parse(serialized).args.every((value: string) => value === '[ARG]' || value.startsWith('-')),
    true,
  );
});

test('times out a hung profile validation and records audit failure if the sink fails', async () => {
  const audit: string[] = [];
  const transport = new FakeTransport();
  const provider = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => profile },
    connectionValidation: {
      validateConnection: async () => new Promise(() => undefined),
      authorizeExecution: async () => new Promise(() => undefined),
    },
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
    connectionValidation: {
      validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }),
      authorizeExecution: async () => ({ profile }),
    },
    transport: sinkFailure.transport,
    auditSink: () => {
      throw new Error('sink unavailable');
    },
  });
  const result = await audited.execute(command);
  assert.equal(result.code, 'provider-failure');
});

test('preserves outcome-unknown when journal finalization and secondary audit both fail', async () => {
  const provider = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => profile },
    connectionValidation: {
      authorizeExecution: async () => ({ profile }),
      validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }),
    },
    transport: new FakeTransport(),
    auditSink: () => {
      throw new Error('sink unavailable');
    },
    auditJournal: {
      async digestArguments() {
        return '0000000000000000000000000000000000000000000000000000000000000000';
      },
      async begin() {
        return {
          operationId: '0123456789abcdef0123456789abcdef',
          finish: async () => {
            throw new Error('journal unavailable');
          },
        };
      },
    },
  });
  const result = await provider.execute(command);
  assert.equal(result.outcome, 'unknown');
  assert.equal(result.code, 'outcome-unknown');
  assert.equal(result.exitCode, null);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('uses the approved sudo lease when the profile source changes', async () => {
  const changed = { ...profile, host: 'changed.internal.example' };
  let current = profile;
  const transport = new FakeTransport();
  const provider = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => current },
    connectionValidation: {
      validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }),
      authorizeExecution: async () => ({ profile: current }),
    },
    transport,
    authorizationProvider: {
      authorize: async () => createExecutionAuthorization(current, Date.now() + 60_000),
    },
    humanApproval: { approve: async () => true },
  });
  const sudo = { profileId: profile.profileId, command: 'sudo', args: ['id'] };
  const approval = await provider.requestSudoApproval(sudo);
  current = changed;
  const result = await provider.execute({ ...sudo, approvalToken: approval.token });
  assert.equal(result.code, 'success');
  assert.equal((transport.calls[0] as { profile: ConnectionProfile }).profile.host, profile.host);
});

test('keeps the approved profile snapshot when no explicit authorization provider is injected', async () => {
  let current = profile;
  const transport = new FakeTransport();
  const provider = new RemoteCommandExecutionProvider({
    profiles: { getProfile: async () => current },
    connectionValidation: {
      validateConnection: async () => ({ profileId: profile.profileId, ready: true as const }),
      authorizeExecution: async () => ({ profile: current }),
    },
    transport,
    humanApproval: { approve: async () => true },
  });
  const sudo = { profileId: profile.profileId, command: 'sudo', args: ['id'] };
  const approval = await provider.requestSudoApproval(sudo);
  current = { ...profile, host: 'changed.internal.example' };
  const result = await provider.execute({ ...sudo, approvalToken: approval.token });
  assert.equal(result.code, 'success');
  assert.equal((transport.calls[0] as { profile: ConnectionProfile }).profile.host, profile.host);
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
