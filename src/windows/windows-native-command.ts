import {
  RemoteExecutionError,
  type RemoteCommandTransport,
  type RemoteCommandTransportRequest,
  type RemoteCommandTransportResult,
} from '../execution/remote-command-execution.js';

/** Opaque native capability; its contents are never inspected by ordinary JS. */
export type WindowsNativeAgentCapability = object;

export interface WindowsNativeAgentCommandRequest {
  readonly profileId: string;
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly expectedHostFingerprint: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export interface WindowsNativeAgentCommandBinding {
  execute(
    capability: WindowsNativeAgentCapability,
    request: WindowsNativeAgentCommandRequest,
    signal?: AbortSignal,
  ): Promise<RemoteCommandTransportResult>;
}

/**
 * The only supported JS/native contract for Windows agent-key commands. The
 * native implementation must resolve Microsoft OpenSSH, use the verified
 * ssh-add identity, retain the opaque known-hosts capability, use fixed argv,
 * bound output, and tear down the process tree before releasing the capability.
 * If that addon boundary is unavailable, this transport fails closed.
 */
export class WindowsNativeAgentCommandTransport implements RemoteCommandTransport {
  constructor(private readonly binding: WindowsNativeAgentCommandBinding | undefined) {}

  execute(request: RemoteCommandTransportRequest, signal?: AbortSignal): Promise<RemoteCommandTransportResult> {
    if (request.profile.authMode !== 'agent-key')
      return Promise.reject(
        new RemoteExecutionError('windows-agent-key-unsupported', 'Windows agent-key command execution requires the native trust boundary'),
      );
    if (this.binding === undefined || request.authorization?.withTransportContext === undefined)
      return Promise.reject(new RemoteExecutionError('windows-agent-key-unsupported', 'Windows native agent command boundary is unavailable'));
    const nativeRequest: WindowsNativeAgentCommandRequest = {
      profileId: request.profile.profileId,
      host: request.profile.host,
      port: request.profile.port,
      user: request.profile.user,
      expectedHostFingerprint: request.profile.expectedHostFingerprint,
      command: request.command,
      args: request.args,
      timeoutMs: request.timeoutMs,
      maxOutputBytes: request.maxOutputBytes,
    };
    const execute = (capability: WindowsNativeAgentCapability): Promise<RemoteCommandTransportResult> =>
      this.binding!.execute(capability, nativeRequest, signal);
    const operation = Promise.resolve().then(() => request.authorization!.withTransportContext!(execute));
    return operation.catch((error: unknown) => {
      const code = (error as { code?: unknown })?.code;
      if (code === 'timeout') throw new RemoteExecutionError('timeout', 'Remote command timed out');
      if (code === 'cancelled') throw new RemoteExecutionError('cancelled', 'Remote command cancelled');
      throw new RemoteExecutionError('connection-failure', 'Remote SSH connection failed');
    });
  }
}
