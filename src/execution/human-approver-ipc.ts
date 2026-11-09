import type { ApprovedProfileIdentity, HumanSudoApprovalProvider, SudoApprovalRequest } from './remote-command-execution.js';

export type HumanApproverIpcPlatform = 'posix' | 'windows';

export interface HumanApproverIpcRequest {
  readonly version: 1;
  readonly operationId: string;
  readonly leaseIdentityDigest: string;
  readonly request: SudoApprovalRequest;
  readonly identity: ApprovedProfileIdentity;
}

export interface HumanApproverIpcChannel {
  approve(request: HumanApproverIpcRequest, signal?: AbortSignal): Promise<boolean>;
}

/**
 * Typed boundary for the local ssh-mcp-approver. The channel implementation is
 * supplied by the trusted host integration: AF_UNIX on POSIX and a
 * SID-protected named pipe on Windows. MCP never receives the endpoint,
 * profile destination, identity, or canonical command.
 */
export class IpcHumanSudoApprovalProvider implements HumanSudoApprovalProvider {
  constructor(
    private readonly channel: HumanApproverIpcChannel,
    private readonly platform: HumanApproverIpcPlatform,
    private readonly identityForRequest: (request: SudoApprovalRequest) => {
      readonly operationId: string;
      readonly identity: ApprovedProfileIdentity;
      readonly leaseIdentityDigest: string;
    },
  ) {}

  async approve(request: SudoApprovalRequest, signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return false;
    const bound =
      request.operationId !== undefined && request.approvedIdentity !== undefined && request.leaseIdentityDigest !== undefined
        ? { operationId: request.operationId, identity: request.approvedIdentity, leaseIdentityDigest: request.leaseIdentityDigest }
        : this.identityForRequest(request);
    const ipcRequest: HumanApproverIpcRequest = Object.freeze({
      version: 1,
      operationId: bound.operationId,
      leaseIdentityDigest: bound.leaseIdentityDigest,
      request: Object.freeze({ ...request, args: Object.freeze([...request.args]) }),
      identity: Object.freeze({ ...bound.identity }),
    });
    // The platform discriminator is intentionally only an internal routing
    // guard; the endpoint remains owned by the trusted host integration.
    if (this.platform !== 'posix' && this.platform !== 'windows') return false;
    try {
      return (await this.channel.approve(ipcRequest, signal)) === true;
    } catch {
      return false;
    }
  }
}

export class UnavailableHumanApproverChannel implements HumanApproverIpcChannel {
  async approve(): Promise<boolean> {
    return false;
  }
}
