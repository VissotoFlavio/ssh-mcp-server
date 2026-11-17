import { randomBytes } from 'node:crypto';

import type { ExecutionAuthorization } from './remote-command-execution.js';

export type ApprovedActionKind = 'file-upload' | 'remote-command';
export type ActionApprovalStatus = 'approved' | 'expired' | 'altered' | 'reused';

interface ApprovalRecord {
  readonly kind: ApprovedActionKind;
  readonly binding: string;
  readonly authorization: ExecutionAuthorization;
  readonly expiresAt: number;
  used: boolean;
}

/** One-use, request-bound authorization capability shared by all MCP actions. */
export class ActionApprovalStore {
  private readonly approvals = new Map<string, ApprovalRecord>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly ttlMs = 60_000,
  ) {}

  issue(kind: ApprovedActionKind, binding: string, authorization: ExecutionAuthorization): string {
    const capability = `${this.now().toString(36)}-${randomBytes(32).toString('hex')}`;
    const expiresAt = this.now() + this.ttlMs;
    this.approvals.set(capability, { kind, binding, authorization, expiresAt, used: false });
    const expiry = setTimeout(() => {
      const current = this.approvals.get(capability);
      if (current?.used !== true && current?.expiresAt === expiresAt) {
        this.approvals.delete(capability);
        void current.authorization.release?.().catch(() => undefined);
      }
    }, this.ttlMs);
    expiry.unref?.();
    return capability;
  }

  consume(
    kind: ApprovedActionKind,
    binding: string,
    capability: string | undefined,
  ): { readonly status: ActionApprovalStatus; readonly authorization?: ExecutionAuthorization } {
    if (capability === undefined) return { status: 'reused' };
    const approval = this.approvals.get(capability);
    if (approval === undefined || approval.used || approval.kind !== kind) return { status: 'reused' };
    if (approval.expiresAt <= this.now()) {
      this.approvals.delete(capability);
      void approval.authorization.release?.().catch(() => undefined);
      return { status: 'expired' };
    }
    if (approval.binding !== binding) return { status: 'altered' };
    approval.used = true;
    this.approvals.delete(capability);
    return { status: 'approved', authorization: approval.authorization };
  }
}
