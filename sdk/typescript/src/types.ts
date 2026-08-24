/**
 * TypeScript definitions for secretctl SDK
 * Note: Secret-bearing fields (passwords, tokens, seeds, cookies) are intentionally excluded.
 */

export type SecretAction =
  | "authenticate.password"
  | "authenticate.totp"
  | "form.sensitive_fill"
  | "oauth.authorize";

export type SecretCtlErrorCode =
  | "AUTH_POLICY_DENIED"
  | "APPROVAL_REJECTED"
  | "APPROVAL_TIMEOUT"
  | "CAPABILITY_EXPIRED"
  | "CAPABILITY_CONSUMED"
  | "EPOCH_INVALIDATED"
  | "ORIGIN_MISMATCH"
  | "FRAME_VIOLATION"
  | "SESSION_TERMINATED"
  | "EXECUTOR_FAILED"
  | "RECIPE_NOT_FOUND"
  | "SECURITY_VIOLATION"
  | "INTERNAL_ERROR";

export interface ConnectOptions {
  principalId: string;
  socketPath?: string;
}

export interface ActionStatus {
  requestId: string;
  state: string;
  detail?: string;
}

export interface TargetConstraint {
  origin: string;
  pathPrefix?: string;
}

export interface ExecuteRequest {
  requestId?: string;
  action: SecretAction;
  identity: string;
  target: TargetConstraint;
  browserSessionId: string;
  tabHint?: number;
  reason: string;
  timeoutMs?: number;
  clientContext?: Record<string, string>;
}

export interface ApprovalSummary {
  approvalId: string;
  actor: string;
  presenceVerified: boolean;
  decidedAt: string;
}

export type ExecuteResult =
  | {
      status: "completed" | "capability_issued";
      requestId: string;
      action: SecretAction;
      identity: string;
      verifiedOrigin: string;
      browserSessionId: string;
      evidenceId?: string;
      completedAt?: string;
    }
  | {
      status: "denied" | "expired" | "cancelled" | "failed";
      requestId: string;
      code: SecretCtlErrorCode;
      safeMessage: string;
      evidenceId?: string;
    };
