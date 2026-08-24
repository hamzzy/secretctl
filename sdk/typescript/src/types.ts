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
  | "USER_PRESENCE_UNAVAILABLE"
  | "SECURITY_VIOLATION"
  | "INTERNAL_ERROR";

export interface ConnectOptions {
  principalId?: string;
  socketPath?: string;
  brokerPublicKeyPath?: string;
  signingKeyPath?: string;
}

export interface ActionStatus {
  requestId: string;
  state: string;
  detail?: string;
}

export interface SessionInfo {
  protocolVersion: string;
  principalId: string;
  role: "agent";
  rekeyAfterSeconds: number;
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

export interface AuthenticateOptions {
  action?: SecretAction;
  requestId?: string;
  timeoutMs?: number;
  clientContext?: Record<string, string>;
}

export type SafeLocator =
  | { kind: "css" | "test_id" | "ref" | "text"; value: string }
  | { kind: "role"; role: string; name: string };

export type WaitCondition =
  | { kind: "locator_present" | "locator_absent"; locator: SafeLocator }
  | { kind: "text_present" | "url_prefix" | "url_changed_from"; value: string };

export interface BrowserTab {
  tab_id: string;
  url: string;
  title: string;
}

export interface PageTextResult {
  text: string;
  truncated: boolean;
}

export interface SafePageElement {
  reference: string;
  tag: string;
  role: string;
  name: string;
  input_type?: string;
  protected: boolean;
  disabled: boolean;
  visible?: boolean;
}

export interface SafePageSnapshot {
  url: string;
  elements: SafePageElement[];
  truncated: boolean;
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
      grantId?: string;
      completedAt?: string;
    }
  | {
      status: "denied" | "expired" | "cancelled" | "indeterminate" | "completed_evidence_lost" | "revoked" | "failed";
      requestId: string;
      code: SecretCtlErrorCode;
      safeMessage: string;
      retryable: boolean;
      evidenceId?: string;
    };
