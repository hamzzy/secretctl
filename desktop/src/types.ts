// Mirrors `secretctl-protocol::admin`. Every type here is a projection the
// daemon produced; none of them can carry credential material, and the frontend
// has no other data source.

export type ActionKind =
  | "authenticate.password"
  | "authenticate.totp"
  | "form.sensitive_fill"
  | "oauth.authorize";

export type RiskLevel = "Low" | "Medium" | "High" | "Critical";

export type ProtectionState =
  | "protected"
  | "approval_required"
  | "sensitive_operation"
  | "completed"
  | "blocked"
  | "protection_interrupted"
  | "outcome_uncertain"
  | "disconnected";

/** The only value this ever takes today; it exists so the tag is explicit at
 *  every use site rather than implied by a field name. */
export type ReasonSource = "agent_provided";

export interface FlowStep {
  role: string;
  label: string;
  optional: boolean;
}

export interface AuthorizationRequest {
  approval_id: string;
  request_id: string;
  agent_name: string;
  agent_id: string;
  credential_name: string;
  provider: string;
  origin: string;
  action: ActionKind;
  action_label: string;
  flow_steps: FlowStep[];
  risk: RiskLevel;
  /** Agent-controlled text. Never rendered as anything but attributed plain
   *  text — see `AgentText` in components/AgentText.tsx. */
  reason: string | null;
  reason_source: ReasonSource;
  context_digest: string;
  expires_at: string;
  requires_presence: boolean;
  is_first_for_agent: boolean;
  grantable: boolean;
}

export type StepState = "pending" | "active" | "done" | "failed";

export interface OperationStep {
  label: string;
  state: StepState;
}

export interface ActiveOperation {
  request_id: string;
  agent_name: string;
  credential_name: string;
  origin: string;
  action_label: string;
  steps: OperationStep[];
  /** Only protections the executor actually confirmed. An empty list means the
   *  broker could not verify any, and the UI must not imply otherwise. */
  confirmed_protections: string[];
  protection_verified: boolean;
}

export interface Status {
  protection: ProtectionState;
  pending_approvals: number;
  active_operation: ActiveOperation | null;
  browser_sessions_connected: number;
  agents_enrolled: number;
  agents_active: number;
  active_grants: number;
  providers: string[];
  policy_fingerprint: string;
  audit_chain_intact: boolean;
}

export interface Grant {
  grant_id: string;
  agent_name: string;
  credential_name: string;
  origin: string;
  action: ActionKind;
  action_label: string;
  risk_ceiling: RiskLevel;
  require_presence: boolean;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoked_reason: string | null;
  last_used_at: string | null;
  use_count: number;
  active: boolean;
}

export interface Agent {
  agent_id: string;
  display_name: string;
  role: string;
  state: string;
  created_at: string;
  active_grants: number;
  recent_event_count: number;
  last_activity_at: string | null;
}

export interface Credential {
  name: string;
  kind: string;
  provider: string;
  allowed_actions: ActionKind[];
  approved_origins: string[];
  used_by: string[];
  last_used_at: string | null;
  disabled: boolean;
}

export interface BrowserSession {
  session_id: string;
  profile: string;
  state: string;
  assurance: string;
  last_heartbeat_at: string;
  active_tab_count: number;
  current_origins: string[];
}

export type EventOutcome =
  | "success"
  | "denied"
  | "pending"
  | "interrupted"
  | "info";

export interface ActivityEvent {
  sequence: number;
  event_id: string;
  event_type: string;
  summary: string;
  outcome: EventOutcome;
  actor_type: string;
  actor_name: string | null;
  origin: string | null;
  action: ActionKind | null;
  risk: RiskLevel | null;
  error_code: string | null;
  created_at: string;
}

export interface Diagnostics {
  installation_dir: string;
  broker_key_pinned: boolean;
  admin_socket_present: boolean;
  agent_socket_present: boolean;
  executor_socket_present: boolean;
  daemon_reachable: boolean;
  restart_command: string;
}

export type NotificationDetail = "minimal" | "detailed" | "disabled";

export interface Settings {
  notification_detail: NotificationDetail;
  confirm_completion: boolean;
}

export interface CommandError {
  message: string;
  /** Present only when the broker itself refused. Kept out of primary UI. */
  code: number | null;
  disconnected: boolean;
}
