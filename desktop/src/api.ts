// The frontend's entire capability surface.
//
// Everything below is a Tauri command that forwards to `secretctld`. There is
// no fetch, no websocket, and no storage of security state: pressing a button
// here sends an intent, and the next status push from the daemon says what
// actually happened. The UI never advances its own state optimistically,
// because a UI that shows "authorized" before the broker agreed would be
// asserting something it cannot know (spec §30).

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  ActivityEvent,
  Agent,
  AuthorizationRequest,
  BrowserSession,
  CommandError,
  Credential,
  Diagnostics,
  Grant,
  Settings,
  Status,
} from "./types";

function asCommandError(error: unknown): CommandError {
  if (error && typeof error === "object" && "message" in error) {
    return error as CommandError;
  }
  return { message: String(error), code: null, disconnected: false };
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw asCommandError(error);
  }
}

export const api = {
  getStatus: () => call<Status>("get_status"),
  getPendingRequests: () => call<AuthorizationRequest[]>("get_pending_requests"),
  getPendingRequest: (approvalId: string) =>
    call<AuthorizationRequest>("get_pending_request", { approvalId }),
  getActivity: (limit = 50) => call<ActivityEvent[]>("get_activity", { limit }),
  getAgents: () => call<Agent[]>("get_agents"),
  getCredentials: () => call<Credential[]>("get_credentials"),
  getBrowserSessions: () => call<BrowserSession[]>("get_browser_sessions"),
  getGrants: (includeRevoked = false) =>
    call<Grant[]>("get_grants", { includeRevoked }),
  getDiagnostics: () => call<Diagnostics>("get_diagnostics"),
  getSettings: () => call<Settings>("get_settings"),
  setSettings: (settings: Settings) => call<void>("set_settings", { settings }),

  /** Approve exactly one flow. `contextDigest` is echoed back unchanged from
   *  the request that was displayed, binding the decision to what was shown. */
  approveOnce: (request: AuthorizationRequest) =>
    call<unknown>("approve_once", {
      approvalId: request.approval_id,
      contextDigest: request.context_digest,
      requiresPresence: request.requires_presence,
    }),

  deny: (request: AuthorizationRequest) =>
    call<unknown>("deny", {
      approvalId: request.approval_id,
      contextDigest: request.context_digest,
    }),

  createGrant: (request: AuthorizationRequest, ttlDays: number) =>
    call<unknown>("create_grant", {
      approvalId: request.approval_id,
      contextDigest: request.context_digest,
      ttlDays,
    }),

  revokeGrant: (selector: string) => call<unknown>("revoke_grant", { selector }),
  disableAgent: (agentId: string) => call<unknown>("disable_agent", { agentId }),

  openApproval: (approvalId: string) => call<void>("open_approval", { approvalId }),
  openManage: (section: string) => call<void>("open_manage", { section }),
  closeWindow: () => call<void>("close_window"),

  getOnboardingComplete: () => call<boolean>("get_onboarding_complete"),
  setOnboardingComplete: () => call<void>("set_onboarding_complete"),
};

/** Status pushes from the daemon watcher. */
export function onStatus(handler: (status: Status) => void): Promise<UnlistenFn> {
  return listen<Status>("secretctl://status", (event) => handler(event.payload));
}

/** Pending-request pushes from the daemon watcher. */
export function onPending(
  handler: (pending: AuthorizationRequest[]) => void,
): Promise<UnlistenFn> {
  return listen<AuthorizationRequest[]>("secretctl://pending", (event) =>
    handler(event.payload),
  );
}
