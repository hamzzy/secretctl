import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { AgentText, VerifiedField } from "../components/AgentText";
import { Divider, displayOrigin } from "../components/Chrome";
import { RiskPill } from "../components/StateIcon";
import { useCountdown } from "../hooks";
import { useDismissOnEscape } from "../keyboard";
import type { AuthorizationRequest, CommandError } from "../types";

/**
 * The authorization ceremony.
 *
 * This is where a human grants authority, so it is built to be read rather than
 * dismissed. Broker-verified facts sit in a distinct block from the agent's own
 * words; a single flow is one decision no matter how many capabilities it
 * contains internally; and widening authority is a separate, deliberate step
 * behind its own review (spec §12–§15).
 */
export function Approval({ approvalId }: { approvalId: string }) {
  const [request, setRequest] = useState<AuthorizationRequest | null>(null);
  const [error, setError] = useState<CommandError | null>(null);
  const [busy, setBusy] = useState(false);
  const [showGrantReview, setShowGrantReview] = useState(false);
  const [gone, setGone] = useState<string | null>(null);
  const remaining = useCountdown(request?.expires_at);
  useDismissOnEscape();

  // Always re-read from the daemon on open. The notification may be seconds
  // stale, and the request may already have expired or been decided elsewhere.
  useEffect(() => {
    let live = true;
    api
      .getPendingRequest(approvalId)
      .then((value) => live && setRequest(value))
      .catch((failure: CommandError) => {
        if (live) setGone(failure.message);
      });
    return () => {
      live = false;
    };
  }, [approvalId]);

  const act = useCallback(
    async (operation: () => Promise<unknown>) => {
      setBusy(true);
      setError(null);
      try {
        await operation();
        // Close only once the daemon has confirmed. The window never reports
        // an outcome it has not been told.
        await api.closeWindow();
      } catch (failure) {
        setError(failure as CommandError);
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  if (gone) {
    return (
      <Frame>
        <div className="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center">
          <div className="text-lg font-semibold">Nothing to authorize</div>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            {gone}
          </p>
          <button className="btn" onClick={() => api.closeWindow()}>
            Close
          </button>
        </div>
      </Frame>
    );
  }

  if (!request) {
    return (
      <Frame>
        <div className="flex flex-1 items-center justify-center">
          <span className="text-sm" style={{ color: "var(--text-tertiary)" }}>
            Loading request…
          </span>
        </div>
      </Frame>
    );
  }

  if (showGrantReview) {
    return (
      <StandingAuthorizationReview
        request={request}
        busy={busy}
        error={error}
        onCancel={() => setShowGrantReview(false)}
        onCreate={(days) => act(() => api.createGrant(request, days))}
      />
    );
  }

  const expired = remaining !== null && remaining <= 0;

  return (
    <Frame>
      <header className="px-5 pb-3 pt-5">
        <div className="text-xs font-medium" style={{ color: "var(--text-tertiary)" }}>
          {request.is_first_for_agent
            ? "First agent authorization"
            : "Authorization requested"}
        </div>
        <h1 className="mt-1 text-xl font-semibold leading-tight">
          {request.agent_name} wants to {request.action_label.toLowerCase()} at{" "}
          {displayOrigin(request.origin)}
        </h1>
        {request.is_first_for_agent && (
          <p className="mt-1.5 text-sm" style={{ color: "var(--text-secondary)" }}>
            This is the first authorization request from this agent.
          </p>
        )}
      </header>

      <Divider />

      {/* Broker-verified block. Every value here was measured, resolved, or
          decided by secretctld — none of it is what the agent claimed. */}
      <section className="flex flex-col gap-3 px-5 py-4">
        <div className="flex items-center justify-between">
          <h2 className="section-label">Verified by secretctl</h2>
          <RiskPill risk={request.risk} />
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-3">
          <VerifiedField label="Agent" value={request.agent_name} />
          <VerifiedField label="Credential" value={request.credential_name} />
          <VerifiedField label="Destination" value={displayOrigin(request.origin)} mono />
          <VerifiedField label="Action" value={request.action_label} />
          <VerifiedField label="Provider" value={request.provider} />
          <VerifiedField
            label="Authentication steps"
            value={
              request.flow_steps.length > 0
                ? request.flow_steps.map((step) => step.label).join(" + ")
                : "—"
            }
          />
        </div>
      </section>

      <Divider />

      {/* Agent-controlled block, visually and verbally separated. */}
      <section className="px-5 py-4">
        {request.reason ? (
          <AgentText text={request.reason} source={request.reason_source} />
        ) : (
          <p className="text-sm" style={{ color: "var(--text-tertiary)" }}>
            The agent gave no reason.
          </p>
        )}
      </section>

      <div className="mt-auto">
        <Divider />
        <footer className="flex flex-col gap-2.5 px-5 py-4">
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            🔒 Your credentials are never shown to the agent.
            {request.requires_presence && " Authorizing requires Touch ID or your password."}
          </p>

          {error && <ErrorNote error={error} />}

          {expired ? (
            <p className="text-sm" style={{ color: "var(--negative)" }}>
              This request expired without being authorized.
            </p>
          ) : (
            remaining !== null && (
              <p className="text-xs tabular-nums" style={{ color: "var(--text-tertiary)" }}>
                Expires in {remaining}s
              </p>
            )
          )}

          <div className="flex items-center gap-2">
            {/* Deny takes initial focus. Nothing that grants authority is ever
                one keystroke from a window that opened by itself; the safe
                action is the default one. */}
            <button
              className="btn btn-danger flex-1"
              disabled={busy}
              onClick={() => act(() => api.deny(request))}
              autoFocus
            >
              Deny
            </button>
            {/* One flow is one decision, even when it consumes a password and a
                TOTP capability underneath (spec §14). */}
            <button
              className="btn btn-primary flex-1"
              disabled={busy || expired}
              onClick={() => act(() => api.approveOnce(request))}
            >
              Authorize once
            </button>
          </div>

          {request.grantable && !expired && (
            <button
              className="link self-center"
              disabled={busy}
              onClick={() => setShowGrantReview(true)}
            >
              Create standing authorization…
            </button>
          )}
        </footer>
      </div>
    </Frame>
  );
}

/**
 * Full-scope review before a standing authorization is created.
 *
 * The phrase "always allow" is avoided deliberately: it describes a feeling,
 * not a scope. Everything the grant will actually cover is enumerated, along
 * with the conditions that still apply on every future use (spec §15).
 */
function StandingAuthorizationReview({
  request,
  busy,
  error,
  onCancel,
  onCreate,
}: {
  request: AuthorizationRequest;
  busy: boolean;
  error: CommandError | null;
  onCancel: () => void;
  onCreate: (ttlDays: number) => void;
}) {
  const [ttlDays, setTtlDays] = useState(30);

  return (
    <Frame>
      <header className="px-5 pb-3 pt-5">
        <h1 className="text-xl font-semibold">Create standing authorization</h1>
        <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
          This replaces the approval prompt for exactly this combination, and
          nothing else.
        </p>
      </header>

      <Divider />

      <section className="grid grid-cols-2 gap-x-4 gap-y-3 px-5 py-4">
        <VerifiedField label="Agent" value={request.agent_name} />
        <VerifiedField label="Credential" value={request.credential_name} />
        <VerifiedField label="Destination" value={request.origin} mono />
        <VerifiedField label="Action" value={request.action_label} />
        <VerifiedField
          label="Authentication flow"
          value={request.flow_steps.map((step) => step.label).join(" + ") || "—"}
        />
        <VerifiedField label="Risk limit" value={`${request.risk} and below`} />
      </section>

      <Divider />

      <section className="px-5 py-4">
        <label className="section-label" htmlFor="ttl">
          Expiration
        </label>
        <select
          id="ttl"
          className="btn mt-1.5 w-full"
          value={ttlDays}
          onChange={(event) => setTtlDays(Number(event.target.value))}
        >
          <option value={7}>7 days</option>
          <option value={30}>30 days</option>
          <option value={90}>90 days (maximum)</option>
        </select>
      </section>

      <Divider />

      <section className="px-5 py-4">
        <div className="section-label">Conditions that still apply</div>
        <ul className="mt-1.5 flex flex-col gap-1 text-sm" style={{ color: "var(--text-secondary)" }}>
          <li>• Exact origin required — no subdomain or path widening</li>
          <li>• Managed browser session required</li>
          <li>• Higher-risk operations still require your approval</li>
          <li>• Every use is recorded in the audit trail</li>
          <li>• Revocable at any time</li>
        </ul>
      </section>

      <div className="mt-auto">
        <Divider />
        <footer className="flex flex-col gap-2.5 px-5 py-4">
          <p className="text-xs" style={{ color: "var(--attention)" }}>
            ▲ Creating this authorization requires Touch ID or your password.
          </p>
          {error && <ErrorNote error={error} />}
          <div className="flex items-center gap-2">
            <button className="btn flex-1" disabled={busy} onClick={onCancel} autoFocus>
              Cancel
            </button>
            <button
              className="btn btn-primary flex-1"
              disabled={busy}
              onClick={() => onCreate(ttlDays)}
            >
              Create authorization
            </button>
          </div>
        </footer>
      </div>
    </Frame>
  );
}

/**
 * Plain-language failure, with the machine code available but not prominent.
 * A user who is told `EPOCH_INVALIDATED (-32006)` has been informed of nothing
 * (spec §19).
 */
export function ErrorNote({ error }: { error: CommandError }) {
  const [showDetail, setShowDetail] = useState(false);
  return (
    <div className="rounded-md px-2.5 py-2" style={{ background: "var(--bg-sunken)" }}>
      <p className="text-sm" style={{ color: "var(--negative)" }}>
        {error.disconnected
          ? "secretctl could not be reached, so nothing was authorized."
          : error.message}
      </p>
      {error.code !== null && (
        <>
          <button className="link mt-1 text-xs" onClick={() => setShowDetail((v) => !v)}>
            {showDetail ? "Hide technical details" : "View technical details"}
          </button>
          {showDetail && (
            <code
              className="mt-1 block font-mono text-xs selectable"
              style={{ color: "var(--text-tertiary)" }}
            >
              broker error {error.code}
            </code>
          )}
        </>
      )}
    </div>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full flex-col overflow-y-auto" style={{ background: "var(--bg-raised)" }}>
      {children}
    </div>
  );
}
