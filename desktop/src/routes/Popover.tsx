import { api } from "../api";
import { Divider, Empty, Section, displayOrigin, formatDate, relativeTime } from "../components/Chrome";
import { OutcomeIcon, ProtectionIndicator, StepIcon } from "../components/StateIcon";
import { usePending, usePolled, useStatus } from "../hooks";
import type { ActiveOperation, ActivityEvent, Grant, Status } from "../types";

/**
 * The menu-bar popover.
 *
 * Compact by design: it answers "is anything happening, and what happened
 * recently", and hands everything else to a management window. It is not a
 * dashboard and must not grow into one (spec §6).
 */
export function Popover() {
  const status = useStatus();
  const pending = usePending();
  const { value: activity } = usePolled(() => api.getActivity(6), 4000);
  const { value: grants } = usePolled(() => api.getGrants(), 10000);

  if (!status) {
    return (
      <Shell>
        <div className="px-3.5 py-6">
          <Empty>Connecting to secretctl…</Empty>
        </div>
      </Shell>
    );
  }

  if (status.protection === "disconnected") {
    return (
      <Shell>
        <Disconnected />
      </Shell>
    );
  }

  return (
    <Shell>
      <Header status={status} />
      <Divider />

      <Section label="Current">
        {status.active_operation ? (
          <SensitiveOperation operation={status.active_operation} />
        ) : pending.length > 0 ? (
          <PendingSummary
            count={pending.length}
            onReview={() => api.openApproval(pending[0].approval_id)}
          />
        ) : (
          <Empty>No sensitive operation</Empty>
        )}
      </Section>

      <Divider />

      <Section
        label="Recent"
        action={
          <button className="link" onClick={() => api.openManage("activity")}>
            All
          </button>
        }
      >
        {activity && activity.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {activity.slice(0, 4).map((event) => (
              <ActivityRow key={event.event_id} event={event} />
            ))}
          </ul>
        ) : (
          <Empty>No recent activity</Empty>
        )}
      </Section>

      <Divider />

      <Section
        label="Standing authorizations"
        action={
          <button className="link" onClick={() => api.openManage("grants")}>
            Manage
          </button>
        }
      >
        {grants && grants.length > 0 ? (
          <ul className="flex flex-col gap-2">
            {grants.slice(0, 2).map((grant) => (
              <GrantRow key={grant.grant_id} grant={grant} />
            ))}
          </ul>
        ) : (
          <Empty>None</Empty>
        )}
      </Section>

      <div className="mt-auto">
        <Divider />
        <nav className="flex items-center justify-between px-3.5 py-2">
          <button className="link" onClick={() => api.openManage("activity")}>
            Activity
          </button>
          <button className="link" onClick={() => api.openManage("settings")}>
            Settings
          </button>
        </nav>
      </div>
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="flex h-full flex-col overflow-y-auto rounded-xl"
      style={{ background: "var(--bg-raised)", boxShadow: "var(--shadow)" }}
    >
      {children}
    </div>
  );
}

function Header({ status }: { status: Status }) {
  return (
    <header className="px-3.5 pb-2.5 pt-3">
      <div className="flex items-baseline justify-between">
        <span className="text-lg font-semibold">secretctl</span>
        <ProtectionIndicator state={status.protection} showLabel={false} />
      </div>
      <div className="mt-0.5 text-sm" style={{ color: "var(--text-secondary)" }}>
        <ProtectionIndicator state={status.protection} showLabel />
      </div>
      <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-0.5 text-xs" style={{ color: "var(--text-tertiary)" }}>
        <Fact label="Browser">
          {status.browser_sessions_connected > 0
            ? `${status.browser_sessions_connected} connected`
            : "Not connected"}
        </Fact>
        <Fact label="Agents">
          {status.agents_active > 0
            ? `${status.agents_active} active`
            : `${status.agents_enrolled} enrolled`}
        </Fact>
        <Fact label="Providers">
          {status.providers.length > 0 ? status.providers.join(", ") : "None"}
        </Fact>
      </dl>
      {!status.audit_chain_intact && (
        <p className="mt-2 text-xs" style={{ color: "var(--critical)" }}>
          ▲ The audit chain could not be verified. Open diagnostics.
        </p>
      )}
    </header>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <span>
      <span className="font-medium">{label}</span> · {children}
    </span>
  );
}

function PendingSummary({ count, onReview }: { count: number; onReview: () => void }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <p className="text-base">
        {count === 1
          ? "An agent is waiting for authorization."
          : `${count} agents are waiting for authorization.`}
      </p>
      <button className="btn btn-primary shrink-0" onClick={onReview}>
        Review
      </button>
    </div>
  );
}

/**
 * The in-flight operation.
 *
 * `confirmed_protections` comes from the broker and is rendered verbatim. When
 * the list is empty the panel says protection is unverified rather than
 * omitting the section, because silence would read as reassurance (spec §16).
 */
function SensitiveOperation({ operation }: { operation: ActiveOperation }) {
  return (
    <div className="flex flex-col gap-2.5">
      <p className="text-base">
        <span className="font-medium">{operation.agent_name}</span> is signing in to{" "}
        <span className="font-medium">{displayOrigin(operation.origin)}</span>
      </p>
      <div className="text-sm" style={{ color: "var(--text-secondary)" }}>
        Credential · {operation.credential_name}
      </div>

      {operation.steps.length > 0 && (
        <ul className="flex flex-col gap-1">
          {operation.steps.map((step, index) => (
            <li key={`${step.label}-${index}`} className="flex items-center gap-2 text-sm">
              <StepIcon state={step.state} />
              <span>{step.label}</span>
            </li>
          ))}
        </ul>
      )}

      <div>
        <div className="section-label">Browser protection</div>
        {operation.protection_verified ? (
          <ul className="mt-1 flex flex-col gap-0.5">
            {operation.confirmed_protections.map((protection) => (
              <li key={protection} className="text-sm" style={{ color: "var(--positive)" }}>
                ✓ {protection}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-sm" style={{ color: "var(--critical)" }}>
            ▲ secretctl cannot currently verify browser protection.
          </p>
        )}
      </div>

      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        Agent credential access · <span style={{ color: "var(--positive)" }}>Not exposed</span>
      </p>
    </div>
  );
}

function ActivityRow({ event }: { event: ActivityEvent }) {
  return (
    <li className="flex items-baseline gap-2">
      <OutcomeIcon outcome={event.outcome} />
      <span className="min-w-0 flex-1 truncate text-sm">{event.summary}</span>
      <span className="text-xs tabular-nums" style={{ color: "var(--text-tertiary)" }}>
        {relativeTime(event.created_at)}
      </span>
    </li>
  );
}

function GrantRow({ grant }: { grant: Grant }) {
  return (
    <li>
      <div className="text-sm font-medium">{grant.credential_name}</div>
      <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
        {grant.agent_name} → {displayOrigin(grant.origin)}
      </div>
      <div className="text-xs" style={{ color: "var(--text-tertiary)" }}>
        Expires {formatDate(grant.expires_at)}
      </div>
    </li>
  );
}

/**
 * Fail closed, and say what that means.
 *
 * Restarting the service is not offered as a button: the frontend has no
 * process permission, and acquiring one so the UI could restart a security
 * daemon would be the wrong trade. The command is shown instead (spec §29).
 */
function Disconnected() {
  const { value: diagnostics } = usePolled(() => api.getDiagnostics(), 3000);

  return (
    <div className="flex flex-col gap-3 px-3.5 py-4">
      <div>
        <div className="text-lg font-semibold">secretctl unavailable</div>
        <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
          The security daemon is not running. Sensitive credential operations are
          disabled.
        </p>
      </div>
      <div className="rounded-md px-2.5 py-2" style={{ background: "var(--bg-sunken)" }}>
        <div className="section-label">Start the service</div>
        <code className="mt-1 block font-mono text-sm selectable">
          {diagnostics?.restart_command ?? "secretctl start"}
        </code>
      </div>
      <button className="btn self-start" onClick={() => api.openManage("diagnostics")}>
        View diagnostics
      </button>
    </div>
  );
}
