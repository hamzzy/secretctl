import { useState } from "react";
import { api } from "../api";
import { Empty, displayOrigin, formatDate, relativeTime } from "../components/Chrome";
import { OutcomeIcon, ProtectionIndicator, RiskPill } from "../components/StateIcon";
import { usePolled, useStatus } from "../hooks";
import { useDismissOnEscape } from "../keyboard";
import type {
  ActivityEvent,
  Agent,
  BrowserSession,
  Credential,
  Grant,
  NotificationDetail,
  Settings,
} from "../types";

const SECTIONS = [
  ["activity", "Activity"],
  ["agents", "Agents"],
  ["grants", "Authorizations"],
  ["credentials", "Credentials"],
  ["browsers", "Browsers"],
  ["settings", "Settings"],
  ["diagnostics", "Diagnostics"],
] as const;

type SectionId = (typeof SECTIONS)[number][0];

/** The management window: everything the popover deliberately leaves out. */
export function Manage({ section }: { section: string }) {
  const [active, setActive] = useState<SectionId>(
    (SECTIONS.find(([id]) => id === section)?.[0] ?? "activity") as SectionId,
  );
  const status = useStatus();
  useDismissOnEscape();

  return (
    <div className="flex h-full" style={{ background: "var(--bg)" }}>
      <nav
        className="flex w-44 shrink-0 flex-col gap-0.5 p-2"
        style={{ background: "var(--bg-sunken)", borderRight: "1px solid var(--border)" }}
      >
        <div className="px-2 py-2">
          {status ? (
            <ProtectionIndicator state={status.protection} />
          ) : (
            <span className="text-sm" style={{ color: "var(--text-tertiary)" }}>
              Connecting…
            </span>
          )}
        </div>
        {SECTIONS.map(([id, label]) => (
          <button
            key={id}
            onClick={() => setActive(id)}
            aria-current={active === id ? "page" : undefined}
            className="rounded-md px-2 py-1.5 text-left text-base"
            style={{
              background: active === id ? "var(--bg-raised)" : "transparent",
              color: active === id ? "var(--text)" : "var(--text-secondary)",
            }}
          >
            {label}
          </button>
        ))}
      </nav>

      <main className="flex-1 overflow-y-auto p-5">
        {active === "activity" && <ActivityPane />}
        {active === "agents" && <AgentsPane />}
        {active === "grants" && <GrantsPane />}
        {active === "credentials" && <CredentialsPane />}
        {active === "browsers" && <BrowsersPane />}
        {active === "settings" && <SettingsPane />}
        {active === "diagnostics" && <DiagnosticsPane />}
      </main>
    </div>
  );
}

function Title({ children, hint }: { children: React.ReactNode; hint?: string }) {
  return (
    <header className="mb-4">
      <h1 className="text-xl font-semibold">{children}</h1>
      {hint && (
        <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
          {hint}
        </p>
      )}
    </header>
  );
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="panel mb-2 rounded-lg px-3.5 py-3">
      {children}
    </div>
  );
}

/** Every authorization event, in order. Secrets are never logged, so there is
 *  nothing here to redact (spec §24). */
function ActivityPane() {
  const { value: events } = usePolled(() => api.getActivity(200), 3000);
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <>
      <Title hint="Every authorization decision and credential operation, newest first.">
        Activity
      </Title>
      {!events || events.length === 0 ? (
        <Empty>No activity recorded yet.</Empty>
      ) : (
        <ul>
          {events.map((event) => (
            <li key={event.event_id}>
              <Card>
                <button
                  className="flex w-full items-baseline gap-2.5 text-left"
                  onClick={() =>
                    setExpanded(expanded === event.event_id ? null : event.event_id)
                  }
                >
                  <OutcomeIcon outcome={event.outcome} />
                  <span className="flex-1 text-base">{event.summary}</span>
                  {event.risk && <RiskPill risk={event.risk} />}
                  <span
                    className="text-xs tabular-nums"
                    style={{ color: "var(--text-tertiary)" }}
                  >
                    {relativeTime(event.created_at)}
                  </span>
                </button>
                {expanded === event.event_id && <EventDetail event={event} />}
              </Card>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function EventDetail({ event }: { event: ActivityEvent }) {
  return (
    <dl
      className="mt-2.5 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1 text-sm selectable"
      style={{ color: "var(--text-secondary)" }}
    >
      <dt>Actor</dt>
      <dd>{event.actor_name ?? event.actor_type}</dd>
      {event.origin && (
        <>
          <dt>Destination</dt>
          <dd className="font-mono text-xs">{event.origin}</dd>
        </>
      )}
      {event.action && (
        <>
          <dt>Action</dt>
          <dd className="font-mono text-xs">{event.action}</dd>
        </>
      )}
      <dt>Recorded</dt>
      <dd>{new Date(event.created_at).toLocaleString()}</dd>
      <dt>Sequence</dt>
      <dd className="font-mono text-xs">#{event.sequence}</dd>
      {event.error_code && (
        <>
          <dt>Technical code</dt>
          <dd className="font-mono text-xs">{event.error_code}</dd>
        </>
      )}
    </dl>
  );
}

/** Agents are security principals, not integrations (spec §22). */
function AgentsPane() {
  const { value: agents, reload } = usePolled(() => api.getAgents(), 5000);
  const [busy, setBusy] = useState<string | null>(null);

  const disable = async (agent: Agent) => {
    setBusy(agent.agent_id);
    try {
      await api.disableAgent(agent.agent_id);
      reload();
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Title hint="Each agent is a distinct principal with its own authority.">Agents</Title>
      {!agents || agents.length === 0 ? (
        <Empty>No agents enrolled.</Empty>
      ) : (
        agents.map((agent) => (
          <Card key={agent.agent_id}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-base font-medium">{agent.display_name}</div>
                <div className="text-sm" style={{ color: "var(--text-secondary)" }}>
                  {agent.state} · {agent.active_grants} standing{" "}
                  {agent.active_grants === 1 ? "authorization" : "authorizations"} ·{" "}
                  {agent.recent_event_count} events
                </div>
                <div className="mt-1 font-mono text-xs selectable" style={{ color: "var(--text-tertiary)" }}>
                  {agent.agent_id}
                </div>
                {agent.last_activity_at && (
                  <div className="text-xs" style={{ color: "var(--text-tertiary)" }}>
                    Last activity {relativeTime(agent.last_activity_at)} ago
                  </div>
                )}
              </div>
              <button
                className="btn btn-danger shrink-0"
                disabled={busy === agent.agent_id}
                onClick={() => disable(agent)}
              >
                Disable agent
              </button>
            </div>
          </Card>
        ))
      )}
    </>
  );
}

/** The primary management surface: scope must be unmissable (spec §23). */
function GrantsPane() {
  const [includeRevoked, setIncludeRevoked] = useState(false);
  const { value: grants, reload } = usePolled(
    () => api.getGrants(includeRevoked),
    5000,
    [includeRevoked],
  );

  return (
    <>
      <Title hint="What each agent may do without asking you again.">
        Standing authorizations
      </Title>
      <label className="mb-3 flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={includeRevoked}
          onChange={(event) => setIncludeRevoked(event.target.checked)}
        />
        Show revoked
      </label>
      {!grants || grants.length === 0 ? (
        <Empty>No standing authorizations. Every request is decided individually.</Empty>
      ) : (
        grants.map((grant) => <GrantCard key={grant.grant_id} grant={grant} onChange={reload} />)
      )}
    </>
  );
}

function GrantCard({ grant, onChange }: { grant: Grant; onChange: () => void }) {
  const [busy, setBusy] = useState(false);
  const revoke = async () => {
    setBusy(true);
    try {
      await api.revokeGrant(grant.grant_id);
      onChange();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-base font-medium">{grant.credential_name}</span>
            <RiskPill risk={grant.risk_ceiling} />
            {!grant.active && (
              <span className="text-xs" style={{ color: "var(--negative)" }}>
                Revoked{grant.revoked_reason ? ` · ${grant.revoked_reason}` : ""}
              </span>
            )}
          </div>
          <dl
            className="mt-2 grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-sm selectable"
            style={{ color: "var(--text-secondary)" }}
          >
            <dt>Agent</dt>
            <dd>{grant.agent_name}</dd>
            <dt>Origin</dt>
            <dd className="font-mono text-xs">{grant.origin}</dd>
            <dt>Action</dt>
            <dd>{grant.action_label}</dd>
            <dt>Created</dt>
            <dd>{formatDate(grant.created_at)}</dd>
            <dt>Expires</dt>
            <dd>{formatDate(grant.expires_at)}</dd>
            <dt>Used</dt>
            <dd>
              {grant.use_count === 0
                ? "Never"
                : `${grant.use_count} times${
                    grant.last_used_at ? `, last ${relativeTime(grant.last_used_at)} ago` : ""
                  }`}
            </dd>
          </dl>
        </div>
        {grant.active && (
          <button className="btn btn-danger shrink-0" disabled={busy} onClick={revoke}>
            Revoke
          </button>
        )}
      </div>
    </Card>
  );
}

/**
 * Credential *references*.
 *
 * There is no reveal control, no generator, and no secret field, because this
 * process never receives a secret to show. That absence is the product
 * (spec §21).
 */
function CredentialsPane() {
  const { value: credentials } = usePolled(() => api.getCredentials(), 8000);

  return (
    <>
      <Title hint="secretctl holds references. The secrets stay with their provider.">
        Credentials
      </Title>
      {!credentials || credentials.length === 0 ? (
        <Empty>
          No credentials configured. Add one with <code className="font-mono">secretctl credential add</code>.
        </Empty>
      ) : (
        credentials.map((credential: Credential) => (
          <Card key={credential.name}>
            <div className="text-base font-medium">
              {credential.name}
              {credential.disabled && (
                <span className="ml-2 text-xs" style={{ color: "var(--negative)" }}>
                  Disabled
                </span>
              )}
            </div>
            <dl
              className="mt-2 grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-sm selectable"
              style={{ color: "var(--text-secondary)" }}
            >
              <dt>Provider</dt>
              <dd>{credential.provider}</dd>
              <dt>Kind</dt>
              <dd>{credential.kind}</dd>
              <dt>Approved destinations</dt>
              <dd>
                {credential.approved_origins.length > 0
                  ? credential.approved_origins.map(displayOrigin).join(", ")
                  : "None — each use is approved individually"}
              </dd>
              <dt>Used by</dt>
              <dd>{credential.used_by.length > 0 ? credential.used_by.join(", ") : "No agent"}</dd>
              <dt>Last used</dt>
              <dd>
                {credential.last_used_at
                  ? `${relativeTime(credential.last_used_at)} ago`
                  : "Never"}
              </dd>
            </dl>
          </Card>
        ))
      )}
    </>
  );
}

/** Ambiguity about *which* session an SDK call targets is a security-relevant
 *  fact, so it is surfaced rather than resolved silently (spec §25). */
function BrowsersPane() {
  const { value: sessions } = usePolled(() => api.getBrowserSessions(), 3000);
  const active = (sessions ?? []).filter((session) => session.state === "active");

  return (
    <>
      <Title hint="Managed browser sessions secretctl can execute in.">Browsers</Title>
      {active.length > 1 && (
        <div
          className="mb-3 rounded-md px-3 py-2 text-sm"
          style={{ background: "var(--bg-sunken)", color: "var(--attention)" }}
        >
          ▲ {active.length} sessions are active. SDK requests must name the session
          explicitly; secretctl will not choose one for the agent.
        </div>
      )}
      {!sessions || sessions.length === 0 ? (
        <Empty>No browser sessions. Install the extension and open a managed browser.</Empty>
      ) : (
        sessions.map((session: BrowserSession) => (
          <Card key={session.session_id}>
            <div className="flex items-center justify-between">
              <span className="text-base font-medium">{session.profile}</span>
              <span
                className="text-sm"
                style={{
                  color: session.state === "active" ? "var(--positive)" : "var(--text-tertiary)",
                }}
              >
                {session.state === "active" ? "● Connected" : `○ ${session.state}`}
              </span>
            </div>
            <dl
              className="mt-2 grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-sm selectable"
              style={{ color: "var(--text-secondary)" }}
            >
              <dt>Assurance</dt>
              <dd>{session.assurance}</dd>
              <dt>Open tabs</dt>
              <dd>{session.active_tab_count}</dd>
              <dt>Current sites</dt>
              <dd>
                {session.current_origins.length > 0
                  ? session.current_origins.map(displayOrigin).join(", ")
                  : "—"}
              </dd>
              <dt>Last heartbeat</dt>
              <dd>{relativeTime(session.last_heartbeat_at)} ago</dd>
            </dl>
          </Card>
        ))
      )}
    </>
  );
}

function SettingsPane() {
  const { value: settings, reload } = usePolled(() => api.getSettings(), 30000);
  if (!settings) return <Empty>Loading…</Empty>;

  const update = async (next: Settings) => {
    await api.setSettings(next);
    reload();
  };

  return (
    <>
      <Title>Settings</Title>
      <Card>
        <div className="text-base font-medium">Notification detail</div>
        <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
          Notifications can appear on a locked screen. Minimal is the default and
          names neither the agent, the credential, nor the site.
        </p>
        <div className="mt-2.5 flex flex-col gap-1.5">
          {(
            [
              ["minimal", "Minimal — say only that a decision is waiting"],
              ["detailed", "Detailed — include the agent and destination"],
              ["disabled", "Disabled — no notifications"],
            ] as [NotificationDetail, string][]
          ).map(([value, label]) => (
            <label key={value} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="notification-detail"
                checked={settings.notification_detail === value}
                onChange={() => update({ ...settings, notification_detail: value })}
              />
              {label}
            </label>
          ))}
        </div>
      </Card>
      <Card>
        <label className="flex items-center gap-2 text-base">
          <input
            type="checkbox"
            checked={settings.confirm_completion}
            onChange={(event) =>
              update({ ...settings, confirm_completion: event.target.checked })
            }
          />
          Confirm when an operation completes
        </label>
      </Card>
    </>
  );
}

function DiagnosticsPane() {
  const { value: diagnostics } = usePolled(() => api.getDiagnostics(), 2000);
  if (!diagnostics) return <Empty>Loading…</Empty>;

  const rows: [string, boolean][] = [
    ["Daemon reachable", diagnostics.daemon_reachable],
    ["Broker key pinned", diagnostics.broker_key_pinned],
    ["Admin socket", diagnostics.admin_socket_present],
    ["Agent socket", diagnostics.agent_socket_present],
    ["Executor socket", diagnostics.executor_socket_present],
  ];

  return (
    <>
      <Title hint="What the desktop app can observe about this installation.">Diagnostics</Title>
      <Card>
        <dl className="grid grid-cols-[12rem_1fr] gap-x-3 gap-y-1.5 text-sm">
          {rows.map(([label, ok]) => (
            <Check key={label} label={label} ok={ok} />
          ))}
          <dt style={{ color: "var(--text-secondary)" }}>Installation</dt>
          <dd className="font-mono text-xs selectable">{diagnostics.installation_dir}</dd>
        </dl>
      </Card>
      {!diagnostics.daemon_reachable && (
        <Card>
          <div className="text-base font-medium">Start the security daemon</div>
          <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
            The desktop app has no permission to start or stop processes. Run this
            in a terminal:
          </p>
          <code className="mt-2 block font-mono text-sm selectable">
            {diagnostics.restart_command}
          </code>
        </Card>
      )}
    </>
  );
}

function Check({ label, ok }: { label: string; ok: boolean }) {
  return (
    <>
      <dt style={{ color: "var(--text-secondary)" }}>{label}</dt>
      <dd style={{ color: ok ? "var(--positive)" : "var(--negative)" }}>
        {ok ? "✓ Present" : "✕ Missing"}
      </dd>
    </>
  );
}

