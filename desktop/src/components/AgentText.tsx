import type { ReasonSource } from "../types";

/**
 * Renders a string the *agent* controls.
 *
 * This is a security control, not styling. An agent writes its own `reason`,
 * and without a visible boundary it could submit text that reads like
 * broker-verified chrome — "Verified by secretctl", "Destination: github.com" —
 * and borrow the authority of the panel around it. So agent text is always:
 *
 *   - attributed in words ("Agent-provided reason"),
 *   - visually demoted and quoted, never styled like a system label,
 *   - rendered as plain text via JSX interpolation, never as HTML or Markdown,
 *   - length-clamped, on top of the clamp the broker already applied.
 *
 * There is deliberately no prop to turn any of that off (spec §13, §31).
 */
export function AgentText({
  text,
  source,
  label = "Agent-provided reason",
}: {
  text: string | null;
  source: ReasonSource;
  label?: string;
}) {
  if (!text) return null;

  // Second clamp. The broker caps this at 500 characters; a UI that trusted
  // that alone would break the moment the limit changed.
  const clamped = text.length > 280 ? `${text.slice(0, 280)}…` : text;

  return (
    <div>
      <div className="section-label">{label}</div>
      <blockquote
        // `title` is omitted on purpose: a native tooltip would render the
        // untruncated agent string outside this attributed container.
        className="mt-1.5 border-l-2 pl-2.5 text-sm italic selectable"
        style={{
          borderColor: "var(--border-strong)",
          color: "var(--text-secondary)",
        }}
        data-reason-source={source}
      >
        {clamped}
      </blockquote>
    </div>
  );
}

/**
 * A broker-verified field: measured from the page, resolved from the credential
 * store, or decided by policy. Visually distinct from `AgentText` so the two can
 * never be confused at a glance.
 */
export function VerifiedField({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <div className="section-label">{label}</div>
      <div
        className={`text-base selectable ${mono ? "font-mono text-sm" : ""}`}
        style={{ color: "var(--text)" }}
      >
        {value}
      </div>
    </div>
  );
}
