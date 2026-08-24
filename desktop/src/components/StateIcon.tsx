import type { EventOutcome, ProtectionState, RiskLevel, StepState } from "../types";

/**
 * State glyphs.
 *
 * Every state pairs a distinct shape with a distinct colour, and callers always
 * render the accompanying word. Nothing in this file is the sole carrier of
 * meaning, which is what keeps the UI readable in greyscale and under
 * high-contrast settings (spec §33).
 */

const PROTECTION: Record<ProtectionState, { glyph: string; label: string; tone: string }> = {
  protected: { glyph: "●", label: "Protected", tone: "var(--positive)" },
  approval_required: { glyph: "!", label: "Approval required", tone: "var(--attention)" },
  sensitive_operation: { glyph: "⚡", label: "Sensitive operation", tone: "var(--accent)" },
  completed: { glyph: "✓", label: "Completed", tone: "var(--positive)" },
  blocked: { glyph: "✕", label: "Blocked", tone: "var(--negative)" },
  protection_interrupted: {
    glyph: "▲",
    label: "Protection interrupted",
    tone: "var(--critical)",
  },
  outcome_uncertain: {
    glyph: "?",
    label: "Outcome could not be verified",
    tone: "var(--critical)",
  },
  disconnected: { glyph: "✕", label: "secretctl unavailable", tone: "var(--negative)" },
};

export function protectionLabel(state: ProtectionState): string {
  return PROTECTION[state].label;
}

export function ProtectionIndicator({
  state,
  showLabel = true,
}: {
  state: ProtectionState;
  showLabel?: boolean;
}) {
  const entry = PROTECTION[state];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span aria-hidden className="text-sm" style={{ color: entry.tone }}>
        {entry.glyph}
      </span>
      {showLabel && <span className="text-base">{entry.label}</span>}
      <span className="sr-only">{entry.label}</span>
    </span>
  );
}

const OUTCOME: Record<EventOutcome, { glyph: string; tone: string; label: string }> = {
  success: { glyph: "✓", tone: "var(--positive)", label: "Succeeded" },
  denied: { glyph: "✕", tone: "var(--negative)", label: "Denied" },
  pending: { glyph: "·", tone: "var(--text-tertiary)", label: "Pending" },
  interrupted: { glyph: "▲", tone: "var(--critical)", label: "Interrupted" },
  info: { glyph: "·", tone: "var(--text-tertiary)", label: "Information" },
};

export function OutcomeIcon({ outcome }: { outcome: EventOutcome }) {
  const entry = OUTCOME[outcome];
  return (
    <span
      className="inline-block w-3 text-center text-sm"
      style={{ color: entry.tone }}
      title={entry.label}
    >
      <span aria-hidden>{entry.glyph}</span>
      <span className="sr-only">{entry.label}</span>
    </span>
  );
}

const STEP: Record<StepState, { glyph: string; tone: string }> = {
  done: { glyph: "✓", tone: "var(--positive)" },
  active: { glyph: "●", tone: "var(--accent)" },
  pending: { glyph: "○", tone: "var(--text-tertiary)" },
  failed: { glyph: "✕", tone: "var(--negative)" },
};

export function StepIcon({ state }: { state: StepState }) {
  return (
    <span aria-hidden className="w-3 text-center text-sm" style={{ color: STEP[state].tone }}>
      {STEP[state].glyph}
    </span>
  );
}

const RISK_TONE: Record<RiskLevel, string> = {
  Low: "var(--text-secondary)",
  Medium: "var(--attention)",
  High: "var(--negative)",
  Critical: "var(--critical)",
};

export function RiskPill({ risk }: { risk: RiskLevel }) {
  return (
    <span
      className="rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide"
      style={{ color: RISK_TONE[risk], border: `1px solid ${RISK_TONE[risk]}` }}
    >
      {risk} risk
    </span>
  );
}
