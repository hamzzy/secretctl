import type { ReactNode } from "react";

/** A labelled block in the popover or a management pane. */
export function Section({
  label,
  children,
  action,
}: {
  label: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="px-3.5 py-3">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="section-label">{label}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Divider() {
  return <div className="divider" />;
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <p className="text-sm" style={{ color: "var(--text-tertiary)" }}>
      {children}
    </p>
  );
}

/** Relative time, at the granularity a security log actually needs. */
export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 0) return "now";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/** Strip the scheme and default port so origins read as sites, without ever
 *  losing the distinction between two different hosts. */
export function displayOrigin(origin: string): string {
  return origin.replace(/^https?:\/\//, "").replace(/:443$/, "");
}
