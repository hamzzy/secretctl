import { useEffect, useState } from "react";
import { api, onPending, onStatus } from "./api";
import type { AuthorizationRequest, Status } from "./types";

/**
 * Daemon status.
 *
 * Seeded with one direct read so a freshly opened window is not blank, then
 * driven entirely by pushes from the watcher. The UI holds no fallback: if the
 * daemon stops reporting, the state becomes `disconnected` rather than the last
 * value that happened to be good (spec §28).
 */
export function useStatus(): Status | null {
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    let live = true;
    api
      .getStatus()
      .then((value) => live && setStatus(value))
      .catch(() => live && setStatus(null));
    const subscription = onStatus((value) => live && setStatus(value));
    return () => {
      live = false;
      subscription.then((unlisten) => unlisten());
    };
  }, []);

  return status;
}

export function usePending(): AuthorizationRequest[] {
  const [pending, setPending] = useState<AuthorizationRequest[]>([]);

  useEffect(() => {
    let live = true;
    api
      .getPendingRequests()
      .then((value) => live && setPending(value))
      .catch(() => live && setPending([]));
    const subscription = onPending((value) => live && setPending(value));
    return () => {
      live = false;
      subscription.then((unlisten) => unlisten());
    };
  }, []);

  return pending;
}

/** Re-read a value on an interval and whenever `deps` change. */
export function usePolled<T>(
  load: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
): { value: T | null; error: string | null; reload: () => void } {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    const run = () =>
      load()
        .then((next) => {
          if (!live) return;
          setValue(next);
          setError(null);
        })
        .catch((failure) => {
          if (!live) return;
          setError(failure?.message ?? String(failure));
        });
    run();
    const timer = window.setInterval(run, intervalMs);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, nonce, ...deps]);

  return { value, error, reload: () => setNonce((n) => n + 1) };
}

/** Seconds remaining before a pending approval expires, ticking locally. */
export function useCountdown(expiresAt: string | undefined): number | null {
  const [remaining, setRemaining] = useState<number | null>(null);

  useEffect(() => {
    if (!expiresAt) {
      setRemaining(null);
      return;
    }
    const tick = () => {
      const seconds = Math.round(
        (new Date(expiresAt).getTime() - Date.now()) / 1000,
      );
      setRemaining(Math.max(0, seconds));
    };
    tick();
    const timer = window.setInterval(tick, 500);
    return () => window.clearInterval(timer);
  }, [expiresAt]);

  return remaining;
}
