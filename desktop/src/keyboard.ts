import { useEffect } from "react";
import { api } from "./api";

/**
 * Escape dismisses a window without deciding anything.
 *
 * Dismissal is deliberately not denial. A window can open while the user is
 * typing elsewhere, and a reflexive Escape must not be recorded as a security
 * decision — the request stays pending and the menu-bar icon keeps showing that
 * a decision is waiting. Denial requires pressing Deny.
 */
export function useDismissOnEscape() {
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        void api.closeWindow();
        return;
      }
      // Cmd+W matches the platform expectation for closing a window.
      if (event.key === "w" && event.metaKey) {
        event.preventDefault();
        void api.closeWindow();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
}
