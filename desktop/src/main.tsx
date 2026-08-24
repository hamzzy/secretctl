import React from "react";
import ReactDOM from "react-dom/client";
import { Approval } from "./routes/Approval";
import { Manage } from "./routes/Manage";
import { Onboarding } from "./routes/Onboarding";
import { Popover } from "./routes/Popover";
import "./styles.css";

/**
 * Routing.
 *
 * The hash is set by the Rust side when it constructs each window, and the only
 * dynamic segment — an approval id — was validated as a broker-minted id before
 * the URL was built. Anything unrecognised falls back to the popover rather than
 * rendering from an unknown route.
 */
function route() {
  const hash = window.location.hash.replace(/^#/, "");
  const [, head, tail] = hash.split("/");

  switch (head) {
    case "approval":
      return tail ? <Approval approvalId={tail} /> : <Popover />;
    case "manage":
      return <Manage section={tail ?? "activity"} />;
    case "onboarding":
      return <Onboarding />;
    default:
      return <Popover />;
  }
}

function App() {
  const [, setTick] = React.useState(0);
  React.useEffect(() => {
    const rerender = () => setTick((value) => value + 1);
    window.addEventListener("hashchange", rerender);
    return () => window.removeEventListener("hashchange", rerender);
  }, []);
  return route();
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
