import { useState } from "react";
import { api } from "../api";
import { useStatus } from "../hooks";

/**
 * First run.
 *
 * Positioning matters here: this is the moment the product explains what it is,
 * and it is not a password manager. The promise is that agents can use accounts
 * without ever possessing the credentials (spec §37, §38).
 */
export function Onboarding() {
  const [step, setStep] = useState(0);
  const status = useStatus();

  const providerConnected = (status?.providers.length ?? 0) > 0;
  const browserConnected = (status?.browser_sessions_connected ?? 0) > 0;

  const steps = [
    <Welcome key="welcome" onNext={() => setStep(1)} />,
    <ConnectProvider
      key="provider"
      providers={status?.providers ?? []}
      connected={providerConnected}
      onNext={() => setStep(2)}
    />,
    <ConnectBrowser key="browser" connected={browserConnected} onNext={() => setStep(3)} />,
    <Ready key="ready" />,
  ];

  return (
    <div
      className="flex h-full flex-col justify-between px-8 py-8"
      style={{ background: "var(--bg-raised)" }}
    >
      {steps[step]}
      <ol className="mt-6 flex justify-center gap-1.5" aria-label={`Step ${step + 1} of 4`}>
        {steps.map((_, index) => (
          <li
            key={index}
            className="h-1.5 w-1.5 rounded-full"
            style={{
              background: index === step ? "var(--accent)" : "var(--border-strong)",
            }}
          />
        ))}
      </ol>
    </div>
  );
}

function Welcome({ onNext }: { onNext: () => void }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center text-center">
      <h1 className="text-xl font-semibold">secretctl</h1>
      <p className="mt-2 text-lg leading-snug">
        Give agents access to your accounts
        <br />
        without giving them your passwords.
      </p>
      <ul className="mt-6 flex flex-col gap-1.5 text-left text-base">
        <Promise>Credentials stay with their provider</Promise>
        <Promise>Agents receive no secrets</Promise>
        <Promise>Browser actions are isolated</Promise>
        <Promise>Every authorization is audited</Promise>
      </ul>
      <button className="btn btn-primary mt-7" onClick={onNext} autoFocus>
        Get started
      </button>
    </div>
  );
}

function Promise({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-baseline gap-2">
      <span style={{ color: "var(--positive)" }}>✓</span>
      {children}
    </li>
  );
}

function ConnectProvider({
  providers,
  connected,
  onNext,
}: {
  providers: string[];
  connected: boolean;
  onNext: () => void;
}) {
  return (
    <Step
      title="Connect a credential provider"
      hint="secretctl never stores your secrets. It asks a provider you already trust to hold them."
      ready={connected}
      readyLabel={providers.join(", ")}
      waitingLabel="No provider configured yet"
      command="secretctl credential add <name>"
      onNext={onNext}
    />
  );
}

function ConnectBrowser({ connected, onNext }: { connected: boolean; onNext: () => void }) {
  return (
    <Step
      title="Connect your browser"
      hint="Credential operations run inside a managed browser session, where secretctl can verify the page and block extraction."
      ready={connected}
      readyLabel="Extension detected"
      waitingLabel="No managed browser session yet"
      command="secretctl browser connect"
      onNext={onNext}
    />
  );
}

function Step({
  title,
  hint,
  ready,
  readyLabel,
  waitingLabel,
  command,
  onNext,
}: {
  title: string;
  hint: string;
  ready: boolean;
  readyLabel: string;
  waitingLabel: string;
  command: string;
  onNext: () => void;
}) {
  return (
    <div className="flex flex-1 flex-col justify-center">
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="mt-1.5 text-base" style={{ color: "var(--text-secondary)" }}>
        {hint}
      </p>
      <div
        className="mt-5 rounded-lg px-3.5 py-3"
        style={{ background: "var(--bg-sunken)" }}
      >
        <div style={{ color: ready ? "var(--positive)" : "var(--text-tertiary)" }}>
          {ready ? `● ${readyLabel}` : `○ ${waitingLabel}`}
        </div>
        {!ready && (
          <code
            className="mt-2 block font-mono text-sm selectable"
            style={{ color: "var(--text-secondary)" }}
          >
            {command}
          </code>
        )}
      </div>
      <div className="mt-6 flex items-center gap-2">
        <button className="btn btn-primary" onClick={onNext} autoFocus>
          Continue
        </button>
        {!ready && (
          <span className="text-sm" style={{ color: "var(--text-tertiary)" }}>
            You can finish this later.
          </span>
        )}
      </div>
    </div>
  );
}

function Ready() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center text-center">
      <h1 className="text-xl font-semibold">secretctl is ready</h1>
      <p className="mt-2 text-base" style={{ color: "var(--text-secondary)" }}>
        It now lives in your menu bar. You will only hear from it when a decision
        is actually yours to make.
      </p>
      <button
        className="btn btn-primary mt-7"
        onClick={() => api.setOnboardingComplete()}
        autoFocus
      >
        Done
      </button>
    </div>
  );
}
