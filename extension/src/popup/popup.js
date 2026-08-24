/**
 * Browser-action popup.
 *
 * A status readout, nothing more. It has no controls, because every decision
 * belongs in the desktop application where the human ceremony lives, and it
 * asserts no protection it has not been told about: an unreachable service
 * worker renders as "cannot verify", never as a stale green badge (spec §26).
 */

const GLYPHS = {
  connected: { glyph: "●", tone: "var(--positive)", label: "Connected" },
  executing: { glyph: "⚡", tone: "var(--accent)", label: "Sensitive operation" },
  offline: { glyph: "✕", tone: "var(--negative)", label: "Not connected" },
  unknown: { glyph: "▲", tone: "var(--attention)", label: "Cannot verify" },
};

/** Escape-free rendering: everything below is set through textContent. */
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function field(label, value, className) {
  const wrapper = element("div");
  wrapper.appendChild(element("div", "label", label));
  wrapper.appendChild(element("div", `value ${className ?? ""}`.trim(), value));
  return wrapper;
}

function divider() {
  return element("div", "divider");
}

function setConnection(kind) {
  const entry = GLYPHS[kind];
  const glyph = document.getElementById("connectionGlyph");
  glyph.textContent = entry.glyph;
  glyph.style.color = entry.tone;
  document.getElementById("connectionLabel").textContent = entry.label;
}

function render(status) {
  const body = document.getElementById("body");
  body.replaceChildren();

  if (!status) {
    setConnection("unknown");
    const note = element(
      "div",
      "note",
      "secretctl could not report its state. Credential operations will not run until it can.",
    );
    body.appendChild(note);
    return;
  }

  if (status.pairingError) {
    setConnection("offline");
    body.appendChild(field("Enrollment", status.pairingError, "muted"));
    body.appendChild(element("div", "note", "Hardened execution is disabled until extension pairing succeeds."));
    return;
  }

  if (status.pairingCode) {
    setConnection("unknown");
    body.appendChild(field("Pairing code", status.pairingCode, "site"));
    body.appendChild(element("div", "note", "Confirm that this code matches the one printed by secretctl browser install."));
    return;
  }

  if (status.executing) {
    setConnection("executing");
    body.appendChild(
      field("Site", displayOrigin(status.executingOrigin ?? status.origin), "site"),
    );
    body.appendChild(divider());
    body.appendChild(
      element("div", "note", "A credential operation is in progress. Review it in the secretctl app."),
    );
    return;
  }

  setConnection(status.connected ? "connected" : "offline");

  body.appendChild(field("Current tab", displayOrigin(status.origin), "site"));
  body.appendChild(divider());

  const protection = element("div");
  protection.appendChild(element("div", "label", "Browser protection"));
  const list = element("ul");
  // Three distinct answers, because "not enforced here" and "cannot verify"
  // are different facts and collapsing them would mislead.
  if (!status.connected) {
    list.appendChild(line("✕", "Not enforced — secretctl is not connected", "var(--negative)"));
  } else if (!status.enforceable) {
    list.appendChild(line("·", "This page is outside secretctl's scope", "var(--text-tertiary)"));
  } else {
    list.appendChild(line("✓", "Page measured and enforced", "var(--positive)"));
    list.appendChild(line("✓", "Credential isolated from page code", "var(--positive)"));
  }
  protection.appendChild(list);
  body.appendChild(protection);

  body.appendChild(divider());
  body.appendChild(field("Sensitive operation", "None", "muted"));
}

function line(glyph, text, tone) {
  const item = element("li");
  const mark = element("span", null, `${glyph} `);
  mark.style.color = tone;
  mark.setAttribute("aria-hidden", "true");
  item.appendChild(mark);
  item.appendChild(document.createTextNode(text));
  return item;
}

function displayOrigin(origin) {
  if (!origin) return "Not a web page";
  return origin.replace(/^https?:\/\//, "").replace(/:443$/, "");
}

// A worker that does not answer is reported as unverifiable rather than
// leaving the previous state on screen.
const timeout = setTimeout(() => render(null), 1500);
chrome.runtime.sendMessage({ type: "SECRETCTL_POPUP_STATUS" }, (status) => {
  clearTimeout(timeout);
  render(chrome.runtime.lastError ? null : status);
});
