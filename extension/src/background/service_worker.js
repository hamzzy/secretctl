/** Trusted MV3 coordinator. Page code never receives capabilities or values. */
const NATIVE_HOST_NAME = "com.secretctl.native_host";

let nativePort = null;
let browserSessionId = null;
let sessionMaterial = null;
let pollTimer = null;
const tabEpochs = new Map();
const pendingRequests = new Map();
/** Set only while a capability is actually being consumed. The popup reports
 *  protection state from observed values like this one, never from an
 *  assumption that things are fine. */
let executionInFlight = null;

function b64urlBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function canonicalOrigin(value) {
  const url = new URL(value);
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  return `${url.protocol}//${url.hostname.toLowerCase()}:${port}`;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sendNativeRequest(method, params, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    if (!nativePort) return reject(new Error("native host unavailable"));
    const id = "rpc_" + crypto.randomUUID();
    pendingRequests.set(id, { resolve, reject });
    nativePort.postMessage({ jsonrpc: "2.0", id, method, params });
    setTimeout(() => {
      if (pendingRequests.delete(id)) reject(new Error("native request timeout"));
    }, timeoutMs);
  });
}

async function connectNative() {
  if (nativePort) return;
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    nativePort = port;
    port.onMessage.addListener((message) => {
      const pending = pendingRequests.get(message.id);
      if (!pending) return;
      pendingRequests.delete(message.id);
      message.error ? pending.reject(new Error(message.error.message || "broker rejected request"))
        : pending.resolve(message.result);
    });
    port.onDisconnect.addListener(() => {
      nativePort = null;
      browserSessionId = null;
      sessionMaterial = null;
      for (const pending of pendingRequests.values()) pending.reject(new Error("native host disconnected"));
      pendingRequests.clear();
      clearTimeout(pollTimer);
      setTimeout(connectNative, 2000);
    });

    const manifest = chrome.runtime.getManifest();
    const registration = await sendNativeRequest("browser.register", {
      // The native host replaces launch-controlled values from Chrome's
      // inherited environment; extension-provided placeholders are untrusted.
      instance_id: "bi_untrusted",
      launcher_nonce: "untrusted",
      profile_id: "untrusted",
      extension_id: chrome.runtime.id,
      extension_version: manifest.version,
      extension_key_id: chrome.runtime.id,
      browser_version: navigator.userAgent
    });
    browserSessionId = registration.browser_session_id;
    sessionMaterial = await crypto.subtle.importKey(
      "raw", b64urlBytes(registration.session_material), { name: "AES-GCM" }, false, ["decrypt"]
    );
    await reportPageContexts();
    schedulePoll(0);
  } catch (_) {
    nativePort = null;
    setTimeout(connectNative, 2000);
  }
}

chrome.webNavigation.onCommitted.addListener((details) => {
  tabEpochs.set(details.tabId, (tabEpochs.get(details.tabId) || 0) + 1);
  if (details.frameId === 0) setTimeout(reportPageContexts, 100);
});
chrome.tabs.onRemoved.addListener((tabId) => tabEpochs.delete(tabId));

async function measureContext(tabId, frameId = 0) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab.url || !/^https?:/.test(tab.url)) throw new Error("unsupported page scheme");
  const measured = await chrome.tabs.sendMessage(tabId, { type: "SECRETCTL_MEASURE" }, { frameId });
  const top = new URL(tab.url);
  return {
    browser_session_id: browserSessionId,
    tab_id: tabId,
    frame_id: frameId,
    document_id: measured.document_id,
    navigation_epoch: tabEpochs.get(tabId) || 1,
    top_origin: canonicalOrigin(top.href),
    frame_origin: canonicalOrigin(measured.href),
    path: new URL(measured.href).pathname,
    path_sha256: await sha256Hex(new URL(measured.href).pathname),
    tls: new URL(measured.href).protocol === "https:",
    incognito: Boolean(tab.incognito)
  };
}

async function reportPageContexts() {
  if (!browserSessionId || !nativePort) return;
  const tabs = await chrome.tabs.query({ active: true });
  for (const tab of tabs) {
    if (!tab.id || !tab.url || !/^https?:/.test(tab.url)) continue;
    try {
      await sendNativeRequest("executor.prepare", { context: await measureContext(tab.id) });
    } catch (_) { /* inaccessible pages are intentionally unavailable */ }
  }
}

setInterval(async () => {
  if (!browserSessionId || !nativePort) return;
  try {
    const tabs = await chrome.tabs.query({});
    await sendNativeRequest("executor.heartbeat", {
      browser_session_id: browserSessionId,
      active_tab_count: tabs.length,
      timestamp: new Date().toISOString()
    });
  } catch (_) { /* disconnect handler owns reconnection */ }
}, 5000);

// Authorization accepts only a very recent browser-measured context. Refresh
// independently of the five-second liveness heartbeat so a request cannot race
// against an otherwise healthy but older measurement.
setInterval(async () => {
  if (!browserSessionId || !nativePort) return;
  try {
    await reportPageContexts();
  } catch (_) { /* disconnect handler owns reconnection */ }
}, 1000);

function schedulePoll(delay = 250) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(pollExecution, delay);
}

async function decryptEnvelope(result) {
  if (!sessionMaterial || !result.secret_envelope) throw new Error("secret envelope unavailable");
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: b64urlBytes(result.secret_envelope.nonce),
      additionalData: new TextEncoder().encode(result.execution_id)
    },
    sessionMaterial,
    b64urlBytes(result.secret_envelope.ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function executeOffer(offer) {
  executionInFlight = { tabId: offer.tab_id, origin: offer.top_origin, startedAt: Date.now() };
  try {
    return await runOffer(offer);
  } finally {
    executionInFlight = null;
  }
}

async function runOffer(offer) {
  if (offer.oauth) return runOAuthOffer(offer);
  const context = await measureContext(offer.tab_id, offer.frame_id);
  if (context.document_id !== offer.document_id ||
      context.navigation_epoch !== offer.navigation_epoch ||
      context.top_origin !== offer.top_origin ||
      context.frame_origin !== offer.frame_origin) {
    throw new Error("execution context changed");
  }
  // DOM verification is deliberately completed before executor.consume can
  // trigger a provider retrieval.
  const preflight = await chrome.tabs.sendMessage(
    offer.tab_id,
    {
      type: "SECRETCTL_PREFLIGHT",
      fields: offer.fields,
      expectedOrigin: offer.frame_origin,
      expectedDocumentId: offer.document_id
    },
    { frameId: offer.frame_id }
  );
  if (!preflight || preflight.error || !preflight.preflight_nonce) {
    throw new Error("page preflight rejected");
  }
  const consumed = await sendNativeRequest("executor.consume", {
    capability_token: offer.capability_token,
    session_signature: "authenticated-native-session",
    current_context: await measureContext(offer.tab_id, offer.frame_id)
  });
  const envelope = await decryptEnvelope(consumed);
  const executionResult = await chrome.tabs.sendMessage(
    offer.tab_id,
    {
      type: "SECRETCTL_COMMIT",
      preflightNonce: preflight.preflight_nonce,
      fields: envelope.fields,
      submitSelector: offer.auto_submit_selector,
      success: offer.success,
      executionId: consumed.execution_id,
      expectedOrigin: offer.frame_origin
    },
    { frameId: offer.frame_id }
  );
  await sendNativeRequest("executor.result", executionResult);
}

async function runOAuthOffer(offer) {
  const plan = offer.oauth;
  const issuerOrigin = canonicalOrigin(plan.issuer_origin);
  const redirect = new URL(plan.redirect_uri);
  const redirectOrigin = canonicalOrigin(redirect.href);
  const callbackUri = await new Promise(async (resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error("OAUTH_CALLBACK_TIMEOUT")), 120000);
    function finish(error, value) {
      clearTimeout(timeout);
      chrome.webNavigation.onCommitted.removeListener(onCommitted);
      error ? reject(error) : resolve(value);
    }
    function onCommitted(details) {
      if (details.tabId !== offer.tab_id || details.frameId !== 0) return;
      try {
        const observed = new URL(details.url);
        const observedOrigin = canonicalOrigin(observed.href);
        if (observedOrigin === redirectOrigin && observed.pathname === redirect.pathname) {
          finish(null, details.url);
        } else if (observedOrigin !== issuerOrigin) {
          finish(new Error("OAUTH_REDIRECT_MISMATCH"));
        }
      } catch (_) {
        finish(new Error("OAUTH_REDIRECT_MISMATCH"));
      }
    }
    chrome.webNavigation.onCommitted.addListener(onCommitted);
    try {
      await chrome.tabs.update(offer.tab_id, { url: plan.authorization_url });
    } catch (_) {
      finish(new Error("OAUTH_NAVIGATION_FAILED"));
    }
  });
  await sendNativeRequest("oauth.callback", {
    capability_token: offer.capability_token,
    browser_session_id: browserSessionId,
    tab_id: offer.tab_id,
    callback_uri: callbackUri
  }, 30000);
}

async function pollExecution() {
  if (!browserSessionId || !nativePort) return schedulePoll(1000);
  try {
    const next = await sendNativeRequest("execution.next", { browser_session_id: browserSessionId });
    if (next.offer) await executeOffer(next.offer);
  } catch (_) { /* failure is safe; a consumed envelope is never requested again */ }
  schedulePoll(250);
}

/**
 * Status for the browser-action popup.
 *
 * Every field is read from live worker state. There is deliberately no default
 * that reports health: if the native host is gone, `connected` is false and the
 * popup says protection cannot be verified rather than staying green.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "SECRETCTL_POPUP_STATUS") return false;
  chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
    const tab = tabs[0];
    let origin = null;
    if (tab?.url && /^https?:/.test(tab.url)) {
      try {
        origin = canonicalOrigin(tab.url);
      } catch (_) {
        origin = null;
      }
    }
    sendResponse({
      connected: Boolean(nativePort) && Boolean(browserSessionId),
      // Enforcement only covers pages the content script can measure.
      enforceable: origin !== null,
      origin,
      navigationEpoch: tab?.id ? tabEpochs.get(tab.id) || null : null,
      executing: Boolean(executionInFlight),
      executingOrigin: executionInFlight?.origin ?? null
    });
  });
  return true; // response is asynchronous
});

connectNative();
