/**
 * secretctl MV3 Background Service Worker
 * Manages native messaging connection, authoritative page measurements,
 * navigation epochs, and execution dispatching.
 */

const NATIVE_HOST_NAME = "com.secretctl.native_host";

let nativePort = null;
let browserSessionId = "bs_" + crypto.randomUUID();
let tabEpochs = new Map(); // tabId -> number
let pendingRequests = new Map(); // requestId -> { resolve, reject }

function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    nativePort.onMessage.addListener((message) => {
      if (message.id && pendingRequests.has(message.id)) {
        const { resolve, reject } = pendingRequests.get(message.id);
        pendingRequests.delete(message.id);
        if (message.error) {
          reject(message.error);
        } else {
          resolve(message.result);
        }
      }
    });

    nativePort.onDisconnect.addListener(() => {
      console.warn("Disconnected from secretctl native host. Retrying in 2s...");
      nativePort = null;
      setTimeout(connectNative, 2000);
    });

    console.info("Connected to secretctl native host.");
  } catch (err) {
    console.error("Failed to connect to secretctl native host:", err);
  }
}

connectNative();

// Track navigation epochs per tab
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    const currentEpoch = (tabEpochs.get(details.tabId) || 0) + 1;
    tabEpochs.set(details.tabId, currentEpoch);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabEpochs.delete(tabId);
});

// Periodic heartbeat
setInterval(() => {
  if (!nativePort) return;
  chrome.tabs.query({ active: true }, (tabs) => {
    sendNativeRequest("executor.heartbeat", {
      browser_session_id: browserSessionId,
      active_tab_count: tabs.length,
      timestamp: new Date().toISOString()
    }).catch((err) => {
      console.warn("Heartbeat error:", err);
    });
  });
}, 5000);

function sendNativeRequest(method, params) {
  return new Promise((resolve, reject) => {
    if (!nativePort) {
      return reject(new Error("Native port is not connected"));
    }
    const id = "rpc_" + crypto.randomUUID();
    pendingRequests.set(id, { resolve, reject });

    nativePort.postMessage({
      jsonrpc: "2.0",
      id,
      method,
      params
    });

    setTimeout(() => {
      if (pendingRequests.has(id)) {
        pendingRequests.delete(id);
        reject(new Error("Request timeout"));
      }
    }, 15000);
  });
}

// Listen for execution commands from extension or content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "MEASURE_CONTEXT") {
    const tabId = sender.tab ? sender.tab.id : 0;
    const epoch = tabEpochs.get(tabId) || 1;
    const frameUrl = new URL(sender.url || sender.tab?.url || "https://unknown.invalid/");
    const topUrl = new URL(sender.tab?.url || frameUrl.href);
    const path = frameUrl.pathname;

    crypto.subtle.digest("SHA-256", new TextEncoder().encode(path)).then((digest) => {
      const pathSha256 = Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0")
      ).join("");
      sendResponse({
        browser_session_id: browserSessionId,
        tab_id: tabId,
        frame_id: sender.frameId || 0,
        document_id: sender.documentId || "doc_" + tabId + "_" + epoch,
        navigation_epoch: epoch,
        top_origin: topUrl.origin,
        frame_origin: frameUrl.origin,
        path,
        path_sha256: pathSha256,
        tls: frameUrl.protocol === "https:"
      });
    }).catch(() => sendResponse({ error: "Unable to measure page path" }));
    return true;
  }

  if (message.type === "EXECUTE_CONSUME") {
    sendNativeRequest("executor.consume", message.params)
      .then(async (res) => {
        const context = message.params.current_context;
        const executionResult = await chrome.tabs.sendMessage(
          context.tab_id,
          {
            type: "SECRETCTL_EXECUTE",
            fields: res.fields,
            submitSelector: res.auto_submit_selector,
            executionId: res.execution_id,
            expectedOrigin: typeof context.top_origin === "string"
              ? context.top_origin
              : `${context.top_origin.scheme}://${context.top_origin.host}:${context.top_origin.port}`
          },
          { frameId: context.frame_id }
        );
        await sendNativeRequest("executor.result", executionResult);
        sendResponse({
          success: true,
          result: {
            execution_id: res.execution_id,
            status: executionResult.status,
            result_code: executionResult.result_code
          }
        });
      })
      .catch((err) => sendResponse({ success: false, error: err }));
    return true;
  }

  if (message.type === "REPORT_RESULT") {
    sendNativeRequest("executor.result", message.params)
      .then((res) => sendResponse({ success: true, result: res }))
      .catch((err) => sendResponse({ success: false, error: err }));
    return true;
  }
});
