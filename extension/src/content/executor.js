/** Isolated-world preflight and commit executor. */
const documentId = "doc_" + crypto.randomUUID();
const prepared = new Map();

function canonicalOrigin(value) {
  const url = new URL(value);
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  return `${url.protocol}//${url.hostname.toLowerCase()}:${port}`;
}

function verifyField(field, expectedOrigin) {
  const matches = document.querySelectorAll(field.selector);
  if (matches.length === 0 && field.optional) return null;
  if (matches.length !== 1) throw new Error("FIELD_AMBIGUOUS");
  const element = matches[0];
  if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) ||
      element.disabled || element.readOnly || !element.isConnected) {
    throw new Error("FIELD_NOT_EDITABLE");
  }
  if (field.role === "password" &&
      (!(element instanceof HTMLInputElement) || element.type.toLowerCase() !== "password")) {
    throw new Error("FIELD_TYPE_MISMATCH");
  }
  if (["totp", "totp_code"].includes(field.role)) {
    if (!(element instanceof HTMLInputElement) ||
        !["text", "tel", "number"].includes(element.type.toLowerCase())) {
      throw new Error("FIELD_TYPE_MISMATCH");
    }
    if (document.querySelectorAll('input[autocomplete="one-time-code"]').length > 1) {
      throw new Error("FIELD_AMBIGUOUS");
    }
  }
  const rect = element.getBoundingClientRect();
  const style = getComputedStyle(element);
  if (rect.width < 10 || rect.height < 10 || rect.bottom <= 0 || rect.right <= 0 ||
      rect.top >= innerHeight || rect.left >= innerWidth || style.display === "none" ||
      style.visibility === "hidden" || Number.parseFloat(style.opacity) < 0.1) {
    throw new Error("FIELD_NOT_VISIBLE");
  }
  const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
  if (hit !== element && !element.contains(hit)) throw new Error("FIELD_OVERLAID");
  const form = element.closest("form");
  if (form?.action && canonicalOrigin(form.action) !== expectedOrigin) {
    throw new Error("FORM_ACTION_MISMATCH");
  }
  return element;
}

function injectValue(element, value) {
  const prototype = element instanceof HTMLTextAreaElement
    ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");
  if (!descriptor?.set) throw new Error("FIELD_SETTER_UNAVAILABLE");
  descriptor.set.call(element, value);
  element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
}

function preflight(fields, expectedOrigin, expectedDocumentId) {
  if (expectedDocumentId !== documentId || canonicalOrigin(location.href) !== expectedOrigin) {
    throw new Error("CONTEXT_MISMATCH");
  }
  const elements = fields.map((field) => verifyField(field, expectedOrigin));
  const nonce = crypto.randomUUID();
  prepared.set(nonce, {
    fields: structuredClone(fields),
    elements,
    expectedOrigin,
    expiresAt: Date.now() + 30000
  });
  setTimeout(() => prepared.delete(nonce), 30000);
  return { preflight_nonce: nonce, fields_verified_count: elements.filter(Boolean).length };
}

async function waitForSuccess(success) {
  if (!success) return false;
  const deadline = Date.now() + Math.min(success.timeout_ms || 5000, 30000);
  while (Date.now() < deadline) {
    const present = !success.selector_present || Boolean(document.querySelector(success.selector_present));
    const absent = !success.selector_absent || !document.querySelector(success.selector_absent);
    const origin = !success.navigation_origin ||
      canonicalOrigin(location.href) === canonicalOrigin(success.navigation_origin);
    if (present && absent && origin) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return false;
}

async function commit(preflightNonce, fields, submitSelector, expectedOrigin, success) {
  const plan = prepared.get(preflightNonce);
  prepared.delete(preflightNonce);
  if (!plan || plan.expiresAt < Date.now() || canonicalOrigin(location.href) !== expectedOrigin ||
      plan.expectedOrigin !== expectedOrigin) {
    throw new Error("PREFLIGHT_EXPIRED");
  }
  const filled = [];
  try {
    for (const field of fields) {
      const index = plan.fields.findIndex((candidate) =>
        candidate.role === field.role && candidate.selector === field.selector
      );
      if (index < 0) throw new Error("FIELD_NOT_IN_RECIPE");
      const element = verifyField(plan.fields[index], expectedOrigin);
      if (!element || element !== plan.elements[index]) throw new Error("FIELD_MUTATED");
      if (field.clear_first) injectValue(element, "");
      injectValue(element, field.encrypted_value);
      field.encrypted_value = "";
      filled.push(element);
    }
    let submitted = false;
    if (submitSelector) {
      const buttons = document.querySelectorAll(submitSelector);
      if (buttons.length !== 1 || !(buttons[0] instanceof HTMLElement)) {
        throw new Error("SUBMIT_AMBIGUOUS");
      }
      buttons[0].click();
      submitted = true;
    }
    const outcome = await waitForSuccess(success);
    if (success && !outcome) throw new Error("OUTCOME_UNVERIFIED");
    // The authorized page observes values synchronously during submit. Once
    // success is proven in the same document, erase every sensitive field so
    // later page or automation reads cannot recover it.
    for (const element of filled) {
      if (element.isConnected) injectValue(element, "");
    }
    return {
      submitted,
      fields_filled_count: filled.length,
      outcome_selector_matched: outcome
    };
  } catch (error) {
    for (const element of filled) injectValue(element, "");
    for (const field of fields) field.encrypted_value = "";
    throw error;
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only the extension service worker can send runtime messages to this
  // listener; no window.postMessage or page event is accepted.
  if (sender.id !== chrome.runtime.id || !message) return;
  if (message.type === "SECRETCTL_MEASURE") {
    sendResponse({ document_id: documentId, href: location.href });
    return;
  }
  if (message.type === "SECRETCTL_PREFLIGHT") {
    try {
      sendResponse(preflight(message.fields, message.expectedOrigin, message.expectedDocumentId));
    } catch (_) {
      sendResponse({ error: "PREFLIGHT_FAILED" });
    }
    return;
  }
  if (message.type === "SECRETCTL_COMMIT") {
    commit(
        message.preflightNonce,
        message.fields,
        message.submitSelector,
        message.expectedOrigin,
        message.success
      ).then((evidence) => sendResponse({
        execution_id: message.executionId,
        status: "completed",
        result_code: "SUCCESS",
        evidence
      })).catch(() => sendResponse({
        execution_id: message.executionId,
        status: "failed",
        result_code: "OUTCOME_UNVERIFIED",
        evidence: null
      }));
    return true;
  }
});
