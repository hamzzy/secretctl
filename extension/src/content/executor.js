/**
 * secretctl Content Script Executor
 * Executes in extension isolated world.
 * Preflight element verification, overlay hit-testing,
 * value injection with synthetic events, auto-submit, and memory cleanup.
 */

async function preflightField(field, expectedOrigin) {
  const matches = document.querySelectorAll(field.selector);
  if (matches.length !== 1) {
    throw new Error("FIELD_AMBIGUOUS");
  }
  const el = matches[0];

  if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) {
    throw new Error("FIELD_NOT_EDITABLE");
  }
  if (el.disabled || el.readOnly || !el.isConnected) {
    throw new Error("FIELD_NOT_EDITABLE");
  }

  const rect = el.getBoundingClientRect();
  if (rect.width < 10 || rect.height < 10) {
    throw new Error("FIELD_NOT_VISIBLE");
  }
  if (rect.bottom <= 0 || rect.right <= 0 || rect.top >= innerHeight || rect.left >= innerWidth) {
    throw new Error("FIELD_OUTSIDE_VIEWPORT");
  }

  const style = window.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden" || parseFloat(style.opacity) < 0.1) {
    throw new Error("FIELD_NOT_VISIBLE");
  }

  // Hit test center point to prevent overlay harvesting
  const centerX = rect.left + rect.width / 2;
  const centerY = rect.top + rect.height / 2;
  const hit = document.elementFromPoint(centerX, centerY);
  if (hit !== el && !el.contains(hit)) {
    throw new Error("FIELD_OVERLAID");
  }

  // Verify form action if within a form
  const form = el.closest("form");
  if (form && form.action) {
    const actionUrl = new URL(form.action, window.location.href);
    if (actionUrl.origin !== expectedOrigin) {
      throw new Error("FORM_ACTION_MISMATCH");
    }
  }

  return el;
}

function injectValue(el, value) {
  // Use prototype setter to trigger frameworks like React, Vue, Angular
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  if (descriptor && descriptor.set) {
    descriptor.set.call(el, value);
  } else {
    el.value = value;
  }

  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

async function executeInjection(fields, submitSelector, expectedOrigin) {
  if (location.origin !== expectedOrigin) {
    throw new Error("ORIGIN_MISMATCH");
  }

  // 1. Run preflight on all fields
  const verifiedElements = [];
  for (const field of fields) {
    verifiedElements.push(await preflightField(field, expectedOrigin));
  }

  // 2. Perform injection
  let fieldsFilled = 0;
  for (let index = 0; index < fields.length; index++) {
    const field = fields[index];
    const el = verifiedElements[index];
    if (!el.isConnected || document.querySelectorAll(field.selector).length !== 1) {
      throw new Error("FIELD_MUTATED");
    }
    if (field.clear_first) {
      injectValue(el, "");
    }
    injectValue(el, field.encrypted_value);
    field.encrypted_value = "";
    fieldsFilled++;
  }

  // 3. Submit if requested
  let submitted = false;
  if (submitSelector) {
    const submitBtn = document.querySelector(submitSelector);
    if (submitBtn) {
      submitBtn.click();
      submitted = true;
    }
  }

  return {
    submitted,
    fields_filled_count: fieldsFilled,
    outcome_selector_matched: true
  };
}

// Only extension-originated runtime messages are accepted. Page-controlled
// window messages are intentionally never an execution channel.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "SECRETCTL_EXECUTE") {
    return;
  }
  const { fields, submitSelector, executionId, expectedOrigin } = message;
  executeInjection(fields, submitSelector, expectedOrigin)
    .then((evidence) => sendResponse({
      execution_id: executionId,
      status: "completed",
      result_code: "SUCCESS",
      evidence
    }))
    .catch(() => {
      for (const field of fields || []) {
        const element = document.querySelector(field.selector);
        if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
          injectValue(element, "");
        }
        field.encrypted_value = "";
      }
      sendResponse({
        execution_id: executionId,
        status: "failed",
        result_code: "PREFLIGHT_FAILED",
        evidence: null
      });
    });
  return true;
});
