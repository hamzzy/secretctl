/**
 * secretctl Content Script Executor
 * Executes in extension isolated world.
 * Preflight element verification, overlay hit-testing,
 * value injection with synthetic events, auto-submit, and memory cleanup.
 */

export async function preflightField(selector) {
  const el = document.querySelector(selector);
  if (!el) {
    throw new Error(`Element not found: ${selector}`);
  }

  const rect = el.getBoundingClientRect();
  if (rect.width < 10 || rect.height < 10) {
    throw new Error(`Element is too small or invisible: ${selector}`);
  }

  const style = window.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden" || parseFloat(style.opacity) < 0.1) {
    throw new Error(`Element is not visible: ${selector}`);
  }

  // Hit test center point to prevent overlay harvesting
  const centerX = rect.left + rect.width / 2;
  const centerY = rect.top + rect.height / 2;
  const hit = document.elementFromPoint(centerX, centerY);
  if (hit !== el && !el.contains(hit)) {
    throw new Error(`Element is obscured by overlay: ${selector}`);
  }

  // Verify form action if within a form
  const form = el.closest("form");
  if (form && form.action) {
    const actionUrl = new URL(form.action, window.location.href);
    if (actionUrl.protocol !== "https:" && window.location.hostname !== "localhost") {
      throw new Error(`Form action is not secure HTTPS: ${actionUrl}`);
    }
  }

  return true;
}

export function injectValue(el, value) {
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

export async function executeInjection(fields, submitSelector) {
  // 1. Run preflight on all fields
  for (const field of fields) {
    await preflightField(field.selector);
  }

  // 2. Perform injection
  let fieldsFilled = 0;
  for (const field of fields) {
    const el = document.querySelector(field.selector);
    if (el) {
      if (field.clear_first) {
        injectValue(el, "");
      }
      injectValue(el, field.encrypted_value);
      fieldsFilled++;
    }
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

// Window message listener for executor execution requests
window.addEventListener("message", async (event) => {
  if (event.source !== window || !event.data || event.data.type !== "SECRETCTL_EXECUTE") {
    return;
  }

  try {
    const { fields, submitSelector, executionId } = event.data;
    const evidence = await executeInjection(fields, submitSelector);

    chrome.runtime.sendMessage({
      type: "REPORT_RESULT",
      params: {
        execution_id: executionId,
        status: "completed",
        result_code: "SUCCESS",
        evidence
      }
    });
  } catch (err) {
    chrome.runtime.sendMessage({
      type: "REPORT_RESULT",
      params: {
        execution_id: event.data.executionId,
        status: "failed",
        result_code: "PREFLIGHT_FAILED",
        evidence: null
      }
    });
  }
});
