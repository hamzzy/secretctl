import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { SecretCtl, assertAgentSafe, parseExecuteResult } from "./client.js";

test("hostile secret-bearing broker fields fail closed", () => {
  assert.throws(
    () => assertAgentSafe({ result: { access_token: "canary" } }),
    /unsafe broker response/,
  );
  assert.doesNotThrow(() =>
    assertAgentSafe({ result: { request_id: "req_1", state: "completed" } }),
  );
});

test("published action result states map without exposing broker internals", () => {
  const request = {
    action: "authenticate.totp" as const,
    identity: "demo",
    target: { origin: "https://example.test" },
    browserSessionId: "bs_m3",
    reason: "contract test",
  };
  const completed = parseExecuteResult({
    request_id: "req_m3_completed",
    state: "completed",
    evidence_ref: "exec:ex_m3_completed",
  }, request);
  assert.equal(completed.status, "completed");
  const failed = parseExecuteResult({
    request_id: "req_m3_failed",
    state: "failed",
    result_code: "EXECUTOR_FAILED",
  }, request);
  assert.equal(failed.status, "failed");
  assert.equal(failed.code, "EXECUTOR_FAILED");
});

test("shared cross-language result fixture stays schema-compatible", () => {
  const fixture = JSON.parse(readFileSync(
    resolve(process.cwd(), "../../tests/fixtures/m3-action-results.json"), "utf8",
  )) as Array<Record<string, unknown>>;
  const request = {
    action: "authenticate.totp" as const,
    identity: "demo",
    target: { origin: "https://example.test" },
    browserSessionId: "bs_m3",
    reason: "fixture",
  };
  assert.deepEqual(fixture.map((value) => parseExecuteResult(value, request).status), [
    "completed", "failed",
  ]);
});

test("ergonomic authentication and safe browser methods stay broker-routed", async () => {
  const calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  const client = Object.create(SecretCtl.prototype) as SecretCtl;
  (client as unknown as {
    rpc: (method: string, params: Record<string, unknown>) => Promise<unknown>;
  }).rpc = async (method: string, params: Record<string, unknown>) => {
    calls.push({ method, params });
    if (method === "action.authenticate") {
      return {
        request_id: "req_auth", state: "capability_issued",
        action: "authenticate.password", verified_origin: "https://example.test:443",
        browser_session_id: "bs_1",
      };
    }
    if (method === "page.read_text") return { text: "Sign in", truncated: false };
    if (method === "page.snapshot_safe") {
      return { url: "https://example.test/", elements: [], truncated: false };
    }
    if (method === "page.wait_for") return { satisfied: true };
    return {};
  };

  const result = await client.authenticate("github-work", "Sign me in");
  assert.equal(result.status, "capability_issued");
  assert.deepEqual(await client.readText("bs_1", "tab_1"), {
    text: "Sign in", truncated: false,
  });
  assert.equal((await client.snapshotSafe("bs_1", "tab_1")).url, "https://example.test/");
  assert.equal(await client.waitFor("bs_1", "tab_1", {
    kind: "text_present", value: "Sign in",
  }), true);
  await client.select("bs_1", "tab_1", { kind: "role", role: "combobox", name: "Region" }, "EU");
  await client.back("bs_1", "tab_1");
  await client.forward("bs_1", "tab_1");

  assert.deepEqual(calls.map((call) => call.method), [
    "action.authenticate", "page.read_text", "page.snapshot_safe",
    "page.wait_for", "page.select", "browser.back", "browser.forward",
  ]);
  assert.deepEqual(calls[0].params, {
    identity: "github-work",
    reason: "Sign me in",
    wait: true,
    timeout_ms: 60000,
  });
});
