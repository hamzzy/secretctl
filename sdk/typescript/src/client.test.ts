import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { assertAgentSafe, parseExecuteResult } from "./client.js";

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
