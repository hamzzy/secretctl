import assert from "node:assert/strict";
import test from "node:test";

import { assertAgentSafe } from "./client.js";

test("hostile secret-bearing broker fields fail closed", () => {
  assert.throws(
    () => assertAgentSafe({ result: { access_token: "canary" } }),
    /unsafe broker response/,
  );
  assert.doesNotThrow(() =>
    assertAgentSafe({ result: { request_id: "req_1", state: "completed" } }),
  );
});
