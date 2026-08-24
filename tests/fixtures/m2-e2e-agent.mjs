import { SecretCtl } from "../../sdk/typescript/dist/index.js";

const browserSessionId = process.env.M2_BROWSER_SESSION_ID;
if (!browserSessionId) throw new Error("M2_BROWSER_SESSION_ID is required");

const client = await SecretCtl.connect();
try {
  const tabId = await client.openTab(
    browserSessionId,
    "http://127.0.0.1:8765/m2-login.html",
  );
  await new Promise((resolve) => setTimeout(resolve, 6000));
  const result = await client.execute({
    action: "authenticate.password",
    identity: "m2-e2e-password",
    target: {
      origin: "http://127.0.0.1:8765",
      pathPrefix: "/m2-login.html",
    },
    browserSessionId,
    reason: "M2 managed-browser acceptance test",
    timeoutMs: 30000,
  });
  if (result.status !== "completed") {
    throw new Error(`M2 action did not complete: ${JSON.stringify(result)}`);
  }
  const serialized = JSON.stringify(result);
  const canaryMarker = ["secretctl", "m2", "canary"].join("-");
  if (serialized.includes(canaryMarker)) {
    throw new Error("agent-visible result contained the canary marker");
  }
  console.log(JSON.stringify(result));
} finally {
  client.close();
}
