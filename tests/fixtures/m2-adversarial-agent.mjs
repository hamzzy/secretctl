import { SecretCtl } from "../../sdk/typescript/dist/index.js";

const browserSessionId = process.env.M2_BROWSER_SESSION_ID;
if (!browserSessionId) throw new Error("M2_BROWSER_SESSION_ID is required");

const client = await SecretCtl.connect();
try {
  for (const mode of ["hidden", "overlay", "duplicate", "replaced"]) {
    const tabId = await client.openTab(
      browserSessionId,
      `http://127.0.0.1:8765/m2-login.html?case=${mode}`,
    );
    await new Promise((resolve) => setTimeout(resolve, 2500));
    const result = await client.execute({
      action: "authenticate.password",
      identity: "m2-e2e-password",
      target: {
        origin: "http://127.0.0.1:8765",
        pathPrefix: "/m2-login.html",
      },
      browserSessionId,
      reason: `M2 ${mode} field rejection test`,
      timeoutMs: 4000,
    });
    if (result.status === "completed") {
      throw new Error(`${mode} field unexpectedly completed`);
    }
    const serialized = JSON.stringify(result);
    const canaryMarker = ["secretctl", "m2", "canary"].join("-");
    if (serialized.includes(canaryMarker)) {
      throw new Error(`${mode} result contained the canary marker`);
    }
    console.log(JSON.stringify({ mode, status: result.status, code: result.code }));
    await client.closeTab(browserSessionId, tabId);
    await new Promise((resolve) => setTimeout(resolve, 2200));
  }
} finally {
  client.close();
}
