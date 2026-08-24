import { SecretCtl } from "../../sdk/typescript/src/index.js";

async function main() {
  console.log("Connecting AI agent to secretctl broker...");
  const secretctl = await SecretCtl.connect();

  console.log("Requesting password authentication for 'github-work'...");
  const result = await secretctl.execute({
    action: "authenticate.password",
    identity: "github-work",
    target: {
      origin: "https://github.com:443",
      pathPrefix: "/login"
    },
    browserSessionId: "bs_demo_session",
    reason: "Agent automated PR triage"
  });

  console.log("Execution result:", result);
  secretctl.close();
}

main().catch(console.error);
