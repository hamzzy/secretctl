import * as net from "net";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import { LengthPrefixedSocket } from "./framing.js";
import { ExecuteRequest, ExecuteResult, SecretCtlErrorCode } from "./types.js";

export class SecretCtl {
  private socket: LengthPrefixedSocket;

  private constructor(socket: LengthPrefixedSocket) {
    this.socket = socket;
  }

  public static async connect(socketPath?: string): Promise<SecretCtl> {
    const defaultPath = path.join(os.homedir(), ".secretctl", "run", "agent.sock");
    const targetSocket = socketPath || defaultPath;

    return new Promise((resolve, reject) => {
      const client = net.createConnection(targetSocket, () => {
        const framed = new LengthPrefixedSocket(client);
        resolve(new SecretCtl(framed));
      });

      client.on("error", (err) => {
        reject(new Error(`Failed to connect to secretctl daemon at ${targetSocket}: ${err.message}`));
      });
    });
  }

  public async execute(request: ExecuteRequest): Promise<ExecuteResult> {
    const requestId = request.requestId || `req_${crypto.randomUUID()}`;

    const rpcReq = {
      jsonrpc: "2.0",
      id: `rpc_${crypto.randomUUID()}`,
      method: "action.request",
      params: {
        request_id: requestId,
        action: request.action,
        identity: request.identity,
        target: {
          origin: request.target.origin,
          path_prefix: request.target.pathPrefix
        },
        browser_session_id: request.browserSessionId,
        tab_hint: request.tabHint,
        reason: request.reason,
        wait: true,
        timeout_ms: request.timeoutMs || 60000,
        client_context: request.clientContext
      }
    };

    await this.socket.send(Buffer.from(JSON.stringify(rpcReq)));
    const respBuf = await this.socket.readNext();
    const rpcResp = JSON.parse(respBuf.toString("utf8"));

    if (rpcResp.error) {
      return {
        status: "failed",
        requestId,
        code: (rpcResp.error.message as SecretCtlErrorCode) || "INTERNAL_ERROR",
        safeMessage: rpcResp.error.message || "Action failed"
      };
    }

    const res = rpcResp.result;
    return {
      status: res.state === "capability_issued" ? "capability_issued" : "completed",
      requestId: res.request_id,
      action: request.action,
      identity: request.identity,
      verifiedOrigin: request.target.origin,
      browserSessionId: request.browserSessionId,
      evidenceId: res.evidence_ref,
      completedAt: res.completed_at || new Date().toISOString()
    };
  }

  public close() {
    this.socket.close();
  }
}
