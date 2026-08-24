import * as net from "net";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import * as fs from "fs";
import { LengthPrefixedSocket } from "./framing.js";
import { ActionStatus, ConnectOptions, ExecuteRequest, ExecuteResult, SecretCtlErrorCode } from "./types.js";

const PROHIBITED_RESPONSE_KEYS = [
  "password", "secret", "token", "seed", "cookie", "authorization",
  "private_key", "refresh_token", "access_token", "capability_token"
];

export function assertAgentSafe(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(assertAgentSafe);
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const normalized = key.toLowerCase();
      if (PROHIBITED_RESPONSE_KEYS.some((part) => normalized.includes(part))) {
        throw new Error("secretctl rejected an unsafe broker response");
      }
      assertAgentSafe(child);
    }
  }
}

const ERROR_CODES: Record<number, SecretCtlErrorCode> = {
  [-32001]: "AUTH_POLICY_DENIED",
  [-32002]: "APPROVAL_REJECTED",
  [-32003]: "APPROVAL_TIMEOUT",
  [-32004]: "CAPABILITY_EXPIRED",
  [-32005]: "CAPABILITY_CONSUMED",
  [-32006]: "EPOCH_INVALIDATED",
  [-32007]: "ORIGIN_MISMATCH",
  [-32008]: "FRAME_VIOLATION",
  [-32009]: "SESSION_TERMINATED",
  [-32010]: "EXECUTOR_FAILED",
  [-32011]: "RECIPE_NOT_FOUND",
  [-32099]: "SECURITY_VIOLATION"
};

export class SecretCtl {
  private socket: LengthPrefixedSocket;

  private constructor(socket: LengthPrefixedSocket) {
    this.socket = socket;
  }

  public static async connect(options: ConnectOptions): Promise<SecretCtl> {
    const defaultPath = path.join(os.homedir(), ".secretctl", "run", "agent.sock");
    const targetSocket = options.socketPath || defaultPath;

    return new Promise((resolve, reject) => {
      const client = net.createConnection(targetSocket, () => {
        const framed = new LengthPrefixedSocket(client);
        const secretctl = new SecretCtl(framed);
        const clientNonce = crypto.randomUUID();
        secretctl.rpc("session.hello", {
          protocol_version: "1.0",
          role: "agent",
          principal_id: options.principalId,
          client_nonce: clientNonce,
          supported_suites: ["X25519_CHACHA20_POLY1305_ED25519"]
        }).then((hello) => {
          const publicKeyPath = options.brokerPublicKeyPath
            || path.join(os.homedir(), ".secretctl", "broker_key.pub");
          const publicKey = fs.readFileSync(publicKeyPath);
          if (publicKey.length !== 32) throw new Error("Invalid broker public key");
          const ephemeral = Buffer.from(hello.ephemeral_public_key, "base64url");
          const transcript = crypto.createHash("sha256");
          for (const component of [
            Buffer.from("secretctl-session-hello-v1"),
            Buffer.from(clientNonce),
            Buffer.from(hello.server_nonce),
            Buffer.from(options.principalId),
            ephemeral,
          ]) {
            const length = Buffer.alloc(8);
            length.writeBigUInt64BE(BigInt(component.length));
            transcript.update(length);
            transcript.update(component);
          }
          const spki = Buffer.concat([
            Buffer.from("302a300506032b6570032100", "hex"),
            publicKey,
          ]);
          const verified = crypto.verify(
            null,
            transcript.digest(),
            crypto.createPublicKey({ key: spki, format: "der", type: "spki" }),
            Buffer.from(hello.signature, "base64url"),
          );
          if (!verified) throw new Error("Broker handshake signature rejected");
          resolve(secretctl);
        }, reject);
      });

      client.on("error", (err) => {
        reject(new Error(`Failed to connect to secretctl daemon at ${targetSocket}: ${err.message}`));
      });
    });
  }

  private async rpc(method: string, params: Record<string, unknown>): Promise<any> {
    const rpcReq = {
      jsonrpc: "2.0",
      id: `rpc_${crypto.randomUUID()}`,
      method,
      params
    };
    await this.socket.send(Buffer.from(JSON.stringify(rpcReq)));
    const respBuf = await this.socket.readNext();
    const rpcResp: unknown = JSON.parse(respBuf.toString("utf8"));
    assertAgentSafe(rpcResp);
    if (!rpcResp || typeof rpcResp !== "object") {
      throw new Error("Invalid secretctl response");
    }
    const response = rpcResp as { error?: { code?: number; message?: string }; result?: unknown };
    if (response.error) {
      const code = ERROR_CODES[response.error.code ?? 0] || "INTERNAL_ERROR";
      const error = new Error(response.error.message || "Action failed") as Error & { code: SecretCtlErrorCode };
      error.code = code;
      throw error;
    }
    return response.result;
  }

  public async execute(request: ExecuteRequest): Promise<ExecuteResult> {
    const requestId = request.requestId || `req_${crypto.randomUUID()}`;

    try {
      const res = await this.rpc("action.request", {
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
      });
      if (!res || typeof res !== "object" || typeof res.request_id !== "string" || typeof res.state !== "string") {
        throw new Error("Invalid action response shape");
      }
      return {
        status: res.state === "capability_issued" ? "capability_issued" : "completed",
        requestId: res.request_id,
        action: request.action,
        identity: request.identity,
        verifiedOrigin: request.target.origin,
        browserSessionId: request.browserSessionId,
        evidenceId: res.evidence_ref,
        completedAt: res.completed_at
      };
    } catch (error) {
      const safeError = error as Error & { code?: SecretCtlErrorCode };
      return {
        status: "failed",
        requestId,
        code: safeError.code || "INTERNAL_ERROR",
        safeMessage: safeError.message || "Action failed"
      };
    }
  }

  public async status(requestId: string): Promise<ActionStatus> {
    const result = await this.rpc("action.status", { request_id: requestId });
    return {
      requestId: result.request_id,
      state: result.state,
      detail: result.detail
    };
  }

  public async cancel(requestId: string, reason?: string): Promise<boolean> {
    const result = await this.rpc("action.cancel", { request_id: requestId, reason });
    return result.cancelled === true;
  }

  public close() {
    this.socket.close();
  }
}
