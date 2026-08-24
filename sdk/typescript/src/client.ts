import * as net from "net";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import * as fs from "fs";
import { execFileSync } from "child_process";
import { LengthPrefixedSocket } from "./framing.js";
import {
  ActionStatus, AuthenticateOptions, BrowserTab, ConnectOptions, ExecuteRequest, ExecuteResult,
  PageTextResult, SafeLocator, SafePageSnapshot, SecretCtlErrorCode, SessionInfo, WaitCondition,
} from "./types.js";

const PROHIBITED_RESPONSE_KEYS = [
  "password", "secret", "token", "seed", "cookie", "authorization",
  "private_key", "refresh_token", "access_token", "capability_token"
];
const KNOWN_ERROR_CODES = new Set<SecretCtlErrorCode>([
  "AUTH_POLICY_DENIED", "APPROVAL_REJECTED", "APPROVAL_TIMEOUT",
  "CAPABILITY_EXPIRED", "CAPABILITY_CONSUMED", "EPOCH_INVALIDATED",
  "ORIGIN_MISMATCH", "FRAME_VIOLATION", "SESSION_TERMINATED",
  "EXECUTOR_FAILED", "RECIPE_NOT_FOUND", "USER_PRESENCE_UNAVAILABLE", "SECURITY_VIOLATION", "INTERNAL_ERROR",
]);

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

/** Convert the broker's discriminated action state to the stable SDK union. */
export function parseExecuteResult(
  result: unknown,
  request: ExecuteRequest,
): ExecuteResult {
  if (!result || typeof result !== "object") throw new Error("Invalid action response");
  const value = result as Record<string, unknown>;
  if (typeof value.request_id !== "string" || typeof value.state !== "string") {
    throw new Error("Invalid action response shape");
  }
  const state = value.state;
  const common = {
    requestId: value.request_id,
    action: request.action,
    identity: request.identity,
    verifiedOrigin: request.target.origin,
    browserSessionId: request.browserSessionId,
    evidenceId: typeof value.evidence_ref === "string" ? value.evidence_ref : undefined,
    grantId: typeof value.grant_id === "string" ? value.grant_id : undefined,
    completedAt: typeof value.completed_at === "string" ? value.completed_at : undefined,
  };
  if (state === "completed") return { status: "completed", ...common };
  if (state === "capability_issued") return { status: "capability_issued", ...common };
  if (state === "denied" || state === "expired" || state === "cancelled" ||
      state === "indeterminate" || state === "completed_evidence_lost" ||
      state === "revoked" || state === "failed") {
    const candidate = typeof value.result_code === "string" ? value.result_code : "";
    const code = KNOWN_ERROR_CODES.has(candidate as SecretCtlErrorCode)
      ? candidate as SecretCtlErrorCode
      : "INTERNAL_ERROR";
    return {
      status: state,
      requestId: common.requestId,
      code,
      safeMessage: state === "completed_evidence_lost" || state === "indeterminate"
        ? "The action may have completed. Do not retry automatically."
        : `Action ended in ${state}`,
      retryable: !["completed_evidence_lost", "indeterminate", "revoked"].includes(state),
      evidenceId: common.evidenceId,
    };
  }
  throw new Error("Unknown action response state");
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
  [-32012]: "USER_PRESENCE_UNAVAILABLE",
  [-32099]: "SECURITY_VIOLATION"
};

function contextDigest(parts: Buffer[]): Buffer {
  const hash = crypto.createHash("sha256");
  for (const part of parts) {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(part.length));
    hash.update(length);
    hash.update(part);
  }
  return hash.digest();
}

class SecureChannel {
  private txCounter = 0n;
  private rxCounter = 0n;

  public constructor(private txKey: Buffer, private rxKey: Buffer) {}

  public static derive(shared: Buffer, salt: Buffer): SecureChannel {
    const material = Buffer.from(crypto.hkdfSync(
      "sha256", shared, salt, Buffer.from("secretctl-agent-session-v1"), 64
    ));
    return new SecureChannel(material.subarray(0, 32), material.subarray(32, 64));
  }

  private nonce(counter: bigint): Buffer {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(counter, 4);
    return nonce;
  }

  public encrypt(plaintext: Buffer): Buffer {
    const cipher = crypto.createCipheriv(
      "chacha20-poly1305", this.txKey, this.nonce(this.txCounter++), { authTagLength: 16 }
    );
    return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  }

  public decrypt(ciphertext: Buffer): Buffer {
    if (ciphertext.length < 16) throw new Error("Invalid encrypted broker response");
    const body = ciphertext.subarray(0, -16);
    const tag = ciphertext.subarray(-16);
    const decipher = crypto.createDecipheriv(
      "chacha20-poly1305", this.rxKey, this.nonce(this.rxCounter), { authTagLength: 16 }
    );
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
    this.rxCounter++;
    return plaintext;
  }
}

export class SecretCtl {
  private socket: LengthPrefixedSocket;
  private channel?: SecureChannel;
  private connectedAt = Date.now();
  private handshaking = true;
  private rpcTail: Promise<void> = Promise.resolve();

  private constructor(socket: LengthPrefixedSocket, private options: ConnectOptions) {
    this.socket = socket;
  }

  public static async connect(options: ConnectOptions = {}): Promise<SecretCtl> {
    const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
    const defaultPath = path.join(configHome, "secretctl", "run", "agent.sock");
    const targetSocket = options.socketPath || defaultPath;
    const principalId = options.principalId || process.env.SECRETCTL_PRINCIPAL_ID;
    if (!principalId) throw new Error("secretctl agent principal is required; launch under secretctl run");

    return new Promise((resolve, reject) => {
      const client = net.createConnection(targetSocket, () => {
        const framed = new LengthPrefixedSocket(client);
        const secretctl = new SecretCtl(framed, options);
        const clientNonce = crypto.randomUUID();
        secretctl.rpc("session.hello", {
          protocol_version: "1.0",
          role: "agent",
          principal_id: principalId,
          client_nonce: clientNonce,
          supported_suites: ["X25519-HKDF-SHA256-CHACHA20POLY1305"]
        }).then((hello) => {
          const publicKeyPath = options.brokerPublicKeyPath
            || path.join(configHome, "secretctl", "broker_key.pub");
          const publicKey = fs.readFileSync(publicKeyPath);
          if (publicKey.length !== 32) throw new Error("Invalid broker public key");
          const ephemeral = Buffer.from(hello.ephemeral_public_key, "base64url");
          const transcript = contextDigest([
            Buffer.from("secretctl-session-hello-v1"),
            Buffer.from(clientNonce),
            Buffer.from(hello.server_nonce),
            Buffer.from(principalId),
            ephemeral,
          ]);
          const spki = Buffer.concat([
            Buffer.from("302a300506032b6570032100", "hex"),
            publicKey,
          ]);
          const verified = crypto.verify(
            null,
            transcript,
            crypto.createPublicKey({ key: spki, format: "der", type: "spki" }),
            Buffer.from(hello.signature, "base64url"),
          );
          if (!verified) throw new Error("Broker handshake signature rejected");
          const keyPair = crypto.generateKeyPairSync("x25519");
          const clientPublicDer = keyPair.publicKey.export({ format: "der", type: "spki" });
          const clientPublic = Buffer.from(clientPublicDer).subarray(-32);
          const serverPublic = crypto.createPublicKey({
            key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), ephemeral]),
            format: "der",
            type: "spki"
          });
          const authTranscript = contextDigest([
            Buffer.from("secretctl-session-auth-v1"),
            Buffer.from("1.0"),
            Buffer.from("agent"),
            Buffer.from(principalId),
            Buffer.from(clientNonce),
            Buffer.from(hello.server_nonce),
            ephemeral,
            clientPublic
          ]);
          let signature: Buffer;
          if (options.signingKeyPath) {
            const seed = fs.readFileSync(options.signingKeyPath);
            if (seed.length !== 32) throw new Error("Invalid agent signing key");
            const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
            signature = crypto.sign(null, authTranscript, crypto.createPrivateKey({
              key: pkcs8, format: "der", type: "pkcs8"
            }));
          } else {
            signature = Buffer.from(execFileSync(
              process.env.SECRETCTL_CLI_PATH || "secretctl",
              ["agent", "sign", "--digest", authTranscript.toString("base64url")],
              { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
            ).trim(), "base64url");
          }
          return secretctl.rpc("session.authenticate", {
            client_ephemeral_public_key: clientPublic.toString("base64url"),
            signature: signature.toString("base64url")
          }).then((authenticated) => {
            if (!authenticated?.authenticated) throw new Error("Agent authentication rejected");
            const shared = crypto.diffieHellman({ privateKey: keyPair.privateKey, publicKey: serverPublic });
            secretctl.channel = SecureChannel.derive(shared, Buffer.from(hello.server_nonce));
            secretctl.connectedAt = Date.now();
            secretctl.handshaking = false;
            resolve(secretctl);
          });
        }).catch(reject);
      });

      client.on("error", (err) => {
        reject(new Error(`Failed to connect to secretctl daemon at ${targetSocket}: ${err.message}`));
      });
    });
  }

  private async rpcOnce(method: string, params: Record<string, unknown>): Promise<any> {
    const rpcReq = {
      jsonrpc: "2.0",
      id: `rpc_${crypto.randomUUID()}`,
      method,
      params
    };
    const plaintext = Buffer.from(JSON.stringify(rpcReq));
    await this.socket.send(this.channel ? this.channel.encrypt(plaintext) : plaintext);
    const wire = await this.socket.readNext();
    const respBuf = this.channel ? this.channel.decrypt(wire) : wire;
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

  private async reconnect(): Promise<void> {
    const replacement = await SecretCtl.connect(this.options);
    this.socket.close();
    this.socket = replacement.socket;
    this.channel = replacement.channel;
    this.connectedAt = replacement.connectedAt;
    this.handshaking = false;
  }

  private async rpcWithReconnect(method: string, params: Record<string, unknown>): Promise<any> {
    if (!this.handshaking && Date.now() - this.connectedAt >= 540_000) {
      await this.reconnect();
    }
    try {
      return await this.rpcOnce(method, params);
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      const transportFailure = /transport|socket|closed|EPIPE|ECONNRESET|read/i.test(message);
      if (this.handshaking || !transportFailure) throw error;
      await this.reconnect();
      return this.rpcOnce(method, params);
    }
  }

  private rpc(method: string, params: Record<string, unknown>): Promise<any> {
    const operation = this.rpcTail.then(() => this.rpcWithReconnect(method, params));
    this.rpcTail = operation.then(() => undefined, () => undefined);
    return operation;
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
      return parseExecuteResult(res, request);
    } catch (error) {
      const safeError = error as Error & { code?: SecretCtlErrorCode };
      return {
        status: "failed",
        requestId,
        code: safeError.code || "INTERNAL_ERROR",
        safeMessage: safeError.message || "Action failed",
        retryable: false,
      };
    }
  }

  /** Ask the broker to resolve the active managed page and credential action. */
  public async authenticate(
    credential: string,
    reason: string,
    options: AuthenticateOptions = {},
  ): Promise<ExecuteResult> {
    const result = await this.rpc("action.authenticate", {
      identity: credential,
      reason,
      ...(options.action ? { action: options.action } : {}),
      ...(options.requestId ? { request_id: options.requestId } : {}),
      wait: true,
      timeout_ms: options.timeoutMs || 60000,
      ...(options.clientContext ? { client_context: options.clientContext } : {}),
    });
    if (!result || typeof result !== "object") throw new Error("Invalid authentication response");
    const routed = result as Record<string, unknown>;
    if (typeof routed.action !== "string" || typeof routed.verified_origin !== "string" ||
        typeof routed.browser_session_id !== "string") {
      throw new Error("Broker did not return a verified authentication context");
    }
    return parseExecuteResult(routed, {
      requestId: typeof routed.request_id === "string" ? routed.request_id : options.requestId,
      action: routed.action as ExecuteRequest["action"],
      identity: credential,
      target: { origin: routed.verified_origin },
      browserSessionId: routed.browser_session_id,
      reason,
      timeoutMs: options.timeoutMs,
      clientContext: options.clientContext,
    });
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

  public async sessionInfo(): Promise<SessionInfo> {
    const result = await this.rpc("session.info", {});
    return {
      protocolVersion: result.protocol_version,
      principalId: result.principal_id,
      role: result.role,
      rekeyAfterSeconds: result.rekey_after_seconds,
    };
  }

  public async *subscribe(requestId: string, timeoutMs = 30000): AsyncGenerator<ActionStatus> {
    let previous: ActionStatus | undefined;
    while (true) {
      const result = await this.rpc("action.subscribe", {
        request_id: requestId,
        ...(previous ? { after_state: previous.state, after_detail: previous.detail } : {}),
        timeout_ms: Math.min(timeoutMs, 30000),
      });
      const status: ActionStatus = {
        requestId: result.request_id, state: result.state, detail: result.detail,
      };
      const changed = !previous || previous.state !== status.state || previous.detail !== status.detail;
      if (changed) yield status;
      previous = status;
      if (["completed", "denied", "expired", "cancelled", "indeterminate", "completed_evidence_lost", "revoked", "failed"].includes(status.state)) return;
    }
  }

  public async tabs(sessionId: string): Promise<BrowserTab[]> {
    const result = await this.rpc("browser.tabs", { session_id: sessionId });
    return result.tabs;
  }

  public async openTab(sessionId: string, url = "about:blank"): Promise<string> {
    const result = await this.rpc("browser.open_tab", { session_id: sessionId, url });
    return result.tab_id;
  }

  public async navigate(sessionId: string, tabId: string, url: string): Promise<void> {
    await this.rpc("browser.navigate", { session_id: sessionId, tab_id: tabId, url });
  }

  public async reload(sessionId: string, tabId: string): Promise<void> {
    await this.rpc("browser.reload", { session_id: sessionId, tab_id: tabId });
  }

  public async closeTab(sessionId: string, tabId: string): Promise<void> {
    await this.rpc("browser.close_tab", { session_id: sessionId, tab_id: tabId });
  }

  public async click(
    sessionId: string,
    tabId: string,
    locator: SafeLocator
  ): Promise<void> {
    await this.rpc("page.click", { session_id: sessionId, tab_id: tabId, locator });
  }

  public async typePublic(
    sessionId: string,
    tabId: string,
    locator: SafeLocator,
    text: string
  ): Promise<void> {
    await this.rpc("page.type_public", { session_id: sessionId, tab_id: tabId, locator, text });
  }

  public async select(
    sessionId: string, tabId: string, locator: SafeLocator, label: string,
  ): Promise<void> {
    await this.rpc("page.select", { session_id: sessionId, tab_id: tabId, locator, label });
  }

  public async readText(
    sessionId: string,
    tabId: string,
    locator?: SafeLocator,
    maxChars?: number,
  ): Promise<PageTextResult> {
    return this.rpc("page.read_text", {
      session_id: sessionId, tab_id: tabId, locator, max_chars: maxChars,
    });
  }

  public async snapshotSafe(
    sessionId: string,
    tabId: string,
    maxNodes?: number,
    checkVisibility = true,
  ): Promise<SafePageSnapshot> {
    return this.rpc("page.snapshot_safe", {
      session_id: sessionId, tab_id: tabId, max_nodes: maxNodes,
      check_visibility: checkVisibility,
    });
  }

  public async waitFor(
    sessionId: string,
    tabId: string,
    condition: WaitCondition,
    timeoutMs = 10000,
  ): Promise<boolean> {
    const result = await this.rpc("page.wait_for", {
      session_id: sessionId, tab_id: tabId, condition, timeout_ms: timeoutMs,
    });
    return result.satisfied === true;
  }

  public async back(sessionId: string, tabId: string): Promise<void> {
    await this.rpc("browser.back", { session_id: sessionId, tab_id: tabId });
  }

  public async forward(sessionId: string, tabId: string): Promise<void> {
    await this.rpc("browser.forward", { session_id: sessionId, tab_id: tabId });
  }

  public close() {
    this.socket.close();
  }
}
