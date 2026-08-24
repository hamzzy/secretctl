#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SecretAction, SecretCtl } from "@secretctl/sdk";

const principalId = process.env.SECRETCTL_PRINCIPAL_ID;
if (!principalId) {
  throw new Error("SECRETCTL_PRINCIPAL_ID must identify an enrolled agent");
}

const ACTIONS = new Set<SecretAction>([
  "authenticate.password", "authenticate.totp", "form.sensitive_fill", "oauth.authorize",
]);
const TOOL_KEYS: Record<string, Set<string>> = {
  secretctl_execute: new Set([
    "requestId", "action", "identity", "origin", "pathPrefix",
    "browserSessionId", "reason", "timeoutMs",
  ]),
  secretctl_action_status: new Set(["requestId"]),
  secretctl_cancel_action: new Set(["requestId", "reason"]),
};

const server = new Server(
  { name: "secretctl", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "secretctl_execute",
      description: "Request a broker-authorized secret action without receiving secret material.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          action: {
            type: "string",
            enum: ["authenticate.password", "authenticate.totp", "form.sensitive_fill", "oauth.authorize"],
          },
          requestId: { type: "string", minLength: 1 },
          identity: { type: "string" },
          origin: { type: "string" },
          pathPrefix: { type: "string" },
          browserSessionId: { type: "string" },
          reason: { type: "string", maxLength: 500 },
          timeoutMs: { type: "integer", minimum: 1, maximum: 120000 },
        },
        required: ["action", "identity", "origin", "browserSessionId", "reason"],
      },
    },
    {
      name: "secretctl_action_status",
      description: "Read the redacted status of an existing action request.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: { requestId: { type: "string" } },
        required: ["requestId"],
      },
    },
    {
      name: "secretctl_cancel_action",
      description: "Cancel an action request that has not begun secret execution.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          requestId: { type: "string" },
          reason: { type: "string", maxLength: 500 },
        },
        required: ["requestId"],
      },
    },
  ],
}));

function requiredString(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid ${key}`);
  }
  return value;
}

function validateArguments(tool: string, args: Record<string, unknown>): void {
  const allowed = TOOL_KEYS[tool];
  if (!allowed) throw new Error("Unknown secretctl tool");
  const unknown = Object.keys(args).find((key) => !allowed.has(key));
  if (unknown) throw new Error("Unknown tool argument");
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = (request.params.arguments ?? {}) as Record<string, unknown>;
  validateArguments(request.params.name, args);
  const client = await SecretCtl.connect({ principalId });
  try {
    let result: unknown;
    switch (request.params.name) {
      case "secretctl_execute":
        const action = requiredString(args, "action") as SecretAction;
        if (!ACTIONS.has(action)) throw new Error("Unsupported secretctl action");
        result = await client.execute({
          requestId: typeof args.requestId === "string" ? args.requestId : undefined,
          action,
          identity: requiredString(args, "identity"),
          target: {
            origin: requiredString(args, "origin"),
            pathPrefix:
              typeof args.pathPrefix === "string" ? args.pathPrefix : undefined,
          },
          browserSessionId: requiredString(args, "browserSessionId"),
          reason: requiredString(args, "reason"),
          timeoutMs: typeof args.timeoutMs === "number" ? args.timeoutMs : undefined,
        });
        break;
      case "secretctl_action_status":
        result = await client.status(requiredString(args, "requestId"));
        break;
      case "secretctl_cancel_action":
        result = {
          requestId: requiredString(args, "requestId"),
          cancelled: await client.cancel(
            requiredString(args, "requestId"),
            typeof args.reason === "string" ? args.reason : undefined,
          ),
        };
        break;
      default:
        throw new Error("Unknown secretctl tool");
    }
    const structuredContent = result && typeof result === "object"
      ? result as Record<string, unknown> : { result };
    return {
      content: [{ type: "text", text: JSON.stringify(structuredContent) }],
      structuredContent,
    };
  } finally {
    client.close();
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("secretctl MCP server running on stdio");
