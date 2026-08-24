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
            enum: ["authenticate.password", "authenticate.totp", "form.sensitive_fill"],
          },
          identity: { type: "string" },
          origin: { type: "string" },
          pathPrefix: { type: "string" },
          browserSessionId: { type: "string" },
          reason: { type: "string", maxLength: 500 },
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

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = (request.params.arguments ?? {}) as Record<string, unknown>;
  const client = await SecretCtl.connect({ principalId });
  try {
    let result: unknown;
    switch (request.params.name) {
      case "secretctl_execute":
        result = await client.execute({
          action: requiredString(args, "action") as SecretAction,
          identity: requiredString(args, "identity"),
          target: {
            origin: requiredString(args, "origin"),
            pathPrefix:
              typeof args.pathPrefix === "string" ? args.pathPrefix : undefined,
          },
          browserSessionId: requiredString(args, "browserSessionId"),
          reason: requiredString(args, "reason"),
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
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  } finally {
    client.close();
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("secretctl MCP server running on stdio");
