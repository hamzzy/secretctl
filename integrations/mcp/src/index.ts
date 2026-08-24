#!/usr/bin/env node

/**
 * secretctl Model Context Protocol (MCP) Server
 * Exposes capability-based authentication tools to AI agent runtimes.
 * Never outputs secret bytes, passwords, seeds, or tokens.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SecretCtl } from "@secretctl/sdk";

const server = new Server(
  {
    name: "secretctl",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "secretctl_authenticate_password",
        description:
          "Perform approved password authentication for an enrolled identity in a managed browser session without receiving the password.",
        inputSchema: {
          type: "object",
          properties: {
            identity: {
              type: "string",
              description: "The name of the enrolled credential/identity (e.g. 'github-work')",
            },
            origin: {
              type: "string",
              description: "The exact destination origin (e.g. 'https://github.com:443')",
            },
            pathPrefix: {
              type: "string",
              description: "Optional URL path prefix (e.g. '/login')",
            },
            browserSessionId: {
              type: "string",
              description: "The managed browser session ID",
            },
            reason: {
              type: "string",
              description: "Attributable justification for requesting authentication",
            },
          },
          required: ["identity", "origin", "browserSessionId", "reason"],
        },
      },
      {
        name: "secretctl_authenticate_totp",
        description:
          "Generate and fill one approved RFC 6238 TOTP code for active authentication without exposing the seed or code.",
        inputSchema: {
          type: "object",
          properties: {
            identity: {
              type: "string",
              description: "The name of the TOTP credential (e.g. 'github-totp')",
            },
            origin: {
              type: "string",
              description: "The exact destination origin",
            },
            browserSessionId: {
              type: "string",
              description: "The managed browser session ID",
            },
            reason: {
              type: "string",
              description: "Attributable justification",
            },
          },
          required: ["identity", "origin", "browserSessionId", "reason"],
        },
      },
      {
        name: "secretctl_fill_sensitive_form",
        description:
          "Fill approved sensitive form fields (e.g. recovery codes, account numbers) into configured recipe fields without exposing values.",
        inputSchema: {
          type: "object",
          properties: {
            identity: {
              type: "string",
              description: "The form identity descriptor",
            },
            origin: {
              type: "string",
              description: "The exact destination origin",
            },
            browserSessionId: {
              type: "string",
              description: "The managed browser session ID",
            },
            reason: {
              type: "string",
              description: "Attributable justification",
            },
          },
          required: ["identity", "origin", "browserSessionId", "reason"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  let action: "authenticate.password" | "authenticate.totp" | "form.sensitive_fill";
  if (name === "secretctl_authenticate_password") {
    action = "authenticate.password";
  } else if (name === "secretctl_authenticate_totp") {
    action = "authenticate.totp";
  } else if (name === "secretctl_fill_sensitive_form") {
    action = "form.sensitive_fill";
  } else {
    throw new Error(`Unknown tool: ${name}`);
  }

  const client = await SecretCtl.connect();
  try {
    const result = await client.execute({
      action,
      identity: (args as any).identity,
      target: {
        origin: (args as any).origin,
        pathPrefix: (args as any).pathPrefix,
      },
      browserSessionId: (args as any).browserSessionId,
      reason: (args as any).reason,
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } finally {
    client.close();
  }
});

async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("secretctl MCP server running on stdio");
}

run().catch((error) => {
  console.error("Fatal MCP error:", error);
  process.exit(1);
});
