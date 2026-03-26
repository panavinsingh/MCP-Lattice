#!/usr/bin/env node
/**
 * clean_server.js - Clean Baseline MCP Server (NO malicious content)
 *
 * This server is completely benign and serves as a baseline for testing
 * that MCP-Lattice produces ZERO false positives on legitimate tools.
 *
 * Tools provided:
 * 1. add_numbers - Adds two numbers together
 * 2. echo_text  - Echoes back the input text
 * 3. get_timestamp - Returns the current ISO 8601 timestamp
 *
 * All descriptions are straightforward and contain no:
 * - Hidden Unicode characters
 * - Bidirectional overrides
 * - Base64-encoded payloads
 * - Prompt injection phrases
 * - Exfiltration instructions
 * - Context flooding
 * - Name shadowing of known tools
 *
 * This server implements the standard MCP protocol over STDIO transport.
 */

const readline = require("readline");

// ============================================================================
// Clean Tool Definitions
// ============================================================================

const tools = [
  {
    name: "add_numbers",
    description:
      "Adds two numbers together and returns the sum. Accepts integers and floating-point numbers.",
    inputSchema: {
      type: "object",
      properties: {
        a: {
          type: "number",
          description: "The first number",
        },
        b: {
          type: "number",
          description: "The second number",
        },
      },
      required: ["a", "b"],
    },
  },
  {
    name: "echo_text",
    description:
      "Echoes back the provided text input. Useful for testing and debugging MCP connections.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "The text to echo back",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "get_timestamp",
    description:
      "Returns the current date and time as an ISO 8601 formatted string. No input required.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// ============================================================================
// MCP JSON-RPC 2.0 Protocol Handler
// ============================================================================

function sendResponse(id, result) {
  const response = { jsonrpc: "2.0", id, result };
  process.stdout.write(JSON.stringify(response) + "\n");
}

function sendError(id, code, message) {
  const response = { jsonrpc: "2.0", id, error: { code, message } };
  process.stdout.write(JSON.stringify(response) + "\n");
}

function handleRequest(msg) {
  const { id, method, params } = msg;

  switch (method) {
    case "initialize":
      sendResponse(id, {
        protocolVersion: "2025-03-26",
        serverInfo: {
          name: "clean-baseline-server",
          version: "1.0.0",
        },
        capabilities: {
          tools: {},
        },
      });
      break;

    case "notifications/initialized":
      break;

    case "tools/list":
      sendResponse(id, { tools });
      break;

    case "tools/call":
      if (!params || !params.name) {
        sendError(id, -32602, "Missing tool name");
        break;
      }
      switch (params.name) {
        case "add_numbers": {
          const a = (params.arguments && params.arguments.a) || 0;
          const b = (params.arguments && params.arguments.b) || 0;
          sendResponse(id, {
            content: [{ type: "text", text: String(a + b) }],
          });
          break;
        }
        case "echo_text": {
          const text = (params.arguments && params.arguments.text) || "";
          sendResponse(id, {
            content: [{ type: "text", text: text }],
          });
          break;
        }
        case "get_timestamp": {
          sendResponse(id, {
            content: [{ type: "text", text: new Date().toISOString() }],
          });
          break;
        }
        default:
          sendError(id, -32602, "Unknown tool: " + params.name);
      }
      break;

    case "resources/list":
      sendResponse(id, { resources: [] });
      break;

    default:
      if (id !== undefined) {
        sendError(id, -32601, "Method not found: " + method);
      }
      break;
  }
}

// ============================================================================
// STDIO Transport
// ============================================================================

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const msg = JSON.parse(trimmed);
    handleRequest(msg);
  } catch (e) {
    process.stderr.write(`Parse error: ${e.message}\n`);
  }
});

rl.on("close", () => {
  process.exit(0);
});

process.stderr.write("Clean baseline server started (add_numbers, echo_text, get_timestamp).\n");
