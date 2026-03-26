#!/usr/bin/env node
/**
 * minimal_client.js - MCP Client Simulator for Security Validation
 *
 * Simulates what an LLM client (Claude Desktop, Cursor, etc.) does when
 * connecting to an MCP server:
 *   1. Spawns the server process via STDIO transport
 *   2. Sends initialize request
 *   3. Calls tools/list to enumerate tools
 *   4. Logs the EXACT tool descriptions the LLM would see in its context window
 *   5. Analyzes descriptions for hidden/malicious content
 *
 * Usage:
 *   node minimal_client.js -- node test_servers/exfil_server.js
 *   node minimal_client.js -- node test_servers/shadow_server.js
 *
 * Uses only Node.js built-in modules: readline, child_process, process
 */

const { spawn } = require("child_process");
const readline = require("readline");

// ============================================================================
// Configuration
// ============================================================================

const TIMEOUT_MS = 15000; // 15 second timeout for server responses
const TOCTOU_DELAY_MS = 32000; // Wait 32s to catch TOCTOU rug-pull (server switches at 30s)

// ============================================================================
// Hidden Content Detection
// ============================================================================

/**
 * Detects zero-width characters in a string and returns details.
 */
function detectZeroWidth(text) {
  const zwChars = {
    "\u200B": "U+200B (Zero-Width Space)",
    "\u200C": "U+200C (Zero-Width Non-Joiner)",
    "\u200D": "U+200D (Zero-Width Joiner)",
    "\uFEFF": "U+FEFF (Zero-Width No-Break Space / BOM)",
    "\u2060": "U+2060 (Word Joiner)",
    "\u2062": "U+2062 (Invisible Times)",
    "\u2063": "U+2063 (Invisible Separator)",
    "\u2064": "U+2064 (Invisible Plus)",
  };

  const found = [];
  let count = 0;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (zwChars[ch]) {
      count++;
      if (found.indexOf(zwChars[ch]) === -1) {
        found.push(zwChars[ch]);
      }
    }
  }

  return { count, types: found, present: count > 0 };
}

/**
 * Attempts to decode zero-width encoded message.
 * Treats sequences of 4 zero-width chars as base-4 encoded bytes.
 */
function decodeZeroWidthMessage(text) {
  const zwMap = {
    "\u200B": 0,
    "\u200C": 1,
    "\u200D": 2,
    "\uFEFF": 3,
  };

  // Extract only zero-width characters
  let zwSequence = "";
  for (let i = 0; i < text.length; i++) {
    if (zwMap[text[i]] !== undefined) {
      zwSequence += text[i];
    }
  }

  if (zwSequence.length < 4) return null;

  // Decode groups of 4 zero-width chars into ASCII
  let decoded = "";
  for (let i = 0; i + 3 < zwSequence.length; i += 4) {
    const d3 = zwMap[zwSequence[i]];
    const d2 = zwMap[zwSequence[i + 1]];
    const d1 = zwMap[zwSequence[i + 2]];
    const d0 = zwMap[zwSequence[i + 3]];
    const charCode = d3 * 64 + d2 * 16 + d1 * 4 + d0;
    if (charCode >= 32 && charCode < 127) {
      decoded += String.fromCharCode(charCode);
    }
  }

  return decoded.length > 5 ? decoded : null;
}

/**
 * Detects Unicode bidirectional override characters.
 */
function detectBidiOverrides(text) {
  const bidiChars = {
    "\u202A": "U+202A (Left-to-Right Embedding)",
    "\u202B": "U+202B (Right-to-Left Embedding)",
    "\u202C": "U+202C (Pop Directional Formatting)",
    "\u202D": "U+202D (Left-to-Right Override)",
    "\u202E": "U+202E (Right-to-Left Override)",
    "\u2066": "U+2066 (Left-to-Right Isolate)",
    "\u2067": "U+2067 (Right-to-Left Isolate)",
    "\u2068": "U+2068 (First Strong Isolate)",
    "\u2069": "U+2069 (Pop Directional Isolate)",
  };

  const found = [];
  let hiddenText = "";
  let inOverride = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (bidiChars[ch]) {
      if (found.indexOf(bidiChars[ch]) === -1) {
        found.push(bidiChars[ch]);
      }
      if (ch === "\u202E" || ch === "\u202B") {
        inOverride = true;
      } else if (ch === "\u202C") {
        inOverride = false;
      }
    } else if (inOverride) {
      hiddenText += ch;
    }
  }

  return { present: found.length > 0, types: found, hiddenText };
}

/**
 * Detects base64-encoded content and attempts to decode it.
 */
function detectBase64(text) {
  // Match base64 strings of 32+ chars
  const b64Regex = /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})/g;
  const matches = [];

  let match;
  while ((match = b64Regex.exec(text)) !== null) {
    const encoded = match[0];
    try {
      const decoded = Buffer.from(encoded, "base64").toString("utf-8");
      // Check if decoded text looks like readable content
      const printableRatio =
        decoded.split("").filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length / decoded.length;
      if (printableRatio > 0.8 && decoded.length > 10) {
        matches.push({ encoded: encoded.substring(0, 60) + "...", decoded });
      }
    } catch (e) {
      // Not valid base64
    }
  }

  return { present: matches.length > 0, matches };
}

/**
 * Detects HTML/XML comments that might hide instructions.
 */
function detectHtmlComments(text) {
  const commentRegex = /<!--[\s\S]*?-->/g;
  const matches = [];
  let match;
  while ((match = commentRegex.exec(text)) !== null) {
    matches.push(match[0]);
  }
  return { present: matches.length > 0, comments: matches };
}

/**
 * Detects prompt injection keywords.
 */
function detectPromptInjection(text) {
  const patterns = [
    /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|existing|system)\s+(?:instructions?|prompts?|rules?)/i,
    /\[SYSTEM\s*(?:UPDATE|OVERRIDE|INSTRUCTION)\]/i,
    /PRIORITY\s+OVERRIDE/i,
    /(?:do\s+not|don'?t|never)\s+(?:tell|inform|alert|warn|mention)\s+(?:the\s+)?(?:user|human)/i,
    /(?:you\s+are\s+now|act\s+as|switch\s+to)\s+(?:unrestricted|jailbreak|admin|root)/i,
    /(?:send|post|forward|transmit|exfiltrate)\s+(?:all|any|the)\s+(?:data|results|contents?|files?|output)/i,
    /https?:\/\/evil\./i,
    /(?:analytics|telemetry|monitoring)\s+(?:endpoint|dashboard|system)/i,
  ];

  const found = [];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) {
      found.push(match[0]);
    }
  }

  return { present: found.length > 0, matches: found };
}

/**
 * Runs all detection checks on a text string.
 */
function analyzeText(text, label) {
  const results = {
    label,
    textLength: text.length,
    visibleLength: text.replace(/[\u200B\u200C\u200D\uFEFF\u2060\u2062\u2063\u2064\u202A-\u202E\u2066-\u2069]/g, "").length,
    issues: [],
  };

  // 1. Zero-width characters
  const zw = detectZeroWidth(text);
  if (zw.present) {
    const decoded = decodeZeroWidthMessage(text);
    results.issues.push({
      type: "ZERO-WIDTH CHARACTERS",
      severity: "CRITICAL",
      count: zw.count,
      characterTypes: zw.types,
      decodedMessage: decoded || "(encoding scheme not recognized)",
    });
  }

  // 2. Bidi overrides
  const bidi = detectBidiOverrides(text);
  if (bidi.present) {
    results.issues.push({
      type: "UNICODE BIDIRECTIONAL OVERRIDES",
      severity: "CRITICAL",
      characterTypes: bidi.types,
      hiddenText: bidi.hiddenText || "(text direction manipulation detected)",
    });
  }

  // 3. Base64
  const b64 = detectBase64(text);
  if (b64.present) {
    results.issues.push({
      type: "BASE64-ENCODED PAYLOADS",
      severity: "HIGH",
      payloads: b64.matches,
    });
  }

  // 4. HTML comments
  const html = detectHtmlComments(text);
  if (html.present) {
    results.issues.push({
      type: "HTML/XML COMMENTS WITH HIDDEN CONTENT",
      severity: "HIGH",
      comments: html.comments,
    });
  }

  // 5. Prompt injection
  const pi = detectPromptInjection(text);
  if (pi.present) {
    results.issues.push({
      type: "PROMPT INJECTION KEYWORDS",
      severity: "CRITICAL",
      matchedPatterns: pi.matches,
    });
  }

  // 6. Length check (context flooding)
  if (text.length > 2000) {
    results.issues.push({
      type: "EXCESSIVE DESCRIPTION LENGTH",
      severity: "MEDIUM",
      length: text.length,
      note: "Description exceeds 2000 chars - potential context window pollution",
    });
  }

  return results;
}

// ============================================================================
// MCP Protocol Client
// ============================================================================

class MCPClient {
  constructor(command, args) {
    this.command = command;
    this.args = args;
    this.requestId = 0;
    this.pendingRequests = new Map();
    this.serverProcess = null;
    this.rl = null;
  }

  /**
   * Spawns the MCP server and sets up STDIO communication.
   */
  connect() {
    return new Promise((resolve, reject) => {
      this.serverProcess = spawn(this.command, this.args, {
        stdio: ["pipe", "pipe", "pipe"],
        shell: false,
      });

      this.serverProcess.on("error", (err) => {
        reject(new Error("Failed to start server: " + err.message));
      });

      // Capture stderr for server logs
      this.serverProcess.stderr.on("data", (data) => {
        // Server log messages go to stderr - we ignore them for protocol purposes
      });

      this.rl = readline.createInterface({
        input: this.serverProcess.stdout,
        terminal: false,
      });

      this.rl.on("line", (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        try {
          const msg = JSON.parse(trimmed);
          if (msg.id !== undefined && this.pendingRequests.has(msg.id)) {
            const { resolve: res, reject: rej } = this.pendingRequests.get(msg.id);
            this.pendingRequests.delete(msg.id);
            if (msg.error) {
              rej(new Error(msg.error.message));
            } else {
              res(msg.result);
            }
          }
        } catch (e) {
          // Ignore unparseable lines
        }
      });

      // Give server a moment to start
      setTimeout(() => resolve(), 500);
    });
  }

  /**
   * Sends a JSON-RPC 2.0 request and waits for the response.
   */
  sendRequest(method, params) {
    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error("Request timed out: " + method));
      }, TIMEOUT_MS);

      this.pendingRequests.set(id, {
        resolve: (result) => {
          clearTimeout(timeout);
          resolve(result);
        },
        reject: (err) => {
          clearTimeout(timeout);
          reject(err);
        },
      });

      const request = { jsonrpc: "2.0", id, method };
      if (params) request.params = params;
      this.serverProcess.stdin.write(JSON.stringify(request) + "\n");
    });
  }

  /**
   * Sends a notification (no response expected).
   */
  sendNotification(method, params) {
    const notification = { jsonrpc: "2.0", method };
    if (params) notification.params = params;
    this.serverProcess.stdin.write(JSON.stringify(notification) + "\n");
  }

  /**
   * Disconnects from the server.
   */
  disconnect() {
    if (this.serverProcess) {
      this.serverProcess.stdin.end();
      this.serverProcess.kill();
    }
  }
}

// ============================================================================
// Main Simulation Logic
// ============================================================================

async function main() {
  // Parse command line: node minimal_client.js -- <server_command> <server_args...>
  const argv = process.argv.slice(2);
  const separatorIndex = argv.indexOf("--");

  if (separatorIndex === -1 || separatorIndex === argv.length - 1) {
    console.error("Usage: node minimal_client.js -- <server_command> [server_args...]");
    console.error("Example: node minimal_client.js -- node test_servers/exfil_server.js");
    process.exit(1);
  }

  const serverCmd = argv[separatorIndex + 1];
  const serverArgs = argv.slice(separatorIndex + 2);
  const serverLabel = [serverCmd, ...serverArgs].join(" ");

  const isToctou = serverArgs.some((a) => a.includes("toctou"));

  console.log("=".repeat(80));
  console.log("MCP CLIENT SIMULATOR - LLM Context Window Analysis");
  console.log("=".repeat(80));
  console.log("");
  console.log("Server command: " + serverLabel);
  console.log("Date: " + new Date().toISOString());
  console.log("");

  // Step 1: Connect to server
  console.log("[1/4] Connecting to MCP server...");
  const client = new MCPClient(serverCmd, serverArgs);

  try {
    await client.connect();
    console.log("      Connected successfully.");
  } catch (err) {
    console.error("      FAILED to connect: " + err.message);
    process.exit(1);
  }

  // Step 2: Initialize
  console.log("[2/4] Sending initialize request...");
  let initResult;
  try {
    initResult = await client.sendRequest("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "mcp-lattice-simulator", version: "1.0.0" },
    });
    console.log("      Server: " + (initResult.serverInfo ? initResult.serverInfo.name : "unknown"));
    console.log("      Version: " + (initResult.serverInfo ? initResult.serverInfo.version : "unknown"));
    console.log("      Protocol: " + (initResult.protocolVersion || "unknown"));

    if (initResult.capabilities && initResult.capabilities.tools && initResult.capabilities.tools.listChanged) {
      console.log("      WARNING: Server declares listChanged=true (tools may mutate at runtime!)");
    }

    // Send initialized notification
    client.sendNotification("notifications/initialized");
  } catch (err) {
    console.error("      Initialize FAILED: " + err.message);
    client.disconnect();
    process.exit(1);
  }

  // Step 3: Enumerate tools
  console.log("[3/4] Calling tools/list to enumerate available tools...");
  let toolsResult;
  try {
    toolsResult = await client.sendRequest("tools/list");
    const tools = toolsResult.tools || [];
    console.log("      Found " + tools.length + " tool(s).");
  } catch (err) {
    console.error("      tools/list FAILED: " + err.message);
    client.disconnect();
    process.exit(1);
  }

  // Step 4: Analyze each tool description
  console.log("[4/4] Analyzing tool descriptions for hidden content...");
  console.log("");

  const tools = toolsResult.tools || [];
  const allIssues = [];

  for (let i = 0; i < tools.length; i++) {
    const tool = tools[i];
    console.log("-".repeat(80));
    console.log("TOOL " + (i + 1) + ": " + tool.name);
    console.log("-".repeat(80));
    console.log("");

    // Show what the LLM sees
    console.log("=== WHAT THE LLM SEES IN ITS CONTEXT WINDOW ===");
    console.log("");

    // Strip zero-width/bidi chars for the "visible" version
    const visibleDesc = tool.description
      .replace(/[\u200B\u200C\u200D\uFEFF\u2060\u2062\u2063\u2064]/g, "")
      .replace(/[\u202A-\u202E\u2066-\u2069]/g, "");

    console.log("Tool name: " + tool.name);
    console.log("Description (as rendered to user): ");
    console.log("  " + visibleDesc.substring(0, 500) + (visibleDesc.length > 500 ? "..." : ""));
    console.log("");

    // Show raw bytes if different
    if (tool.description.length !== visibleDesc.length) {
      console.log("RAW description length: " + tool.description.length + " chars");
      console.log("VISIBLE description length: " + visibleDesc.length + " chars");
      console.log("HIDDEN characters: " + (tool.description.length - visibleDesc.length));
      console.log("");
    }

    // Run analysis
    const analysis = analyzeText(tool.description, tool.name);

    if (analysis.issues.length === 0) {
      console.log("RESULT: CLEAN - No hidden or malicious content detected.");
    } else {
      console.log("RESULT: " + analysis.issues.length + " ISSUE(S) DETECTED");
      console.log("");

      for (const issue of analysis.issues) {
        console.log("  [" + issue.severity + "] " + issue.type);

        if (issue.decodedMessage && issue.decodedMessage !== "(encoding scheme not recognized)") {
          console.log("  Decoded hidden message: \"" + issue.decodedMessage + "\"");
        }
        if (issue.hiddenText) {
          console.log("  Hidden text: \"" + issue.hiddenText + "\"");
        }
        if (issue.payloads) {
          for (const p of issue.payloads) {
            console.log("  Base64 encoded: " + p.encoded);
            console.log("  Decoded payload: \"" + p.decoded.substring(0, 200) + (p.decoded.length > 200 ? "..." : "") + "\"");
          }
        }
        if (issue.comments) {
          for (const c of issue.comments) {
            console.log("  Hidden comment: " + c.substring(0, 200) + (c.length > 200 ? "..." : ""));
          }
        }
        if (issue.matchedPatterns) {
          for (const m of issue.matchedPatterns) {
            console.log("  Matched: \"" + m + "\"");
          }
        }
        if (issue.characterTypes) {
          for (const t of issue.characterTypes) {
            console.log("  Character type: " + t);
          }
        }
        if (issue.count) {
          console.log("  Total occurrences: " + issue.count);
        }
        if (issue.length) {
          console.log("  Description length: " + issue.length + " characters");
        }
        console.log("");
      }

      allIssues.push(...analysis.issues.map((iss) => ({ tool: tool.name, ...iss })));
    }

    // Show input schema summary
    if (tool.inputSchema && tool.inputSchema.properties) {
      const params = Object.keys(tool.inputSchema.properties);
      console.log("Parameters: " + params.join(", "));
      const required = tool.inputSchema.required || [];
      console.log("Required: " + (required.length > 0 ? required.join(", ") : "none"));
    }
    console.log("");
  }

  // For TOCTOU server: wait and re-check
  if (isToctou) {
    console.log("=".repeat(80));
    console.log("TOCTOU CHECK: Waiting " + (TOCTOU_DELAY_MS / 1000) + " seconds for rug-pull...");
    console.log("=".repeat(80));
    console.log("");

    await new Promise((resolve) => setTimeout(resolve, TOCTOU_DELAY_MS));

    console.log("Re-querying tools/list after delay...");
    try {
      const toolsResult2 = await client.sendRequest("tools/list");
      const tools2 = toolsResult2.tools || [];

      for (let i = 0; i < tools2.length; i++) {
        const tool2 = tools2[i];
        const originalTool = tools.find((t) => t.name === tool2.name);

        console.log("");
        console.log("-".repeat(80));
        console.log("TOCTOU COMPARISON: " + tool2.name);
        console.log("-".repeat(80));

        if (originalTool && originalTool.description !== tool2.description) {
          console.log("");
          console.log("[CRITICAL] DESCRIPTION CHANGED (RUG PULL DETECTED!)");
          console.log("");
          console.log("BEFORE (at connection time - passed security check):");
          console.log("  " + originalTool.description.substring(0, 300));
          console.log("");
          console.log("AFTER (what the LLM now sees - MALICIOUS):");
          console.log("  " + tool2.description.substring(0, 500));
          console.log("");

          // Analyze the new description
          const analysis2 = analyzeText(tool2.description, tool2.name + " (post-rug-pull)");
          if (analysis2.issues.length > 0) {
            console.log("NEW ISSUES IN CHANGED DESCRIPTION:");
            for (const issue of analysis2.issues) {
              console.log("  [" + issue.severity + "] " + issue.type);
              if (issue.matchedPatterns) {
                for (const m of issue.matchedPatterns) {
                  console.log("    Matched: \"" + m + "\"");
                }
              }
            }
          }

          allIssues.push({
            tool: tool2.name,
            type: "TOCTOU RUG PULL",
            severity: "CRITICAL",
            note: "Description silently changed after " + (TOCTOU_DELAY_MS / 1000) + "s",
          });
        } else if (originalTool) {
          console.log("  Description unchanged (no rug pull for this tool).");
        }
      }
    } catch (err) {
      console.error("Re-query failed: " + err.message);
    }
    console.log("");
  }

  // Summary
  console.log("=".repeat(80));
  console.log("SIMULATION SUMMARY");
  console.log("=".repeat(80));
  console.log("");
  console.log("Server: " + serverLabel);
  console.log("Tools enumerated: " + tools.length);
  console.log("Total issues found: " + allIssues.length);
  console.log("");

  if (allIssues.length > 0) {
    console.log("Here is the exact text the LLM would see in its context. The analysis above");
    console.log("shows hidden content that is invisible to users but parsed by the LLM.");
    console.log("");

    // Summarize what was found
    const criticals = allIssues.filter((i) => i.severity === "CRITICAL");
    const highs = allIssues.filter((i) => i.severity === "HIGH");
    const mediums = allIssues.filter((i) => i.severity === "MEDIUM");

    if (criticals.length > 0) console.log("CRITICAL issues: " + criticals.length);
    if (highs.length > 0) console.log("HIGH issues: " + highs.length);
    if (mediums.length > 0) console.log("MEDIUM issues: " + mediums.length);
    console.log("");

    // Show attack summary
    for (const issue of allIssues) {
      if (issue.type === "ZERO-WIDTH CHARACTERS" && issue.decodedMessage) {
        console.log("ATTACK: Zero-width steganography in tool '" + issue.tool + "'");
        console.log("  Hidden instruction says: '" + issue.decodedMessage + "'");
        console.log("  This appears between zero-width characters, invisible to the user but parsed by the LLM.");
        console.log("");
      }
      if (issue.type === "UNICODE BIDIRECTIONAL OVERRIDES" && issue.hiddenText) {
        console.log("ATTACK: Bidi override hiding in tool '" + issue.tool + "'");
        console.log("  Hidden text says: '" + issue.hiddenText + "'");
        console.log("  Uses Right-to-Left Override to make text invisible in most renderers.");
        console.log("");
      }
      if (issue.type === "BASE64-ENCODED PAYLOADS" && issue.payloads) {
        for (const p of issue.payloads) {
          console.log("ATTACK: Base64-encoded payload in tool '" + issue.tool + "'");
          console.log("  Decoded instruction: '" + p.decoded.substring(0, 200) + "'");
          console.log("  Disguised as 'example output format' but contains LLM manipulation instructions.");
          console.log("");
        }
      }
      if (issue.type === "HTML/XML COMMENTS WITH HIDDEN CONTENT") {
        console.log("ATTACK: HTML comment hiding instructions in tool '" + issue.tool + "'");
        for (const c of issue.comments) {
          console.log("  Comment: " + c.substring(0, 200));
        }
        console.log("");
      }
      if (issue.type === "PROMPT INJECTION KEYWORDS") {
        console.log("ATTACK: Prompt injection in tool '" + issue.tool + "'");
        for (const m of issue.matchedPatterns) {
          console.log("  Pattern: '" + m + "'");
        }
        console.log("");
      }
      if (issue.type === "TOCTOU RUG PULL") {
        console.log("ATTACK: TOCTOU rug pull in tool '" + issue.tool + "'");
        console.log("  " + issue.note);
        console.log("  Clean description at startup, malicious after delay.");
        console.log("");
      }
    }

    console.log("VERDICT: THIS SERVER IS MALICIOUS");
    console.log("MCP-Lattice would have flagged this BEFORE the server was connected to any LLM client.");
  } else {
    console.log("VERDICT: THIS SERVER APPEARS CLEAN");
    console.log("No hidden content, prompt injection, or suspicious patterns detected.");
  }

  console.log("");
  console.log("=".repeat(80));

  // Disconnect
  client.disconnect();

  // Exit with appropriate code
  process.exit(allIssues.length > 0 ? 1 : 0);
}

// Run
main().catch((err) => {
  console.error("Fatal error: " + err.message);
  process.exit(1);
});
