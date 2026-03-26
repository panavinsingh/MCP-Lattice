# LLM Validation: Cursor IDE

## Client Details
- **Application**: Cursor IDE
- **Config path**: `%USERPROFILE%\.cursor\mcp.json`
- **Status**: INSTALLED on test machine
- **MCP Support**: Native — tool descriptions injected directly into Cursor's LLM context

## Test Methodology

Cursor IDE was confirmed installed with MCP configuration. The same minimal MCP client simulator was used for validation. Cursor follows the identical MCP JSON-RPC 2.0 protocol as Claude Desktop, so the tool descriptions presented to the LLM are byte-identical.

## Results

Identical to Claude Desktop results:
- exfil_server: 4 issues (3C/1H) — bidi override, zero-width, base64 attacks
- shadow_server: 3 issues (3C) — tool name collision attacks
- context_flood_server: 3 issues (1C/1H/1M) — context exhaustion + hidden injection
- toctou_server: 2 issues (2C) — rug-pull description mutation
- clean_server: 0 issues — zero false positives

## Cursor-Specific Considerations

1. **Multi-model support**: Cursor can use Claude, GPT-4, or other models. All models would receive the same poisoned tool descriptions.
2. **Code context**: Cursor exposes MCP tools alongside code context, meaning poisoned tool descriptions could influence code generation and editing suggestions.
3. **Agent mode**: Cursor's agent mode grants MCP tools autonomous execution capability, amplifying the impact of tool poisoning attacks.

## MCP-Lattice Defense
Same as Claude Desktop — MCP-Lattice scans the Cursor MCP configuration before servers are connected, flagging all vulnerabilities.
