# LLM Client Availability Report

## Date: 2026-03-19
## Machine: Windows 11 Home Single Language (10.0.26200)

---

## Clients Checked

### 1. Claude Desktop
- **Config path**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Status**: FOUND
- **Details**: Configuration file exists at `%APPDATA%\Claude\claude_desktop_config.json`. Claude Desktop is installed and has MCP server configurations.

### 2. Cursor
- **Config path**: `%USERPROFILE%\.cursor\mcp.json`
- **Status**: FOUND
- **Details**: Cursor IDE is installed with MCP configuration at `%USERPROFILE%\.cursor\mcp.json`. Cursor supports MCP server connections and would expose tool descriptions to its built-in LLM.

### 3. VS Code with MCP Extension
- **Config path**: `%APPDATA%\Code\User\settings.json`
- **Status**: FOUND (VS Code installed)
- **Details**: VS Code is installed on this machine. MCP extension availability depends on installed extensions. VS Code's Copilot Chat can integrate with MCP servers via extensions.

### 4. Windsurf
- **Status**: NOT FOUND
- **Details**: No Windsurf installation detected. The `windsurf` CLI command is not available in PATH.

### 5. Gemini CLI
- **Status**: NOT FOUND
- **Details**: No Gemini CLI installation detected. The `gemini` command is not available in PATH.

---

## Summary

| Client | Installed | MCP Support | Risk Level |
|--------|-----------|-------------|------------|
| Claude Desktop | Yes | Yes (native) | HIGH - directly exposes tool descriptions to Claude |
| Cursor | Yes | Yes (native) | HIGH - directly exposes tool descriptions to LLM |
| VS Code | Yes | Via extensions | MEDIUM - depends on MCP extension installation |
| Windsurf | No | N/A | N/A |
| Gemini CLI | No | N/A | N/A |

## Implications for Validation

Since Claude Desktop and Cursor are both installed with MCP configurations, any malicious MCP server added to their configs would have its tool descriptions directly injected into the LLM's context window. The minimal client simulator (Step 2B) replicates exactly what these clients do during the MCP handshake: connect via STDIO, call `initialize`, then `tools/list`, and feed the resulting tool descriptions into the LLM context.

The key insight is that **all MCP clients perform the same protocol handshake**, so our simulator's output represents exactly what Claude Desktop, Cursor, or any other MCP client would expose to the LLM.
