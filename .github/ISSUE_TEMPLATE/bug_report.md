---
name: Bug Report
about: Report a bug in MCP-Lattice
title: "[BUG] "
labels: bug
assignees: ''
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. Run `mcp-lattice scan ...` with the following flags: ...
2. Against a server configured as: ...
3. Observe that: ...

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include the full terminal output if possible.

## Error Output

```
Paste any error messages, stack traces, or unexpected output here.
```

## Environment

- **MCP-Lattice version**: (run `mcp-lattice version`)
- **Go version**: (run `go version`)
- **Operating system**: (e.g., macOS 14.2, Ubuntu 24.04, Windows 11)
- **Architecture**: (e.g., amd64, arm64)
- **MCP client**: (e.g., Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI)

## Configuration

If relevant, include your MCP configuration (redact any secrets, tokens, or API keys):

```json
{
  "mcpServers": {
    "example": {
      "command": "...",
      "args": ["..."]
    }
  }
}
```

## Template

If the bug is related to a specific detection template, include the template file name or content:

```yaml
# Paste template YAML here if relevant
```

## Additional Context

- Does this happen consistently or intermittently?
- Did it work in a previous version of MCP-Lattice? If so, which version?
- Are there any workarounds?
- Any other context that might help diagnose the issue.
