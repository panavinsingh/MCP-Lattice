# V-005: Transport Token Exposure via SSE

**Severity**: MEDIUM-HIGH (CVSS 7.0)
**CWE**: CWE-287 (Improper Authentication), CWE-319 (Cleartext Transmission)
**Status**: Confirmed — SSE transport exposes tokens in URLs
**Detection**: Proposed — MCP-Lattice transport audit template

## Summary

SSE-based MCP servers pass authentication tokens in URL parameters, exposing them in logs, browser history, proxy caches, and referrer headers. Some servers also bind to 0.0.0.0, exposing them to the local network.

## Impact

Authentication tokens are leaked through multiple channels, enabling session hijacking, replay attacks, and unauthorized access to MCP server functionality.

## Remediation

1. Migrate from SSE to Streamable HTTP transport (recommended by MCP spec)
2. Use HTTP headers instead of URL parameters for authentication
3. Bind to localhost (127.0.0.1) instead of 0.0.0.0

## References

- Full analysis: `research/vulns/transport_security.md`
