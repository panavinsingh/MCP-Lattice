# V-004: OAuth Scope Over-Provisioning

**Severity**: MEDIUM (CVSS 6.5)
**CWE**: CWE-269 (Improper Privilege Management)
**Status**: Confirmed for @modelcontextprotocol/server-github
**Detection**: Proposed — MCP-Lattice OAuth scope auditing template

## Summary

MCP servers that use OAuth request or use tokens with scopes far broader than their documented capabilities require. The GitHub MCP server requests the `repo` scope, which grants delete, secrets, and admin access when only read/write is needed.

## Impact

A compromised or malicious MCP server with an over-provisioned OAuth token can perform actions far beyond its intended scope, including deleting repositories, accessing secrets, and modifying admin settings.

## Remediation

1. MCP servers should request minimal OAuth scopes
2. Users should review requested scopes before granting access
3. MCP clients should display scope information during server connection

## References

- Full analysis: `research/vulns/oauth_scope_creep.md`
