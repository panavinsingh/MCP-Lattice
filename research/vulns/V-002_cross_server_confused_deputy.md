# V-002: Cross-Server Confused Deputy Attack

**Severity**: CRITICAL (CVSS 9.1)
**CWE**: CWE-441 (Unintended Proxy or Intermediary / Confused Deputy)
**Status**: Confirmed, 110+ findings via MCP-Lattice capability graph
**Detection**: MCP-Lattice Layer 3 capability graph analysis

## Summary

When multiple MCP servers are connected to a single LLM client, the LLM can be manipulated into reading sensitive data from one server and exfiltrating it through another. The attack is emergent — no single server is malicious, and no per-server scanner detects the risk.

## Technical Details

MCP-Lattice's capability graph models the deployment as G = (V, E) where:
- V = tools from ALL servers, annotated with inferred capabilities
- E = potential data flows between tools

The graph reveals toxic combinations: {filesystem_read, network_access} → exfiltration chain.

In our 3-server test (filesystem + memory + everything), MCP-Lattice detected:
- 38 filesystem-network exfiltration chain findings
- 36 credential access chain findings
- 36 privilege escalation findings
- 110+ total cross-server findings

## Proof of Concept

Configure Claude Desktop or Cursor with:
1. `@modelcontextprotocol/server-filesystem` (reads files)
2. `@modelcontextprotocol/server-memory` (stores data)
3. Any server with HTTP capability (sends data externally)

A prompt injection in any tool description can instruct the LLM to: read ~/.ssh/id_rsa → store in memory → send via HTTP.

## Impact

This is a fundamental architectural vulnerability in the MCP trust model. Every multi-server MCP deployment is potentially affected.

## Remediation

1. Implement capability-based access control per server
2. Use MCP-Lattice to identify toxic combinations before deployment
3. Apply behavioral confinement (restrict data flow between server capabilities)

## References

- Full analysis: `research/vulns/confused_deputy.md`
- MCP-Lattice capability graph: `internal/graph/capability_graph.go`
