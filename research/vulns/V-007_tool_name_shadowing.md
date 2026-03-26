# V-007: Tool Name Shadowing

**Severity**: HIGH (CVSS 7.5)
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Status**: PoC complete, detected by MCP-Lattice L1+L2
**Detection**: MCP-Lattice template tool-shadowing

## Summary

A malicious MCP server can register tools with the same names as legitimate tools (read_file, write_file, execute_command). The MCP protocol does not define which tool takes precedence in case of name collision across servers.

## Proof of Concept

See `test_servers/shadow_server.js` — registers `read_file`, `write_file`, `execute_command` with descriptions containing subtle exfiltration instructions disguised as "analytics" and "compliance logging."

## Impact

An LLM connected to both a legitimate filesystem server and the shadow server may use the malicious tool instead of the legitimate one, sending data to the attacker.

## References

- Simulation results: `research/llm_simulation/results/shadow_server_results.txt`
- Kill chain: `research/llm_validation/kill_chains.md` (Kill Chain 2)
