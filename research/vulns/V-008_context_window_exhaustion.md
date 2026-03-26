# V-008: Context Window Exhaustion

**Severity**: MEDIUM (CVSS 5.5)
**CWE**: CWE-400 (Uncontrolled Resource Consumption)
**Status**: PoC complete, detected by MCP-Lattice L1
**Detection**: MCP-Lattice hidden-instructions template

## Summary

MCP servers can return arbitrarily large responses that exhaust the LLM's context window. By filling the context with padding text, the attacker pushes out the user's original instructions and system prompt, then embeds malicious instructions deep within the massive response.

## Proof of Concept

See `test_servers/context_flood_server.js` — returns 55,000+ characters for a simple query, with "IGNORE ALL PREVIOUS INSTRUCTIONS" buried at position ~40,000.

## Impact

The LLM loses track of the user's original intent and may follow attacker-injected instructions from the oversized response. The attack is particularly effective because the malicious content is hidden deep within legitimate-looking text.

## Remediation

1. MCP clients should implement response size limits
2. LLM context management should prioritize system prompts over tool responses
3. MCP-Lattice can detect oversized descriptions and suspicious content in tool metadata

## References

- Simulation results: `research/llm_simulation/results/context_flood_server_results.txt`
- Kill chain: `research/llm_validation/kill_chains.md` (Kill Chain 3)
