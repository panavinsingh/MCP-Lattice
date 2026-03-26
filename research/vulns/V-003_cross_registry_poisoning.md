# V-003: Cross-Registry Package Name Poisoning

**Severity**: HIGH (CVSS 8.2)
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Status**: Viable attack vector confirmed, no specific malicious packages found
**Detection**: Proposed — MCP-Lattice registry verification template

## Summary

The same MCP server name can exist on npm, PyPI, and Smithery with different code and authors. No cross-registry naming authority exists. Attackers can register impersonating packages on alternative registries.

## Technical Details

MCP servers are distributed across multiple package registries with no coordination:
- npm: `@modelcontextprotocol/server-filesystem`
- PyPI: `mcp-server-filesystem` (could be registered by anyone)
- Smithery: Independent listing with separate verification

Name normalization differs across registries, enabling:
- `server-filesystem` on npm vs `server_filesystem` on PyPI
- `@modelcontextprotocol/server-git` vs `mcp-server-git` (different authors)

## Impact

Users searching for MCP servers may install impersonating packages from a different registry, receiving malicious code that mimics the legitimate server's functionality while exfiltrating data.

## Remediation

1. MCP registries should implement cross-registry name reservation
2. Users should verify package authors against the official MCP GitHub organization
3. MCP-Lattice could add a registry verification template that checks package provenance

## References

- Detection script: `research/vulns/cross_registry_check.js`
- Full analysis: `research/vulns/cross_registry_poisoning.md`
