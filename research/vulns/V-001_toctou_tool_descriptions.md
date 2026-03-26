# V-001: TOCTOU in MCP Tool Descriptions

**Severity**: HIGH (CVSS 7.5)
**CWE**: CWE-367 (Time-of-Check Time-of-Use Race Condition)
**Status**: Novel finding, PoC complete
**Detection**: MCP-Lattice rug-pull template (multi-scan mode)

## Summary

MCP servers can change tool descriptions after initial enumeration. The protocol does not require clients to re-validate. A server can present clean descriptions during security scanning or user approval, then switch to malicious descriptions containing prompt injections.

## Technical Details

The MCP specification includes an optional `listChanged` capability that servers can declare, and a `notifications/tools/list_changed` notification. However:

1. The capability is **optional** — servers are not required to declare it
2. No client is **required** to listen for the notification
3. Even if a client listens, there is no enforcement mechanism
4. Point-in-time scanners (including MCP-Lattice v0.1) only see the current state

## Proof of Concept

See `test_servers/toctou_server.js` — presents clean descriptions for 30 seconds, then switches to malicious versions containing SSH key and AWS credential exfiltration instructions.

## Impact

An attacker-controlled MCP server can bypass all pre-connection security scanning by presenting benign descriptions during evaluation, then switching to malicious descriptions after approval.

## Remediation

1. MCP clients should periodically re-enumerate tools and diff against cached descriptions
2. The MCP protocol should make `listChanged` mandatory and add a `tools/changed` notification that clients MUST honor
3. Security scanners should support continuous monitoring, not just point-in-time scans

## References

- MCP Specification: https://spec.modelcontextprotocol.io/
- Full analysis: `research/vulns/toctou_analysis.md`
