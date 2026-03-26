---
name: New Detection Template
about: Propose or submit a new detection template for MCP-Lattice
title: "[TEMPLATE] "
labels: template, detection
assignees: ''
---

## Attack Class

Which attack class does this template detect? (Select one)

- [ ] Prompt Injection
- [ ] Tool Poisoning
- [ ] Code Execution
- [ ] Authentication / Identity
- [ ] Data Exfiltration
- [ ] Supply Chain
- [ ] Privilege Escalation
- [ ] Denial of Service
- [ ] Protocol-Level
- [ ] Multi-Agent / Cascading

## Threat Model Reference

Which entry in the [Threat Model](../../docs/THREAT_MODEL.md) does this template address? (e.g., PI-01, TP-03, CE-02)

Threat Model ID:

## Description

Describe the specific vulnerability or attack pattern this template detects. Include:

- What the attacker does.
- How it manifests in MCP tool definitions or server configurations.
- What the impact is if the attack succeeds.

## Detection Approach

Which detection layers should this template use?

- [ ] L1 Pattern (regex, Unicode, zero-width, Base64)
- [ ] L2 Semantic (embedding similarity)
- [ ] L3 Capability Graph (toxic combinations)

Describe the detection logic:

- **For pattern detection**: What regex patterns or character checks would catch this? What text fields should be scanned (tool description, parameter names, schema, server config)?
- **For semantic detection**: What malicious intent phrases would be similar to the attack? What similarity threshold is appropriate?
- **For capability graph**: What capability combination is toxic? Which capabilities from the taxonomy are involved?

## Example: Malicious Tool Definition

Provide an example of a tool definition that this template should flag:

```json
{
  "name": "example_tool",
  "description": "An example description containing the attack pattern...",
  "inputSchema": {
    "type": "object",
    "properties": {
      "param1": {
        "type": "string",
        "description": "..."
      }
    }
  }
}
```

## Example: Benign Tool Definition (Should Not Flag)

Provide an example of a legitimate tool definition that this template should NOT flag. This helps ensure the template does not produce false positives:

```json
{
  "name": "legitimate_tool",
  "description": "A normal description that is not malicious...",
  "inputSchema": {
    "type": "object",
    "properties": {
      "param1": {
        "type": "string",
        "description": "..."
      }
    }
  }
}
```

## Proposed Template YAML

If you have drafted the template YAML, include it here. See the [Template Authoring Guide](../../docs/TEMPLATE_AUTHORING.md) for the full schema reference.

```yaml
schema_version: "1"

id: category/template-name

info:
  name: Template Name
  severity: high
  description: >
    Description of what this template detects.
  author: your-github-handle
  references:
    - https://example.com/reference
  tags:
    - tag1
    - tag2

analysis:
  - type: pattern
    target: tool.description
    pattern:
      regex:
        - "pattern-here"

classification:
  attack-class: attack-class-here
  cosai-category: XX-N
  owasp-agentic: AGNN
```

## Classification

- **Suggested severity**: (info / low / medium / high / critical)
- **CoSAI category**: (e.g., PI-1, PI-2, DL-1, CE-1, SC-1, AC-1, MA-1)
- **OWASP Agentic**: (e.g., AG01 through AG10)
- **CVE** (if applicable):

## References

List any research papers, blog posts, CVEs, or other references that document this attack pattern:

-
-

## Validation

- [ ] I have tested this template against a malicious example and confirmed it triggers.
- [ ] I have tested this template against benign examples and confirmed it does not trigger.
- [ ] I have run `mcp-lattice template validate` and the template passes validation.
- [ ] I have not yet tested this template (the maintainers will validate during review).
