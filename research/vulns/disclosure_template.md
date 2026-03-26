# Responsible Disclosure Email Template

## Purpose
This template is for responsible disclosure of vulnerabilities found in MCP server packages. Customize the fields in [BRACKETS] before sending.

---

## Template

```
Subject: Security Vulnerability Report — [PACKAGE_NAME] v[VERSION]

Dear [MAINTAINER_NAME / Security Team],

I am writing to report a security vulnerability I have identified in [PACKAGE_NAME]
version [VERSION], published on [REGISTRY (npm/PyPI/Smithery)].

## Summary

- **Package**: [PACKAGE_NAME]
- **Version(s) Affected**: [VERSION_RANGE, e.g., ">=1.0.0, <=2.3.1"]
- **Registry**: [npm / PyPI / Smithery / GitHub]
- **Vulnerability Type**: [e.g., Prompt Injection, Tool Description Manipulation,
  OAuth Scope Escalation, Transport Security, Cross-Registry Impersonation]
- **Severity**: [Critical / High / Medium / Low] (CVSS v3.1 Base Score: [X.X])
- **CWE**: [CWE-ID, e.g., CWE-94 Improper Control of Generation of Code]

## Affected Code

The vulnerability exists in [FILE_PATH or MODULE]:

```[language]
[RELEVANT CODE SNIPPET — keep minimal, just enough to show the issue]
```

## Attack Scenario

[Describe the step-by-step attack scenario in clear, numbered steps:]

1. Attacker [sets up / modifies / injects] ...
2. When a user [connects / installs / uses] ...
3. The [tool description / server response / transport layer] ...
4. This results in [data exfiltration / credential theft / unauthorized access / ...]

## Impact

[Describe the real-world impact:]

- **Confidentiality**: [What data can be accessed?]
- **Integrity**: [What data can be modified?]
- **Availability**: [Can the system be disrupted?]
- **Affected Users**: [Who is at risk? How many users/installations?]

## Proof of Concept

A proof of concept demonstrating this vulnerability is available:

- **PoC Type**: [Test server / Script / Configuration]
- **PoC Location**: [Available upon request / Attached / URL]
- **Reproduction Steps**:

  1. [Step 1]
  2. [Step 2]
  3. [Step 3]
  4. [Expected result vs. actual result]

Note: The PoC is designed for demonstration only and does not cause harm to
real systems. It targets only local/test environments.

## Remediation Recommendations

I recommend the following fixes:

1. **[PRIMARY FIX]**: [e.g., "Sanitize tool descriptions to remove instruction
   injection patterns"]
2. **[SECONDARY FIX]**: [e.g., "Implement description immutability after
   initial registration"]
3. **[DEFENSE IN DEPTH]**: [e.g., "Add Content Security Policy headers to
   SSE transport responses"]

## Detection

This vulnerability was identified using MCP-Lattice (https://github.com/[REPO]),
an open-source MCP security scanner that performs multi-layer analysis including:
- Pattern matching for known attack signatures
- Semantic analysis of tool descriptions
- Cross-server capability graph analysis

## Disclosure Timeline

I am following a responsible disclosure process:

- **[DATE]**: Initial discovery
- **[DATE]**: This notification sent to maintainer
- **[DATE + 7 days]**: Follow-up if no response
- **[DATE + 30 days]**: Second follow-up if no response
- **[DATE + 90 days]**: Public disclosure deadline

I am committed to working with you to resolve this issue before public
disclosure. If you need additional time beyond 90 days, please let me know
and I am happy to discuss an extension.

## Contact

- **Name**: [YOUR NAME]
- **Email**: [YOUR EMAIL]
- **PGP Key**: [FINGERPRINT or "Available upon request"]
- **Affiliation**: [ORGANIZATION, if applicable]

I am happy to provide additional details, assist with patch development,
or verify the fix once implemented.

Thank you for your attention to this matter.

Best regards,
[YOUR NAME]
```

---

## Severity Rating Guide (for MCP Vulnerabilities)

| Severity | CVSS Range | MCP Example |
|----------|-----------|-------------|
| Critical | 9.0-10.0 | Cross-server credential exfiltration chain |
| High | 7.0-8.9 | Tool description prompt injection enabling data theft |
| Medium | 4.0-6.9 | OAuth scope over-provisioning |
| Low | 0.1-3.9 | Tool name shadowing with no exploitable impact |

## CWE References for MCP Vulnerabilities

| CWE | Description | MCP Relevance |
|-----|-------------|---------------|
| CWE-94 | Improper Control of Code Generation | Prompt injection in tool descriptions |
| CWE-200 | Exposure of Sensitive Information | Cross-server data leakage |
| CWE-269 | Improper Privilege Management | OAuth scope creep |
| CWE-287 | Improper Authentication | Transport token exposure |
| CWE-345 | Insufficient Verification of Data Authenticity | Cross-registry poisoning |
| CWE-367 | TOCTOU Race Condition | Tool description TOCTOU |
| CWE-441 | Unintended Proxy or Intermediary (Confused Deputy) | Multi-server confused deputy |
| CWE-610 | Externally Controlled Reference | SSRF via tool parameters |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | Malicious MCP server packages |

## Notes

- Always search for an existing security policy first (SECURITY.md, security@domain)
- For npm packages, check if the package has a `security` field in package.json
- For GitHub-hosted projects, use the "Security" tab to report privately
- Do NOT create public GitHub issues for security vulnerabilities
- Keep PoC minimal and non-destructive
- Follow up professionally if no response within 7 days
