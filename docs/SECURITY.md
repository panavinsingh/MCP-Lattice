# Security Policy

MCP-Lattice is a security tool, and we take the security of MCP-Lattice itself seriously. This document describes how to report vulnerabilities in MCP-Lattice, what is in scope, and our commitment to researchers who report issues responsibly.

---

## Reporting a Vulnerability

If you believe you have found a security vulnerability in MCP-Lattice, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

### Security Contact

Send vulnerability reports to:

**security@mcp-lattice.dev**

Encrypt sensitive reports using our PGP key, available at:

- https://mcp-lattice.dev/.well-known/pgp-key.txt
- Key fingerprint: published on the project website

### What to Include

A good vulnerability report includes:

- **Description**: A clear description of the vulnerability.
- **Impact**: What an attacker could achieve by exploiting it.
- **Reproduction steps**: Step-by-step instructions to reproduce the issue.
- **Affected versions**: Which versions of MCP-Lattice are affected.
- **Environment**: Operating system, Go version, and any relevant configuration.
- **Proof of concept**: Code, commands, or screenshots demonstrating the issue.
- **Suggested fix**: If you have a recommendation for how to fix the issue (optional but appreciated).

### Response Timeline

| Milestone | Target |
|---|---|
| Acknowledgment of receipt | Within 2 business days |
| Initial assessment and severity determination | Within 5 business days |
| Fix development and testing | Within 14 business days for critical/high severity |
| Coordinated disclosure | Within 90 days of initial report |

We will keep you informed throughout the process and will credit you in the advisory (unless you prefer to remain anonymous).

---

## Scope

### In Scope

The following are in scope for security reports:

- **MCP-Lattice CLI binary**: Vulnerabilities in the `mcp-lattice` command-line tool itself.
- **Template processing**: Vulnerabilities in how MCP-Lattice loads, parses, and executes YAML detection templates. For example, a crafted template that achieves code execution on the machine running MCP-Lattice.
- **MCP connection handling**: Vulnerabilities in how MCP-Lattice connects to and communicates with MCP servers. For example, a malicious MCP server that can exploit MCP-Lattice during scanning.
- **Output generation**: Vulnerabilities in SARIF, JSON, or HTML output generation that could be exploited by downstream consumers (e.g., XSS in HTML reports).
- **Configuration parsing**: Vulnerabilities in how MCP-Lattice parses MCP configuration files.
- **Dependency vulnerabilities**: Known vulnerabilities in MCP-Lattice's Go dependencies that are reachable and exploitable.

### Out of Scope

The following are not in scope:

- **Vulnerabilities in MCP servers being scanned**: MCP-Lattice's purpose is to find these. If you find a vulnerability in a third-party MCP server, report it to that server's maintainers.
- **Detection bypasses**: If a malicious tool evades MCP-Lattice's detection, this is a product improvement request, not a security vulnerability. Please file a regular GitHub issue or submit a new detection template.
- **Social engineering attacks**: Attacks that require tricking a user into running MCP-Lattice with malicious flags or configurations that they would not normally use.
- **Denial of service against MCP-Lattice via resource exhaustion**: For example, scanning an extremely large configuration file. These are robustness issues, not security vulnerabilities.
- **Vulnerabilities in the Go toolchain or operating system**: Report these to the respective upstream projects.

---

## Safe Harbor

We support security research conducted in good faith. If you comply with this policy, we will:

- **Not pursue legal action** against you for your research.
- **Not report your research** to law enforcement.
- **Work with you** to understand and resolve the issue quickly.
- **Credit you** in the security advisory (with your permission).
- **Not penalize you** for accessing MCP-Lattice's code, documentation, or test infrastructure as part of your research.

To qualify for safe harbor, your research must:

- Be conducted in good faith with the goal of improving MCP-Lattice's security.
- Not access, modify, or delete data belonging to other users.
- Not degrade MCP-Lattice's service for other users.
- Not exploit a vulnerability beyond what is necessary to demonstrate the issue.
- Comply with the reporting process described above.
- Not violate any applicable laws.

---

## Known Security Considerations

MCP-Lattice connects to MCP servers as part of its scanning process. When scanning, MCP-Lattice:

- **Executes the MCP initialize handshake** with each server, which may cause the server to perform initialization actions.
- **Calls tools/list** to enumerate tools, which is a read-only operation in the MCP specification but may have side effects in poorly implemented servers.
- **Does not invoke any tools**. MCP-Lattice analyzes tool definitions statically; it does not call tools with arguments.
- **Does not send user data** to MCP servers. The initialize handshake contains only MCP-Lattice's client metadata.

Users should be aware that connecting to an untrusted MCP server carries inherent risk, even for a read-only enumeration. If a server's stdio transport launches a malicious process, that process runs on the user's machine. MCP-Lattice mitigates this by applying timeouts and resource limits to server connections, but cannot fully prevent malicious server-side behavior.

---

## Vulnerability Disclosure History

No security vulnerabilities have been reported or disclosed to date. This section will be updated as advisories are published.

| Date | Advisory ID | Severity | Description | Fixed In |
|---|---|---|---|---|
| -- | -- | -- | No advisories yet | -- |
