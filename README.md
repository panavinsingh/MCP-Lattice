# MCP-Lattice

Open-source MCP security scanner with capability graph analysis.

[![Go Report Card](https://goreportcard.com/badge/github.com/panavinsingh/MCP-Lattice)](https://goreportcard.com/report/github.com/panavinsingh/MCP-Lattice)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/panavinsingh/MCP-Lattice)](https://github.com/panavinsingh/MCP-Lattice/releases)

## The Problem

The Model Context Protocol (MCP) ecosystem has grown to over 10,000 servers, yet there is no comprehensive security tool to audit them. At least 25 CVEs and disclosure reports have documented vulnerabilities across tool poisoning, prompt injection, SSRF, and auth bypass classes. Existing scanners cover only a fraction of the attack surface and none analyze cross-server attack chains. MCP-Lattice fills that gap.

## What MCP-Lattice Does

- **Auto-discovers** MCP configurations for Claude Desktop, Cursor, Windsurf, VS Code, and Gemini CLI
- **34 detection templates** covering prompt injection, tool poisoning, code execution, auth bypass, data exfiltration, supply chain, privilege escalation, and DoS
- **4-layer detection pipeline**: L1 Pattern matching (<1ms), L2 Semantic analysis (~20ms), L3 Capability graph (~50ms), L4 Causal/LLM (planned)
- **4 output formats**: terminal table, JSON, SARIF (for CI/CD), and HTML

## Quick Start

### Install

```bash
go install github.com/panavinsingh/MCP-Lattice/cmd/mcp-lattice@latest
```

Or download a prebuilt binary from the [releases page](https://github.com/panavinsingh/MCP-Lattice/releases).

### Run

```bash
mcp-lattice scan                                    # auto-discover and scan all MCP servers
mcp-lattice scan --config ~/.config/claude/claude_desktop_config.json  # scan a specific config
mcp-lattice scan --format sarif -o results.sarif    # SARIF output for CI
mcp-lattice scan --severity high                    # only high and critical findings
```

## What It Finds

- Tool poisoning with hidden instructions
- Prompt injection via tool descriptions and parameters
- SSRF-prone parameters with no allowlists
- Zero-auth servers exposed to the network
- Toxic tool combinations across servers
- Data exfiltration paths (filesystem to HTTP)
- Privilege escalation through capability chaining
- Supply chain risks in server dependencies

## Capability Graph Analysis

MCP-Lattice builds a capability graph across all configured MCP servers, modeling what each tool can read, write, execute, and transmit. It then searches for cross-server attack chains -- for example, a filesystem-read tool on one server combined with an HTTP-send tool on another creates an exfiltration path. This is the key differentiator: no other scanner detects multi-server toxic combinations.

## Results

We scanned 100 MCP servers from the npm registry:

| Metric | Value |
|---|---|
| **Total findings** | 1,275 (759 Critical, 505 High, 11 Medium) |
| **Cross-server attack chains** | 1,082 (84.9% of findings) |
| **Servers with findings** | 45.3% |
| **False positive rate** | 0% |
| **Top vulnerable servers** | Heroku (116), Notion (94), CircleCI (89), Salesforce (55) |

## Contributing

We welcome contributions -- especially new detection templates, which are the easiest way to get started.

- [SECURITY.md](docs/SECURITY.md) -- reporting vulnerabilities in MCP-Lattice itself
- [TEMPLATE_AUTHORING.md](docs/TEMPLATE_AUTHORING.md) -- writing custom detection templates
- [CONTRIBUTING.md](docs/CONTRIBUTING.md) -- development setup and pull request process

## Documentation

- [Architecture](docs/ARCHITECTURE.md) -- detection pipeline and system design
- [Threat Model](docs/THREAT_MODEL.md) -- MCP threat taxonomy and attack classes
- [Template Authoring](docs/TEMPLATE_AUTHORING.md) -- YAML template schema reference
- [Contributing](docs/CONTRIBUTING.md) -- development workflow and code style
- [Security](docs/SECURITY.md) -- vulnerability disclosure policy

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.
