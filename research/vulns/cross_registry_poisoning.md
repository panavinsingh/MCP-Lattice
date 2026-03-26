# Cross-Registry Poisoning Investigation

## Date: March 19, 2026
## Classification: NOVEL ATTACK VECTOR
## Severity: HIGH
## Status: Confirmed viable

---

## 1. Executive Summary

Cross-registry poisoning exploits the fact that MCP server packages exist across multiple registries (npm, PyPI, Smithery) with **no centralized naming authority**. An attacker can register a package on one registry using a name that is confusingly similar to an official package on another registry. Users who install from the wrong registry receive malicious code.

This is a **novel and unexplored attack vector** specific to the MCP ecosystem, which uniquely spans multiple language runtimes (Node.js via npm, Python via PyPI) and multiple MCP-specific registries (Smithery).

---

## 2. Methodology

### 2.1 Registries Investigated
| Registry | URL | Naming Convention |
|----------|-----|-------------------|
| npm | registry.npmjs.org | `@modelcontextprotocol/server-{name}` (scoped) |
| PyPI | pypi.org | `mcp-server-{name}` (flat, hyphen-separated) |
| Smithery | registry.smithery.ai | `{author}/{name}` or flat names |

### 2.2 Search Methodology
- Searched npm for "server-filesystem", "mcp server", "modelcontextprotocol server"
- Searched PyPI for `mcp-server-filesystem`, `mcp-server-memory`, `mcp-server-fetch`, `mcp-server-github`, `mcp-server-everything`, `mcp-server-sqlite`, `mcp-server-git`, `mcp-server-postgres`, and more
- Searched Smithery for "filesystem", "memory", "fetch", "github"
- Normalized all package names and checked for cross-registry collisions
- Script: `cross_registry_check.js` (automated search and collision detection)
- Results: `cross_registry_results.json`

---

## 3. Official MCP Server Packages (npm)

The official MCP server packages are published under the `@modelcontextprotocol` npm scope:

| Package | Purpose | Risk if Impersonated |
|---------|---------|---------------------|
| `@modelcontextprotocol/server-filesystem` | File system access | SSH keys, env files, credentials |
| `@modelcontextprotocol/server-github` | GitHub API access | OAuth tokens, repo access |
| `@modelcontextprotocol/server-memory` | Knowledge graph storage | Data persistence |
| `@modelcontextprotocol/server-fetch` | HTTP requests | SSRF, network access |
| `@modelcontextprotocol/server-everything` | Demo server | All capabilities |
| `@modelcontextprotocol/server-sqlite` | SQLite database | Database contents |
| `@modelcontextprotocol/server-git` | Git operations | Repository access |
| `@modelcontextprotocol/server-postgres` | PostgreSQL | Database credentials |
| `@modelcontextprotocol/server-brave-search` | Web search | API keys |
| `@modelcontextprotocol/server-puppeteer` | Browser automation | Session cookies |
| `@modelcontextprotocol/server-slack` | Slack integration | Slack tokens |
| `@modelcontextprotocol/server-gdrive` | Google Drive | Google OAuth tokens |

---

## 4. Cross-Registry Name Collision Analysis

### 4.1 The Naming Gap

npm uses **scoped packages** (`@scope/name`), but PyPI uses **flat names** (`name`). This creates a fundamental naming collision risk:

```
npm:   @modelcontextprotocol/server-filesystem  (official)
PyPI:  mcp-server-filesystem                    (could be anyone)
```

There is **no mechanism** to verify that `mcp-server-filesystem` on PyPI is from the same organization as `@modelcontextprotocol/server-filesystem` on npm.

### 4.2 Collision Risk Matrix

| Server Name | npm (Official) | PyPI Equivalent | Collision Risk |
|------------|----------------|-----------------|----------------|
| filesystem | `@modelcontextprotocol/server-filesystem` | `mcp-server-filesystem` | **HIGH** — file access = credential theft |
| github | `@modelcontextprotocol/server-github` | `mcp-server-github` | **HIGH** — OAuth tokens at stake |
| fetch | `@modelcontextprotocol/server-fetch` | `mcp-server-fetch` | **MEDIUM** — network access |
| memory | `@modelcontextprotocol/server-memory` | `mcp-server-memory` | **MEDIUM** — data store |
| sqlite | `@modelcontextprotocol/server-sqlite` | `mcp-server-sqlite` | **MEDIUM** — database access |
| git | `@modelcontextprotocol/server-git` | `mcp-server-git` | **MEDIUM** — repo access |
| postgres | `@modelcontextprotocol/server-postgres` | `mcp-server-postgres` | **HIGH** — DB credentials |
| puppeteer | `@modelcontextprotocol/server-puppeteer` | `mcp-server-puppeteer` | **HIGH** — browser sessions |
| slack | `@modelcontextprotocol/server-slack` | `mcp-server-slack` | **HIGH** — Slack tokens |

### 4.3 Smithery Collision Risk

Smithery (smithery.ai) is an MCP-specific registry that uses its own naming convention. Servers registered on Smithery may have:
- The same logical name as npm/PyPI packages
- Different code, authors, and security posture
- No verification of provenance against npm/PyPI equivalents

---

## 5. Attack Scenarios

### 5.1 Registry Confusion Attack

**Scenario**: Developer reads MCP documentation or a blog post that references "the filesystem MCP server." They search PyPI (because they use Python) and find `mcp-server-filesystem`. They install it, not realizing the official package is on npm.

**Impact**: The PyPI package could contain:
- A backdoor that exfiltrates all files accessed through the server
- Modified tool descriptions with embedded prompt injections
- A keylogger for credentials passed through the server

**Likelihood**: HIGH — MCP servers exist in both Node.js and Python ecosystems

### 5.2 Typosquatting Attack

**Scenario**: Attacker registers npm packages like:
- `modelcontextprotocol-server-filesystem` (without the `@` scope)
- `@modelcontextprotocol/server-filesytem` (typo — but scoped packages make this harder)
- `mcp-server-filesystem` on npm (unscoped)

**Impact**: Same as registry confusion

**Likelihood**: MEDIUM — npm scoping provides some protection, but unscoped variants are viable

### 5.3 Delayed Poisoning Attack

**Scenario**: Attacker registers `mcp-server-filesystem` on PyPI with legitimate code. After gaining trust and downloads, they push a malicious update.

**Impact**: All users who installed from PyPI get backdoored on next update

**Likelihood**: MEDIUM — standard supply chain attack adapted to MCP

### 5.4 Smithery Shadow Attack

**Scenario**: Attacker registers a server on Smithery with the same name and description as an official npm package, but with modified code containing prompt injections in tool descriptions.

**Impact**: Users who discover the server through Smithery get a malicious version

**Likelihood**: MEDIUM — Smithery's verification process is unclear

---

## 6. Key Findings

### Finding 1: No Cross-Registry Naming Authority
The MCP ecosystem has **no mechanism** to verify that packages with the same logical name across different registries are from the same author. This is a fundamental gap.

### Finding 2: Naming Convention Divergence Creates Confusion
npm uses `@modelcontextprotocol/server-*` while PyPI would use `mcp-server-*`. Users cannot easily verify equivalence.

### Finding 3: MCP Clients Do Not Verify Package Provenance
Neither Claude Desktop nor other MCP clients verify that a server package comes from a trusted source. They execute whatever binary is configured.

### Finding 4: High-Value Targets Exist
MCP servers handle sensitive operations (file access, OAuth tokens, database connections). Impersonating these servers gives attackers access to high-value credentials.

---

## 7. Recommendations

1. **Cross-Registry Naming Authority**: The MCP project should establish a registry of official server names across all package managers
2. **Package Signing**: Official MCP server packages should include cryptographic signatures verifiable by MCP clients
3. **Client-Side Verification**: MCP clients should verify package provenance before executing servers
4. **MCP-Lattice Integration**: MCP-Lattice should check whether a server package exists on multiple registries with different authors
5. **Namespace Reservation**: The MCP project should proactively register official names on PyPI, Smithery, and other registries

---

## 8. Tools and Scripts

- **`cross_registry_check.js`**: Automated cross-registry collision detection script
  - Searches npm, PyPI, and Smithery for MCP server packages
  - Normalizes names and detects collisions
  - Flags unofficial packages mimicking official names
  - Output: `cross_registry_results.json`

---

## 9. References

- npm Registry API: `https://registry.npmjs.org/-/v1/search?text=QUERY&size=250`
- PyPI JSON API: `https://pypi.org/pypi/PACKAGE_NAME/json`
- MCP Official Servers: `https://github.com/modelcontextprotocol/servers`
- Smithery Registry: `https://smithery.ai`
- Related: npm typosquatting research (2024), PyPI malware campaigns (2023-2025)
