# MCP-Lattice Architecture

This document describes the internal architecture of MCP-Lattice, the design rationale behind each component, and how data flows through the system.

---

## Four-Layer Detection Model

MCP-Lattice applies detection in progressive layers. Each successive layer is more expensive but catches more subtle attacks. Findings from earlier layers are confirmed (or dismissed) by later layers, which reduces false positives.

| Layer | Name | Latency | What It Does |
|---|---|---|---|
| L1 | Pattern | <1ms per tool | Regex matching, Unicode tag detection, zero-width character scanning, Base64 payload detection |
| L2 | Semantic | ~20ms per tool | Embeds tool descriptions and parameters, then computes cosine similarity against a corpus of known malicious intents |
| L3 | Capability Graph | ~50ms per scan | Builds a directed graph of capabilities across all tools and servers, then searches for toxic combinations (e.g., read_file + send_http) |
| L4 | Causal / LLM | Async (planned) | Uses an LLM to reason about novel attack chains that static analysis cannot detect |

### False Positive Management

A finding's confidence level is determined by how many layers flag it:

- **L1 only** -> `low` confidence. Reported but may be noisy.
- **L1 + L2** -> `high` confidence. Pattern and semantic analysis agree.
- **L1 + L2 + L3** -> `critical` confidence. An exploitable attack path exists.
- **L2 only** (no pattern match) -> `medium` confidence. Semantic-only findings may indicate novel attacks missed by patterns.
- **L3 only** -> `medium` confidence. Toxic combination exists but individual tools appear benign.

This multi-layer confirmation strategy keeps MCP-Lattice's false positive rate low while maintaining high recall for genuine threats.

---

## Core Engine Design

```
 +------------------------------------------------------------------+
 |                        MCP-Lattice Core Engine                        |
 +------------------------------------------------------------------+
 |                                                                    |
 |  +--------------+    +-------------------+    +-----------------+ |
 |  |   Config     |--->|   MCP Connection  |--->|   Template      | |
 |  |   Discovery  |    |   Pool            |    |   Loader        | |
 |  +--------------+    +-------------------+    +-----------------+ |
 |        |                      |                       |           |
 |        v                      v                       v           |
 |  +------------------------------------------------------------+  |
 |  |                  Detection Pipeline                         |  |
 |  |                                                              |  |
 |  |  +----------+   +----------+   +------------------+         |  |
 |  |  | L1       |-->| L2       |-->| L3               |         |  |
 |  |  | Pattern  |   | Semantic |   | Capability Graph |         |  |
 |  |  +----------+   +----------+   +------------------+         |  |
 |  |                                                              |  |
 |  +------------------------------------------------------------+  |
 |                           |                                       |
 |                           v                                       |
 |                  +-----------------+                              |
 |                  |    Result       |                              |
 |                  |    Aggregation  |                              |
 |                  +-----------------+                              |
 |                           |                                       |
 |                           v                                       |
 |                  +-----------------+                              |
 |                  |    Output       |                              |
 |                  |    (Reporter)   |                              |
 |                  +-----------------+                              |
 |                                                                    |
 +------------------------------------------------------------------+
```

---

## Component Descriptions

### Discovery (`internal/discovery/`)

Responsible for locating MCP configuration files on the host system. Searches platform-specific paths for:

| Client | Platform | Default Config Path |
|---|---|---|
| Claude Desktop | macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop | Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop | Linux | `~/.config/claude/claude_desktop_config.json` |
| Cursor | All | `~/.cursor/mcp.json` |
| Windsurf | All | `~/.windsurf/mcp.json` and `~/.codeium/windsurf/mcp_config.json` |
| VS Code | All | `~/.vscode/mcp.json` and workspace `.vscode/mcp.json` |
| Gemini CLI | All | `~/.gemini/settings.json` |

The discovery module returns a normalized `[]ServerConfig` regardless of which client format the file uses. It also accepts explicit paths via `--config` and `--server` flags.

### Connector (`internal/connector/`)

Manages connections to MCP servers over supported transports:

- **stdio**: Launches the server process and communicates over stdin/stdout using JSON-RPC 2.0.
- **SSE (Server-Sent Events)**: Connects to HTTP-based MCP servers that use SSE for streaming.
- **Streamable HTTP**: Connects to servers using the newer streamable HTTP transport.

The connector pool manages concurrent connections, enforces timeouts, and handles graceful shutdown. Each connection performs the MCP `initialize` handshake and then calls `tools/list` to enumerate available tools.

Key design decisions:
- Connections are pooled per server to avoid repeated handshakes during multi-template scans.
- A circuit breaker prevents retrying servers that repeatedly fail to connect.
- The connector captures the full `tools/list` response including tool names, descriptions, and input schemas for analysis.

### Scanner (`internal/scanner/`)

Orchestrates the scan lifecycle:

1. Calls Discovery to find configurations.
2. Calls Connector to connect to each server and enumerate tools.
3. Loads templates via the Template Loader.
4. For each tool on each server, runs the Detection Pipeline.
5. Passes raw findings to Result Aggregation.
6. Passes aggregated findings to the Reporter.

The scanner runs servers concurrently with a configurable parallelism limit (default: number of CPUs).

### Detection (`internal/detection/`)

Implements the three active detection layers:

**L1 Pattern Engine** (`detection/pattern.go`)
- Compiles regex patterns from templates at load time.
- Scans tool descriptions, parameter descriptions, and schema fields.
- Detects Unicode directional tags (U+200E, U+200F, U+202A-U+202E, U+2066-U+2069).
- Detects zero-width characters (U+200B, U+200C, U+200D, U+FEFF).
- Optionally decodes and scans Base64-encoded content found in descriptions.

**L2 Semantic Engine** (`detection/semantic.go`)
- Loads an ONNX model (default: `all-MiniLM-L6-v2`) for sentence embedding.
- Pre-computes embeddings for malicious intent phrases defined in templates.
- At scan time, embeds the target text and computes cosine similarity against each intent.
- If similarity exceeds the template-defined threshold, the finding is flagged.
- The ONNX runtime is initialized once and shared across all scans.

**L3 Capability Graph Engine** (`detection/graph.go`)
- Assigns capability tags to each tool based on its name, description, and parameter schema (e.g., `reads_filesystem`, `sends_http`, `executes_code`).
- Builds a directed graph where nodes are tools and edges represent data flow between capabilities.
- Searches for toxic combinations defined in templates (e.g., `reads_filesystem` + `sends_http` = exfiltration path).
- Reports the full chain when a toxic combination is detected.

### Graph (`internal/graph/`)

Provides the capability graph data structure and algorithms:

- `CapabilityGraph`: Adjacency-list directed graph with capability-annotated nodes.
- `ToxicPathFinder`: BFS/DFS search for paths that traverse a specified set of capabilities.
- `CapabilityTagger`: Heuristic classifier that assigns capability tags to tools based on keywords in names, descriptions, and parameter names.

The capability taxonomy used for tagging:

| Capability | Description | Keyword Examples |
|---|---|---|
| `reads_filesystem` | Can read local files | read_file, get_contents, load |
| `writes_filesystem` | Can write or modify local files | write_file, save, create_file |
| `reads_credentials` | Can access secrets or credentials | ssh, password, token, key, secret |
| `sends_http` | Can make outbound HTTP requests | fetch, request, curl, http, url |
| `accesses_network` | Can access network resources | connect, socket, dns, ping |
| `executes_code` | Can execute arbitrary code or commands | exec, run, shell, eval, command |
| `reads_env` | Can read environment variables | env, environment, getenv |
| `writes_external` | Can write to external services | send, post, publish, upload |
| `database_access` | Can query or modify databases | query, sql, select, insert, db |
| `email_send` | Can send emails | email, mail, send_mail, smtp |

### Templates (`internal/templates/`)

Loads and validates YAML detection templates. Templates are loaded from:

1. Embedded default templates (compiled into the binary).
2. User-specified template directory (`--templates` flag).

The loader validates each template against the schema (version 1) and returns a typed `[]Template` slice. Invalid templates are logged as warnings and skipped.

### Reporter (`internal/reporter/`)

Formats scan results into the requested output format:

- **Table**: Human-readable terminal output with color-coded severity.
- **JSON**: Machine-readable JSON array of findings.
- **SARIF**: Static Analysis Results Interchange Format v2.1.0, compatible with GitHub Code Scanning and GitLab SAST.
- **HTML**: Self-contained HTML report with sortable tables and severity charts.

---

## Technology Choices and Rationale

| Choice | Rationale |
|---|---|
| **Go** | Single static binary with no runtime dependencies. Fast startup. Strong concurrency primitives for parallel scanning. Mature JSON-RPC and HTTP libraries. |
| **ONNX Runtime (via onnxruntime-go)** | Runs sentence embedding models without requiring Python or a GPU. Small model files (~23MB for MiniLM) ship alongside the binary or are downloaded on first use. |
| **Nuclei-inspired YAML templates** | Proven model for community-driven security detection. Low barrier to contribution. Separates detection logic from engine code. |
| **No Python, no Node** | Eliminates entire classes of supply chain risk and dependency management complexity. Users install a single binary. |
| **SARIF output** | Industry standard for static analysis results. Direct integration with GitHub Advanced Security, GitLab SAST, Azure DevOps, and VS Code. |

### Why Go-only for v0.1

The v0.1 release is pure Go with an optional ONNX dependency for L2 semantic detection. This keeps the build simple and the binary portable. Future versions may add:

- A gRPC plugin interface for custom detectors in any language.
- L4 causal detection via LLM API calls (OpenAI, Anthropic, local models).
- A runtime proxy mode that intercepts MCP traffic in real time.

---

## Data Flow Diagram

```
  User runs: mcp-lattice scan
       |
       v
  +-- Discovery --+
  |                |
  | Scan filesystem for known config paths        |
  | Parse JSON configs into []ServerConfig        |
  +----------------+
       |
       v  ([]ServerConfig)
  +-- Connector Pool --+
  |                     |
  | For each server:                               |
  |   1. Launch process or connect via HTTP        |
  |   2. Send initialize request                   |
  |   3. Send tools/list request                   |
  |   4. Store []Tool per server                   |
  +---------------------+
       |
       v  (map[Server][]Tool)
  +-- Template Loader --+
  |                      |
  | Load embedded + user templates                 |
  | Validate against schema v1                     |
  | Pre-compile regex patterns                     |
  | Pre-compute semantic embeddings                |
  +----------------------+
       |
       v  ([]Template)
  +-- Detection Pipeline --+
  |                         |
  | For each (server, tool, template):             |
  |   L1: Run pattern checks                      |
  |   L2: Run semantic similarity (if enabled)     |
  |   L3: Run capability graph analysis            |
  |   Assign confidence based on layer agreement   |
  +-------------------------+
       |
       v  ([]RawFinding)
  +-- Result Aggregation --+
  |                         |
  | Deduplicate findings                           |
  | Merge multi-layer evidence                     |
  | Compute final severity and confidence          |
  | Sort by severity descending                    |
  +-------------------------+
       |
       v  ([]Finding)
  +-- Reporter --+
  |               |
  | Format as table / JSON / SARIF / HTML          |
  | Write to stdout or file                        |
  +---------------+
       |
       v
  Output to user
```

---

## Directory Structure

```
mcp-lattice/
  cmd/
    mcp-lattice/
      main.go              # CLI entry point (cobra)
      scan.go              # scan subcommand
      version.go           # version subcommand
  internal/
    discovery/
      discovery.go         # Config file discovery
      claude.go            # Claude Desktop config parser
      cursor.go            # Cursor config parser
      vscode.go            # VS Code config parser
      windsurf.go          # Windsurf config parser
      gemini.go            # Gemini CLI config parser
    connector/
      pool.go              # Connection pool
      stdio.go             # stdio transport
      sse.go               # SSE transport
      streamhttp.go        # Streamable HTTP transport
    scanner/
      scanner.go           # Scan orchestrator
    detection/
      pipeline.go          # Detection pipeline coordinator
      pattern.go           # L1 pattern engine
      semantic.go          # L2 semantic engine
      graph.go             # L3 capability graph engine
    graph/
      graph.go             # Capability graph data structure
      toxic.go             # Toxic path finder
      tagger.go            # Capability tagger
    templates/
      loader.go            # Template loader and validator
      schema.go            # Template schema types
      embed.go             # Embedded default templates
    reporter/
      reporter.go          # Reporter interface
      table.go             # Terminal table output
      json.go              # JSON output
      sarif.go             # SARIF output
      html.go              # HTML output
  templates/
    tool-poisoning/        # Detection templates by category
    prompt-injection/
    code-execution/
    auth/
    data-exfiltration/
    supply-chain/
    capability-graph/
  docs/
    ARCHITECTURE.md        # This file
    TEMPLATE_AUTHORING.md  # Template writing guide
    CONTRIBUTING.md        # Contribution guide
    THREAT_MODEL.md        # Attack taxonomy
    SECURITY.md            # Security policy
  go.mod
  go.sum
  Makefile
  LICENSE
  README.md
```
