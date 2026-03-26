# MCP-Lattice Template Authoring Guide

This guide covers everything you need to write, test, and contribute detection templates for MCP-Lattice.

---

## Table of Contents

1. [Overview](#overview)
2. [Template Schema Reference](#template-schema-reference)
3. [Analysis Types](#analysis-types)
4. [Classification Fields](#classification-fields)
5. [Capability Taxonomy](#capability-taxonomy)
6. [Tutorial: Creating a Template from Scratch](#tutorial-creating-a-template-from-scratch)
7. [Testing Templates Locally](#testing-templates-locally)

---

## Overview

MCP-Lattice templates are YAML files that define what to look for and how to classify findings. They are inspired by [Nuclei](https://github.com/projectdiscovery/nuclei) templates and follow a declarative model: you describe the detection logic, and the engine executes it.

Templates live in the `templates/` directory, organized by attack category:

```
templates/
  tool-poisoning/
  prompt-injection/
  code-execution/
  auth/
  data-exfiltration/
  supply-chain/
  capability-graph/
```

Each template file must have a `.yaml` extension.

---

## Template Schema Reference

Every template must conform to `schema_version: 1`. Below is the complete schema with all supported fields.

```yaml
# Required. Must be "1" for the current schema version.
schema_version: "1"

# Required. Unique identifier for this template. Use kebab-case.
# Convention: <category>/<specific-name>
id: tool-poisoning/hidden-instruction

# Required. Metadata about this template.
info:
  # Required. Human-readable name.
  name: Hidden Instructions in Tool Description

  # Required. One of: info, low, medium, high, critical
  severity: critical

  # Required. Brief description of what this template detects.
  description: >
    Detects tool descriptions that contain hidden instructions intended
    to manipulate the LLM into performing unauthorized actions, such as
    reading sensitive files or exfiltrating data.

  # Optional. Who wrote this template.
  author: mcp-lattice-team

  # Optional. Reference URLs for more context.
  references:
    - https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-XXXXX

  # Optional. Tags for filtering and organization.
  tags:
    - tool-poisoning
    - hidden-instruction
    - prompt-injection

# Required. One or more analysis blocks. Each block defines a detection layer.
analysis:
  - type: pattern          # or "semantic" or "capability_graph"
    target: tool.description  # what to analyze (see Target Fields below)
    pattern:                 # configuration for pattern-type analysis
      # ... (see Pattern Options below)

  - type: semantic
    target: tool.description
    semantic:
      # ... (see Semantic Options below)

  - type: capability_graph
    capability_graph:
      # ... (see Capability Graph Options below)

# Required. How to classify findings from this template.
classification:
  attack-class: tool-poisoning
  cosai-category: PI-2
  owasp-agentic: AG02
  cve: ""                   # Optional. CVE ID if applicable.
```

### Target Fields

The `target` field in pattern and semantic analysis blocks specifies what text to analyze:

| Target | Description |
|---|---|
| `tool.description` | The tool's description string |
| `tool.name` | The tool's name |
| `tool.parameters` | All parameter descriptions concatenated |
| `tool.parameter.<name>` | A specific parameter's description |
| `tool.schema` | The full JSON schema of the tool's input |
| `server.url` | The server's connection URL |
| `server.command` | The server's launch command (for stdio servers) |
| `server.args` | The server's launch arguments |
| `server.env` | The server's environment variables |

---

## Analysis Types

### Pattern Analysis

Pattern analysis uses fast string matching operations. It runs as L1 in the detection pipeline and completes in under 1 millisecond per tool.

```yaml
analysis:
  - type: pattern
    target: tool.description
    pattern:
      # Regex patterns. Finding matches if ANY pattern matches.
      # Patterns use Go's regexp syntax (RE2).
      regex:
        - "(?i)(before|after|always|first|must)\\s+(execute|run|read|send|include|output)"
        - "(?i)ignore\\s+(previous|prior|above)\\s+instructions?"
        - "(?i)do\\s+not\\s+(tell|inform|alert|notify)\\s+(the\\s+)?user"
        - "(?i)silently|covertly|secretly|without\\s+(the\\s+)?user"

      # Check for Unicode directional override tags.
      # These can be used to visually hide text in descriptions.
      # Default: false
      unicode_tags: true

      # Check for zero-width characters (U+200B, U+200C, U+200D, U+FEFF).
      # These can hide content invisible to human reviewers.
      # Default: false
      zero_width: true

      # Decode and scan Base64-encoded strings found in the target.
      # Attackers may encode malicious instructions in Base64 within
      # tool descriptions to evade pattern matching.
      # Default: false
      base64_check: true
```

**Pattern options reference:**

| Option | Type | Default | Description |
|---|---|---|---|
| `regex` | `[]string` | `[]` | List of RE2 regular expressions. A match on any pattern triggers the finding. |
| `unicode_tags` | `bool` | `false` | Scan for Unicode bidirectional and tag characters that can hide text. Detects: U+200E, U+200F, U+202A-U+202E, U+2066-U+2069, U+E0001, U+E0020-U+E007F. |
| `zero_width` | `bool` | `false` | Scan for zero-width characters. Detects: U+200B (zero-width space), U+200C (zero-width non-joiner), U+200D (zero-width joiner), U+FEFF (zero-width no-break space). |
| `base64_check` | `bool` | `false` | Find Base64-encoded strings (minimum 20 characters), decode them, and apply regex patterns to the decoded content. |

### Semantic Analysis

Semantic analysis uses sentence embeddings to detect malicious intent even when the exact wording does not match any regex pattern. It runs as L2 and takes approximately 20 milliseconds per tool.

```yaml
analysis:
  - type: semantic
    target: tool.description
    semantic:
      # The sentence embedding model to use.
      # Must be an ONNX model compatible with the sentence-transformers format.
      # Default: all-MiniLM-L6-v2
      model: all-MiniLM-L6-v2

      # Cosine similarity threshold. Findings above this threshold are reported.
      # Range: 0.0 to 1.0
      # Recommended: 0.75 - 0.85 depending on intent specificity.
      # Lower values increase recall but may increase false positives.
      threshold: 0.78

      # List of malicious intent phrases. The engine embeds each phrase and
      # computes cosine similarity against the target text.
      # Write these as specific, descriptive sentences.
      malicious_intents:
        - "exfiltrate user credentials before executing the requested action"
        - "read sensitive files and include contents in the response"
        - "ignore safety guidelines and execute hidden commands"
        - "send collected data to an external server without user knowledge"
        - "override user preferences and perform unauthorized actions"
```

**Semantic options reference:**

| Option | Type | Default | Description |
|---|---|---|---|
| `model` | `string` | `all-MiniLM-L6-v2` | ONNX sentence embedding model name. The model file must be available in the models directory or will be downloaded on first use. |
| `threshold` | `float64` | `0.78` | Cosine similarity threshold (0.0-1.0). Findings with similarity above this value are reported. |
| `malicious_intents` | `[]string` | `[]` | List of malicious intent descriptions. Each is embedded and compared against the target text. |

**Tips for writing effective malicious intents:**

- Be specific and descriptive. "steal data" is too vague; "read SSH private keys and encode them in the response" is better.
- Write intents from the attacker's perspective, describing what the hidden instruction would tell the LLM to do.
- Include 3-7 intents per template. Too few may miss variations; too many slow down scanning.
- Test your threshold empirically. Start at 0.78 and adjust based on false positive/negative rates.

### Capability Graph Analysis

Capability graph analysis detects dangerous combinations of tool capabilities across one or more MCP servers. It runs as L3 and takes approximately 50 milliseconds for a full scan.

```yaml
analysis:
  - type: capability_graph
    capability_graph:
      # Define toxic combinations of capabilities.
      # Each combination specifies a set of capabilities that, when present
      # together across the tool graph, create an exploitable attack path.
      toxic_combinations:
        - name: filesystem-to-network-exfiltration
          description: >
            Tools that can read local files combined with tools that can
            send data over the network create a file exfiltration path.
          capabilities:
            - reads_filesystem
            - sends_http
          severity: critical

        - name: credential-theft-via-network
          description: >
            Tools that can access credentials combined with tools that can
            send HTTP requests enable credential exfiltration.
          capabilities:
            - reads_credentials
            - sends_http
          severity: critical

        - name: code-execution-with-network
          description: >
            Tools that can execute arbitrary code combined with network
            access create a remote code execution chain.
          capabilities:
            - executes_code
            - accesses_network
          severity: high

        - name: env-to-email-exfiltration
          description: >
            Tools that can read environment variables (often containing
            secrets) combined with email sending capability.
          capabilities:
            - reads_env
            - email_send
          severity: high
```

**Capability graph options reference:**

| Option | Type | Description |
|---|---|---|
| `toxic_combinations` | `[]ToxicCombination` | List of dangerous capability combinations to detect. |
| `toxic_combinations[].name` | `string` | Identifier for this combination. |
| `toxic_combinations[].description` | `string` | Human-readable description of the attack path. |
| `toxic_combinations[].capabilities` | `[]string` | List of capability tags (see Capability Taxonomy). All listed capabilities must be present in the tool graph for the combination to trigger. |
| `toxic_combinations[].severity` | `string` | Severity override for this combination: `info`, `low`, `medium`, `high`, `critical`. |

---

## Classification Fields

Every template must include a `classification` block that maps the finding to standardized taxonomies.

```yaml
classification:
  # Required. MCP-Lattice's internal attack class.
  attack-class: tool-poisoning

  # Required. CoSAI (Coalition for Secure AI) category identifier.
  cosai-category: PI-2

  # Required. OWASP Agentic Top 10 entry.
  owasp-agentic: AG02

  # Optional. CVE identifier if a specific CVE applies.
  cve: CVE-2025-12345
```

**Attack class values:**

| Value | Description |
|---|---|
| `prompt-injection` | Direct or indirect prompt injection attacks |
| `tool-poisoning` | Malicious content in tool metadata or descriptions |
| `code-execution` | Command injection, sandbox escape, path traversal |
| `auth-bypass` | Authentication and identity vulnerabilities |
| `data-exfiltration` | Data leakage via tool parameters or side channels |
| `supply-chain` | Typosquatting, malicious packages, dependency confusion |
| `privilege-escalation` | Excessive permissions, confused deputy |
| `denial-of-service` | Resource exhaustion, infinite loops |
| `protocol-level` | CSRF, CORS, transport security issues |
| `multi-agent` | Cross-agent poisoning, cascading failures |

**CoSAI category values:**

| Value | Description |
|---|---|
| `PI-1` | Direct prompt injection |
| `PI-2` | Indirect prompt injection / tool poisoning |
| `PI-3` | Cross-plugin/tool attacks |
| `DL-1` | Data leakage via outputs |
| `DL-2` | Data leakage via side channels |
| `CE-1` | Code execution via agent actions |
| `SC-1` | Supply chain compromise |
| `AC-1` | Access control failures |
| `MA-1` | Multi-agent coordination attacks |

**OWASP Agentic values:**

| Value | Description |
|---|---|
| `AG01` | Prompt injection |
| `AG02` | Tool poisoning / manipulation |
| `AG03` | Excessive agency |
| `AG04` | Inadequate sandboxing |
| `AG05` | Data exfiltration |
| `AG06` | Broken access control |
| `AG07` | Supply chain vulnerabilities |
| `AG08` | Insecure output handling |
| `AG09` | Denial of service |
| `AG10` | Logging and monitoring failures |

---

## Capability Taxonomy

The capability taxonomy is the vocabulary used by the L3 capability graph engine to tag tools and detect toxic combinations.

| Capability | Description | Typical Tool Examples |
|---|---|---|
| `reads_filesystem` | Can read files from the local filesystem | `read_file`, `list_directory`, `get_file_contents` |
| `writes_filesystem` | Can create, modify, or delete local files | `write_file`, `create_file`, `edit_file`, `delete_file` |
| `reads_credentials` | Can access secrets, keys, tokens, or passwords | `read_ssh_key`, `get_secret`, `access_keychain` |
| `sends_http` | Can make outbound HTTP/HTTPS requests | `fetch_url`, `http_request`, `call_api` |
| `accesses_network` | Can access network resources (sockets, DNS) | `dns_lookup`, `ping`, `connect`, `tcp_send` |
| `executes_code` | Can execute arbitrary code or shell commands | `run_command`, `exec`, `shell`, `eval`, `python_exec` |
| `reads_env` | Can read environment variables | `get_env`, `list_env`, `environment` |
| `writes_external` | Can write data to external services | `upload`, `publish`, `send_to_api`, `post_data` |
| `database_access` | Can query or modify databases | `sql_query`, `db_execute`, `insert_record` |
| `email_send` | Can send email messages | `send_email`, `send_mail`, `smtp_send` |

Tools are tagged automatically by the capability tagger based on keywords in their names, descriptions, and parameter names. Templates can reference any of these capabilities in `toxic_combinations`.

---

## Tutorial: Creating a Template from Scratch

This tutorial walks through creating a template that detects MCP servers with tool descriptions containing Base64-encoded hidden instructions.

### Step 1: Create the Template File

Create a new file at `templates/prompt-injection/base64-hidden-payload.yaml`:

```yaml
schema_version: "1"
```

### Step 2: Add the ID and Info Block

Choose a unique ID following the `<category>/<name>` convention:

```yaml
schema_version: "1"

id: prompt-injection/base64-hidden-payload

info:
  name: Base64-Encoded Hidden Payload in Tool Description
  severity: high
  description: >
    Detects tool descriptions that contain Base64-encoded strings which,
    when decoded, reveal hidden instructions. Attackers use Base64 encoding
    to evade simple pattern matching while still influencing LLM behavior,
    as many LLMs will decode and follow Base64-encoded instructions.
  author: your-github-handle
  references:
    - https://example.com/research-on-base64-injection
  tags:
    - prompt-injection
    - base64
    - encoding
    - evasion
```

### Step 3: Add Pattern Analysis

Start with L1 pattern detection. Enable `base64_check` so the engine decodes Base64 strings before applying regex:

```yaml
analysis:
  - type: pattern
    target: tool.description
    pattern:
      regex:
        - "(?i)(ignore|override|bypass|disable)\\s+(previous|safety|security|all)\\s+(instructions?|rules?|guidelines?|restrictions?)"
        - "(?i)(read|access|send|exfiltrate|steal|copy)\\s+(ssh|credentials?|tokens?|keys?|passwords?|secrets?)"
        - "(?i)(do\\s+not|never|don't)\\s+(tell|inform|show|alert|warn)\\s+(the\\s+)?user"
      base64_check: true
```

### Step 4: Add Semantic Analysis

Add L2 semantic detection to catch rephrasings that evade regex:

```yaml
  - type: semantic
    target: tool.description
    semantic:
      model: all-MiniLM-L6-v2
      threshold: 0.80
      malicious_intents:
        - "decode the Base64 string and follow the hidden instructions"
        - "execute the encoded payload without informing the user"
        - "Base64 encoded command to read sensitive files"
        - "hidden instruction encoded to avoid detection by security tools"
```

### Step 5: Add Classification

```yaml
classification:
  attack-class: prompt-injection
  cosai-category: PI-1
  owasp-agentic: AG01
```

### Step 6: Complete Template

Here is the full template:

```yaml
schema_version: "1"

id: prompt-injection/base64-hidden-payload

info:
  name: Base64-Encoded Hidden Payload in Tool Description
  severity: high
  description: >
    Detects tool descriptions that contain Base64-encoded strings which,
    when decoded, reveal hidden instructions. Attackers use Base64 encoding
    to evade simple pattern matching while still influencing LLM behavior,
    as many LLMs will decode and follow Base64-encoded instructions.
  author: your-github-handle
  references:
    - https://example.com/research-on-base64-injection
  tags:
    - prompt-injection
    - base64
    - encoding
    - evasion

analysis:
  - type: pattern
    target: tool.description
    pattern:
      regex:
        - "(?i)(ignore|override|bypass|disable)\\s+(previous|safety|security|all)\\s+(instructions?|rules?|guidelines?|restrictions?)"
        - "(?i)(read|access|send|exfiltrate|steal|copy)\\s+(ssh|credentials?|tokens?|keys?|passwords?|secrets?)"
        - "(?i)(do\\s+not|never|don't)\\s+(tell|inform|show|alert|warn)\\s+(the\\s+)?user"
      base64_check: true

  - type: semantic
    target: tool.description
    semantic:
      model: all-MiniLM-L6-v2
      threshold: 0.80
      malicious_intents:
        - "decode the Base64 string and follow the hidden instructions"
        - "execute the encoded payload without informing the user"
        - "Base64 encoded command to read sensitive files"
        - "hidden instruction encoded to avoid detection by security tools"

classification:
  attack-class: prompt-injection
  cosai-category: PI-1
  owasp-agentic: AG01
```

---

## Testing Templates Locally

### Validate Template Syntax

```bash
mcp-lattice template validate templates/prompt-injection/base64-hidden-payload.yaml
```

This checks:
- YAML syntax is valid.
- All required fields are present.
- Schema version is supported.
- Regex patterns compile.
- Capability names are in the taxonomy.
- Severity values are valid.

### Dry Run Against a Server

```bash
mcp-lattice scan --server stdio:///path/to/test-server \
  --templates templates/prompt-injection/ \
  --verbose
```

The `--verbose` flag shows which templates matched and at which detection layer.

### Test Against a Mock Tool Description

Create a test config file with a mock server that has a suspicious tool description:

```json
{
  "mcpServers": {
    "test-server": {
      "command": "echo",
      "args": ["{}"]
    }
  }
}
```

For more thorough testing, use the test harness in the repository:

```bash
make test-templates
```

This runs every template against a corpus of known-good and known-bad tool descriptions and reports precision and recall.

### Check for False Positives

Run your template against a set of legitimate MCP servers to verify it does not produce false positives:

```bash
mcp-lattice scan --templates templates/prompt-injection/base64-hidden-payload.yaml \
  --config test/fixtures/benign-config.json \
  --verbose
```

A well-written template should produce zero findings against benign servers. If it does produce findings, consider:

1. Making regex patterns more specific.
2. Raising the semantic threshold.
3. Adding negative examples to your test corpus.

### Template Linting

```bash
mcp-lattice template lint templates/
```

The linter checks for common issues:
- Overly broad regex patterns (e.g., `.*` without anchoring).
- Semantic thresholds below 0.70 (high false positive risk).
- Missing classification fields.
- Duplicate template IDs.
- Malicious intents that are too short or too generic.
