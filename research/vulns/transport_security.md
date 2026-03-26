# Transport Security Investigation

## Date: March 19, 2026
## Classification: NOVEL ATTACK VECTOR
## Severity: MEDIUM-HIGH
## Status: Investigation complete

---

## 1. Executive Summary

MCP servers use multiple transport mechanisms (STDIO, SSE, and the newer Streamable HTTP), each with different security properties. This investigation documents transport-level security weaknesses in the MCP ecosystem:

1. **SSE (Server-Sent Events)** is deprecated but still widely used, and it exposes authentication tokens in URL parameters
2. **Many servers listen on `0.0.0.0`** instead of `localhost`, exposing them to the local network
3. **No TLS requirement** for local transports, enabling man-in-the-middle attacks on shared networks
4. **Token-in-URL exposure** creates credential leakage through browser history, logs, and referrer headers

---

## 2. MCP Transport Mechanisms

### 2.1 Transport Overview

| Transport | Description | Security | Status |
|-----------|-------------|----------|--------|
| **STDIO** | Communication over stdin/stdout | Good — process-local | Active, recommended |
| **SSE** | Server-Sent Events over HTTP | Poor — tokens in URLs | **Deprecated** (security reasons) |
| **Streamable HTTP** | HTTP POST/GET with streaming | Better — tokens in headers | Active, replacement for SSE |

### 2.2 MCP Specification Transport Security Recommendations

The MCP specification (https://spec.modelcontextprotocol.io/) addresses transport security:

#### STDIO Transport
- Communication is process-local (stdin/stdout)
- No network exposure
- **Security**: Inherently secure against network attacks
- **Weakness**: No inter-process isolation; any process with access to the pipes can read/write

#### SSE Transport (Deprecated)
- Uses HTTP for client-to-server and SSE for server-to-client
- **Deprecated in favor of Streamable HTTP** due to security concerns
- The specification acknowledges security weaknesses but SSE servers still exist in the wild

#### Streamable HTTP Transport
- Uses standard HTTP POST for requests, optional SSE for streaming responses
- Authentication via HTTP headers (not URL parameters)
- **Security**: Better than SSE, but still requires TLS for production use

### 2.3 Spec Security Gaps

The MCP specification:
- Does NOT require TLS for any transport
- Does NOT specify authentication mechanisms (left to implementation)
- Does NOT mandate binding to localhost for local servers
- Does NOT provide guidance on token storage or rotation
- Acknowledges SSE deprecation but provides no migration timeline

---

## 3. SSE Usage in the Wild

### 3.1 How Many Servers Use SSE?

Despite being deprecated, SSE remains in use because:
1. Many tutorials and examples still reference SSE
2. The `@modelcontextprotocol/sdk` still supports SSE transport
3. Existing deployments have not migrated to Streamable HTTP
4. Some client implementations only support SSE

**Estimated SSE usage**: Based on npm package analysis and GitHub repository scanning:
- The official MCP SDK (`@modelcontextprotocol/sdk`) includes SSE transport support
- Many community MCP servers implement SSE as their primary HTTP transport
- Migration to Streamable HTTP is ongoing but incomplete

### 3.2 SSE Security Risks

```
SSE Connection Flow:
  Client → GET /sse?token=BEARER_TOKEN_HERE → Server
                    ↑
                    └── Token exposed in:
                        - Browser history
                        - HTTP access logs
                        - Proxy logs
                        - Referrer headers
                        - Network monitoring tools
```

---

## 4. Token Exposure in URL Parameters

### 4.1 The Problem

SSE-based MCP servers often pass authentication tokens in URL query parameters:

```
GET https://mcp-server.example.com/sse?token=ghp_xxxxxxxxxxxx
```

This exposes tokens in:

| Exposure Vector | Risk | Mitigation |
|----------------|------|------------|
| Server access logs | Tokens stored in log files | Log scrubbing |
| Browser history | Tokens visible in history | N/A for non-browser clients |
| Proxy logs | Corporate proxies log full URLs | TLS (prevents proxy inspection) |
| Referrer headers | Token sent to third-party resources | Referrer-Policy header |
| Shell history | Token visible in command history | Environment variables |
| Network monitoring | Token visible on the wire | TLS |
| Error reporting | Token included in error URLs | URL sanitization |

### 4.2 MCP-Specific Token Risks

MCP servers commonly use these tokens in URLs or environment:
- `GITHUB_PERSONAL_ACCESS_TOKEN` — GitHub API access
- `BRAVE_API_KEY` — Brave Search API
- `GOOGLE_MAPS_API_KEY` — Google Maps API
- `SLACK_BOT_TOKEN` — Slack workspace access
- `ANTHROPIC_API_KEY` — Anthropic API access
- `OPENAI_API_KEY` — OpenAI API access

When these are passed via URL parameters (SSE transport), they are logged everywhere.

---

## 5. Servers Listening on 0.0.0.0

### 5.1 The Problem

Some MCP servers bind to `0.0.0.0` (all interfaces) instead of `127.0.0.1` (localhost only):

```
// INSECURE — accessible from the entire local network
server.listen(3000, '0.0.0.0');

// SECURE — only accessible from localhost
server.listen(3000, '127.0.0.1');
```

### 5.2 Risk Assessment

When an MCP server listens on `0.0.0.0`:
1. **Any device on the same network** can connect to the server
2. **No authentication** is typically required for STDIO-converted-to-HTTP servers
3. **Tool execution** is available to anyone who can reach the port
4. **On public WiFi**, this exposes the server to all nearby devices

### 5.3 Common Patterns in MCP Servers

Based on analysis of MCP server packages:

| Pattern | Prevalence | Risk |
|---------|-----------|------|
| STDIO transport (no network) | Most official servers | Low |
| HTTP on localhost (127.0.0.1) | Some community servers | Low |
| HTTP on 0.0.0.0 | Some community servers | **HIGH** |
| SSE without TLS | Many community servers | **HIGH** |
| SSE with TLS | Few servers | Medium |
| Streamable HTTP on localhost | Growing adoption | Low |

### 5.4 Specific Findings

Notable patterns observed in the MCP ecosystem:

1. **mcp-proxy and bridge tools**: Tools that convert STDIO servers to HTTP often default to `0.0.0.0` binding for convenience
2. **Docker deployments**: MCP servers in Docker containers bind to `0.0.0.0` inside the container (acceptable) but port mapping may expose them to the host network
3. **Development servers**: Many servers use `0.0.0.0` during development and this configuration leaks into production

---

## 6. Missing TLS for Local Communication

### 6.1 The Gap

Even servers that correctly bind to `localhost` may not use TLS. On shared machines (multi-user systems, CI/CD environments):
- Other users can sniff localhost traffic
- Malware can intercept unencrypted local communication
- Container-to-container communication may be unencrypted

### 6.2 Recommendation

For production MCP deployments:
- STDIO transport is preferred (no network exposure)
- HTTP-based transports should use TLS, even on localhost
- Consider mTLS (mutual TLS) for high-security environments

---

## 7. MCP Spec Transport Security Recommendations

### 7.1 What the Spec Says

The MCP specification provides limited transport security guidance:
- SSE is "deprecated" but no removal date
- Streamable HTTP is the recommended replacement
- Authentication is "implementation-defined"
- No TLS requirements

### 7.2 What the Spec Should Say

1. **MUST use TLS** for any HTTP-based transport in production
2. **MUST bind to localhost** unless explicitly configured for remote access
3. **MUST NOT pass tokens in URL parameters** (use Authorization headers)
4. **SHOULD deprecate SSE** with a clear removal timeline
5. **SHOULD define a standard authentication mechanism** (e.g., Bearer tokens in Authorization header)
6. **SHOULD require token rotation** support

---

## 8. Recommendations for MCP-Lattice

### 8.1 Transport Security Detection Templates

1. **SSE Usage Detection**: Flag servers that use SSE transport (deprecated)
2. **Token-in-URL Detection**: Detect when tokens appear in URL parameters
3. **0.0.0.0 Binding Detection**: Flag servers that listen on all interfaces
4. **Missing TLS Detection**: Detect HTTP (not HTTPS) connections
5. **Token Exposure Detection**: Check if environment variables containing tokens are accessible to multiple servers

### 8.2 Scan Enhancements

- Add a `--transport-audit` flag to MCP-Lattice
- Check server startup arguments for bind address
- Verify TLS certificate validity for HTTPS connections
- Flag shared environment variables across servers

---

## 9. Summary of Findings

| Finding | Severity | Prevalence | Novelty |
|---------|----------|------------|---------|
| SSE still in use despite deprecation | MEDIUM | Common | Known but underdocumented |
| Tokens exposed in URL parameters | HIGH | Common in SSE | Known but MCP-specific impact undocumented |
| Servers on 0.0.0.0 | HIGH | Some | Novel in MCP context |
| No TLS requirement in spec | MEDIUM | Universal | Novel analysis |
| No standard auth mechanism | MEDIUM | Universal | Novel analysis |

---

## 10. References

- MCP Specification — Transport: https://spec.modelcontextprotocol.io/
- OWASP Transport Layer Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- SSE Security Considerations: https://html.spec.whatwg.org/multipage/server-sent-events.html
- Token in URL risks: OWASP Testing Guide v4, OTG-AUTHN-001
