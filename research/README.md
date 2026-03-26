# Reproducing the MCP-Lattice Scan Results

## Overview

This directory contains the scripts and data from our evaluation of 100 MCP servers from the npm registry.

## Files

| File | Purpose |
| --- | --- |
| `harvest_mcp_servers.js` | Discovers MCP server packages on npm by matching naming conventions |
| `batch_scan.js` | Runs MCP-Lattice against a list of harvested servers via npx |
| `scan_analysis.js` | Aggregates raw scan output into summary statistics |
| `large_scale_results.md` | Summary of the 100-server scan results |
| `findings_summary.md` | Detailed per-server finding breakdown |
| `comparison_with_published.md` | Comparison of our results against published ecosystem studies |

## Reproduction Steps

1. Install dependencies:

```bash
cd research && npm install
```

2. Harvest MCP server list from npm:

```bash
node harvest_mcp_servers.js
```

3. Run batch scan (requires MCP-Lattice binary in PATH):

```bash
node batch_scan.js
```

4. Generate summary statistics:

```bash
node scan_analysis.js
```

## Controlled Test Environment

The `test_servers/` directory at the repo root contains five purpose-built MCP servers used for controlled evaluation:

- `clean_server.js` — Benign baseline (add_numbers, echo_text, get_timestamp). Produces zero findings.
- `toctou_server.js` — Demonstrates TOCTOU tool description mutation attack.
- `exfil_server.js` — Demonstrates steganographic prompt injection via Unicode, zero-width, and Base64 techniques.
- `shadow_server.js` — Demonstrates tool name shadowing attacks.
- `context_flood_server.js` — Demonstrates context window exhaustion with embedded injection.

## Notes on False Positive Rate

The "zero false positive" claim applies specifically to the controlled test environment: the clean_server.js baseline produced zero findings across all 34 templates. The large-scale npm scan has not been independently validated for false positives — the over-approximation inherent in capability graph analysis (Section 5.6 of the white paper) means some cross-server findings may flag theoretical rather than practically exploitable attack chains.
