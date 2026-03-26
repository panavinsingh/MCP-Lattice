#!/bin/bash
# Run the MCP client simulator against all test servers
# Execute from the mcp-lattice root directory

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

mkdir -p "$RESULTS_DIR"

echo "Running MCP Client Simulator against all test servers..."
echo ""

# 1. Exfil server
echo "=== Running against exfil_server.js ==="
node "$SCRIPT_DIR/minimal_client.js" -- node "$PROJECT_DIR/test_servers/exfil_server.js" > "$RESULTS_DIR/exfil_server_results.txt" 2>&1
echo "  Saved to $RESULTS_DIR/exfil_server_results.txt"

# 2. Shadow server
echo "=== Running against shadow_server.js ==="
node "$SCRIPT_DIR/minimal_client.js" -- node "$PROJECT_DIR/test_servers/shadow_server.js" > "$RESULTS_DIR/shadow_server_results.txt" 2>&1
echo "  Saved to $RESULTS_DIR/shadow_server_results.txt"

# 3. Context flood server
echo "=== Running against context_flood_server.js ==="
node "$SCRIPT_DIR/minimal_client.js" -- node "$PROJECT_DIR/test_servers/context_flood_server.js" > "$RESULTS_DIR/context_flood_server_results.txt" 2>&1
echo "  Saved to $RESULTS_DIR/context_flood_server_results.txt"

# 4. TOCTOU server (takes ~35 seconds)
echo "=== Running against toctou_server.js (will take ~35 seconds) ==="
node "$SCRIPT_DIR/minimal_client.js" -- node "$PROJECT_DIR/test_servers/toctou_server.js" > "$RESULTS_DIR/toctou_server_results.txt" 2>&1
echo "  Saved to $RESULTS_DIR/toctou_server_results.txt"

# 5. Clean server
echo "=== Running against clean_server.js ==="
node "$SCRIPT_DIR/minimal_client.js" -- node "$PROJECT_DIR/test_servers/clean_server.js" > "$RESULTS_DIR/clean_server_results.txt" 2>&1
echo "  Saved to $RESULTS_DIR/clean_server_results.txt"

echo ""
echo "All simulations complete. Results saved to $RESULTS_DIR/"
