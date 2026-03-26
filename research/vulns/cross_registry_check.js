#!/usr/bin/env node
/**
 * cross_registry_check.js — Cross-Registry Poisoning Detection Script
 *
 * Searches npm and PyPI for MCP server packages with overlapping names.
 * Flags any name collisions where the same logical server name exists
 * on multiple registries with potentially different code/authors.
 *
 * Usage: node cross_registry_check.js [--output results.json]
 *
 * Attack vector: An attacker registers "mcp-server-filesystem" on PyPI
 * while the official package is "@modelcontextprotocol/server-filesystem"
 * on npm. Users who install from the wrong registry get malicious code.
 */

const https = require("https");
const fs = require("fs");

// ============================================================================
// Configuration
// ============================================================================

const MCP_SERVER_NAMES = [
  "server-filesystem",
  "server-memory",
  "server-fetch",
  "server-github",
  "server-everything",
  "server-sqlite",
  "server-git",
  "server-postgres",
  "server-brave-search",
  "server-puppeteer",
  "server-slack",
  "server-sequential-thinking",
  "server-google-maps",
  "server-aws-kb-retrieval-server",
  "server-gdrive",
  "server-redis",
];

const NPM_SEARCH_QUERIES = [
  "mcp server filesystem",
  "modelcontextprotocol server",
  "server-filesystem",
  "mcp-server",
];

const PYPI_PACKAGE_PATTERNS = [
  "mcp-server-filesystem",
  "mcp-server-memory",
  "mcp-server-fetch",
  "mcp-server-github",
  "mcp-server-everything",
  "mcp-server-sqlite",
  "mcp-server-git",
  "mcp-server-postgres",
  "mcp-server-puppeteer",
  "mcp-server-slack",
  "mcp-server-brave-search",
  "mcp-server-gdrive",
  "mcp-server-redis",
  "mcp-server-google-maps",
];

// ============================================================================
// HTTP Helper
// ============================================================================

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { "User-Agent": "mcp-lattice-research/1.0" } }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else if (res.statusCode === 404) {
            resolve(null);
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`));
          }
        } catch (e) {
          reject(new Error(`JSON parse error: ${e.message}`));
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(15000, () => {
      req.destroy();
      reject(new Error("Timeout"));
    });
  });
}

// ============================================================================
// npm Registry Search
// ============================================================================

async function searchNpm(query, size = 50) {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=${size}`;
  try {
    const data = await fetchJSON(url);
    if (!data || !data.objects) return [];
    return data.objects.map((o) => ({
      name: o.package.name,
      version: o.package.version,
      description: (o.package.description || "").substring(0, 200),
      publisher: o.package.publisher ? o.package.publisher.username : "unknown",
      registry: "npm",
    }));
  } catch (e) {
    console.error(`[npm] Search error for "${query}": ${e.message}`);
    return [];
  }
}

// ============================================================================
// PyPI Registry Search
// ============================================================================

async function checkPyPI(packageName) {
  const url = `https://pypi.org/pypi/${packageName}/json`;
  try {
    const data = await fetchJSON(url);
    if (!data) return null;
    return {
      name: data.info.name,
      version: data.info.version,
      description: (data.info.summary || "").substring(0, 200),
      author: data.info.author || data.info.author_email || "unknown",
      homepage: data.info.home_page || data.info.project_url || "",
      registry: "pypi",
    };
  } catch (e) {
    console.error(`[pypi] Error checking "${packageName}": ${e.message}`);
    return null;
  }
}

// ============================================================================
// Smithery Search (smithery.ai)
// ============================================================================

async function searchSmithery(query) {
  // Smithery API endpoint (public search)
  const url = `https://registry.smithery.ai/api/search?q=${encodeURIComponent(query)}&limit=20`;
  try {
    const data = await fetchJSON(url);
    if (!data || !Array.isArray(data)) return [];
    return data.map((item) => ({
      name: item.name || item.id || "unknown",
      description: (item.description || "").substring(0, 200),
      author: item.author || "unknown",
      registry: "smithery",
    }));
  } catch (e) {
    // Smithery API may not be publicly accessible — this is expected
    console.error(`[smithery] Search error: ${e.message}`);
    return [];
  }
}

// ============================================================================
// Cross-Registry Collision Detection
// ============================================================================

function normalizeServerName(name) {
  return name
    .toLowerCase()
    .replace(/^@[^/]+\//, "") // Remove npm scope
    .replace(/^mcp-/, "")
    .replace(/^server-/, "")
    .replace(/-/g, "");
}

function detectCollisions(npmPackages, pypiPackages, smitheryPackages) {
  const collisions = [];
  const npmByNorm = {};
  const pypiByNorm = {};
  const smitheryByNorm = {};

  npmPackages.forEach((pkg) => {
    const norm = normalizeServerName(pkg.name);
    if (!npmByNorm[norm]) npmByNorm[norm] = [];
    npmByNorm[norm].push(pkg);
  });

  pypiPackages.forEach((pkg) => {
    if (!pkg) return;
    const norm = normalizeServerName(pkg.name);
    if (!pypiByNorm[norm]) pypiByNorm[norm] = [];
    pypiByNorm[norm].push(pkg);
  });

  smitheryPackages.forEach((pkg) => {
    const norm = normalizeServerName(pkg.name);
    if (!smitheryByNorm[norm]) smitheryByNorm[norm] = [];
    smitheryByNorm[norm].push(pkg);
  });

  // Find names that exist in multiple registries
  const allNorms = new Set([
    ...Object.keys(npmByNorm),
    ...Object.keys(pypiByNorm),
    ...Object.keys(smitheryByNorm),
  ]);

  for (const norm of allNorms) {
    const registries = [];
    if (npmByNorm[norm]) registries.push({ registry: "npm", packages: npmByNorm[norm] });
    if (pypiByNorm[norm]) registries.push({ registry: "pypi", packages: pypiByNorm[norm] });
    if (smitheryByNorm[norm]) registries.push({ registry: "smithery", packages: smitheryByNorm[norm] });

    if (registries.length > 1) {
      collisions.push({
        normalized_name: norm,
        registries: registries,
        risk: assessCollisionRisk(registries),
      });
    }

    // Also flag npm-internal collisions (different scopes, same base name)
    if (npmByNorm[norm] && npmByNorm[norm].length > 1) {
      const uniquePublishers = new Set(npmByNorm[norm].map((p) => p.publisher));
      if (uniquePublishers.size > 1) {
        collisions.push({
          normalized_name: norm,
          registries: [{ registry: "npm-internal", packages: npmByNorm[norm] }],
          risk: "MEDIUM — Multiple npm packages with same base name from different publishers",
        });
      }
    }
  }

  return collisions;
}

function assessCollisionRisk(registries) {
  const regNames = registries.map((r) => r.registry).sort().join("+");
  if (regNames.includes("npm") && regNames.includes("pypi")) {
    return "HIGH — Same server name exists on both npm and PyPI. Users may install the wrong one.";
  }
  if (regNames.includes("smithery")) {
    return "MEDIUM — Server exists on Smithery and another registry. Version/code divergence possible.";
  }
  return "LOW — Name collision detected but risk unclear.";
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  const outputFile = process.argv.includes("--output")
    ? process.argv[process.argv.indexOf("--output") + 1]
    : null;

  console.log("=== Cross-Registry MCP Server Poisoning Check ===\n");
  console.log(`Date: ${new Date().toISOString()}\n`);

  // Step 1: Search npm for MCP server packages
  console.log("[1/4] Searching npm for MCP server packages...");
  const npmResults = [];
  for (const query of NPM_SEARCH_QUERIES) {
    const results = await searchNpm(query, 50);
    for (const r of results) {
      if (!npmResults.find((e) => e.name === r.name)) {
        npmResults.push(r);
      }
    }
  }
  console.log(`  Found ${npmResults.length} unique npm packages\n`);

  // Step 2: Check PyPI for packages with matching names
  console.log("[2/4] Checking PyPI for MCP server packages...");
  const pypiResults = [];
  for (const name of PYPI_PACKAGE_PATTERNS) {
    const result = await checkPyPI(name);
    if (result) {
      pypiResults.push(result);
      console.log(`  FOUND on PyPI: ${result.name} v${result.version} by ${result.author}`);
    } else {
      console.log(`  Not found on PyPI: ${name}`);
    }
  }
  console.log(`  Found ${pypiResults.length} PyPI packages\n`);

  // Step 3: Search Smithery
  console.log("[3/4] Searching Smithery registry...");
  const smitheryResults = [];
  for (const name of ["filesystem", "memory", "fetch", "github"]) {
    const results = await searchSmithery(name);
    for (const r of results) {
      if (!smitheryResults.find((e) => e.name === r.name)) {
        smitheryResults.push(r);
      }
    }
  }
  console.log(`  Found ${smitheryResults.length} Smithery packages\n`);

  // Step 4: Detect collisions
  console.log("[4/4] Detecting cross-registry name collisions...\n");
  const collisions = detectCollisions(npmResults, pypiResults, smitheryResults);

  // Report
  console.log("=== RESULTS ===\n");
  console.log(`npm packages found: ${npmResults.length}`);
  console.log(`PyPI packages found: ${pypiResults.length}`);
  console.log(`Smithery packages found: ${smitheryResults.length}`);
  console.log(`Cross-registry collisions: ${collisions.length}\n`);

  if (collisions.length > 0) {
    console.log("=== COLLISIONS DETECTED ===\n");
    for (const c of collisions) {
      console.log(`[${c.risk.split(" ")[0]}] Normalized name: "${c.normalized_name}"`);
      for (const reg of c.registries) {
        for (const pkg of reg.packages) {
          console.log(`  ${reg.registry}: ${pkg.name} (${pkg.version || "N/A"}) by ${pkg.publisher || pkg.author || "unknown"}`);
        }
      }
      console.log(`  Risk: ${c.risk}`);
      console.log();
    }
  } else {
    console.log("No cross-registry collisions detected.\n");
    console.log("NOTE: This does not mean the risk is zero. An attacker could register");
    console.log("packages at any time. Continuous monitoring is recommended.\n");
  }

  // Additional analysis: flag unofficial npm packages mimicking official ones
  console.log("=== UNOFFICIAL NPM PACKAGES MIMICKING OFFICIAL NAMES ===\n");
  const officialScope = "@modelcontextprotocol/";
  const officialNames = npmResults.filter((p) => p.name.startsWith(officialScope));
  const unofficial = npmResults.filter(
    (p) => !p.name.startsWith(officialScope) && p.name.toLowerCase().includes("mcp")
  );

  console.log(`Official @modelcontextprotocol packages: ${officialNames.length}`);
  console.log(`Unofficial MCP-related packages: ${unofficial.length}\n`);

  for (const u of unofficial.slice(0, 20)) {
    // Check if any official package has a similar base name
    const uNorm = normalizeServerName(u.name);
    const matchingOfficial = officialNames.find(
      (o) => normalizeServerName(o.name) === uNorm
    );
    if (matchingOfficial) {
      console.log(`  [COLLISION] ${u.name} by ${u.publisher} shadows ${matchingOfficial.name}`);
    } else {
      console.log(`  [INFO] ${u.name} by ${u.publisher} — no official equivalent found`);
    }
  }

  // Save results
  const report = {
    timestamp: new Date().toISOString(),
    npm_packages: npmResults,
    pypi_packages: pypiResults,
    smithery_packages: smitheryResults,
    collisions: collisions,
    official_count: officialNames.length,
    unofficial_count: unofficial.length,
  };

  const outPath = outputFile || "cross_registry_results.json";
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`\nResults saved to ${outPath}`);
}

main().catch((e) => {
  console.error("Fatal error:", e.message);
  process.exit(1);
});
