#!/usr/bin/env node
/**
 * harvest_mcp_servers.js
 *
 * Fetches MCP server packages from the npm registry API.
 * Searches multiple queries, deduplicates, checks for MCP SDK dependency,
 * and saves the list to npm_mcp_servers.json.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const SEARCH_QUERIES = [
  'mcp-server',
  'modelcontextprotocol+server',
  '@modelcontextprotocol'
];

const OUTPUT_FILE = path.join(__dirname, 'npm_mcp_servers.json');

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'mcp-lattice-harvester/1.0' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Failed to parse JSON from ${url}: ${e.message}`));
        }
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function fetchPackageDetails(packageName) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const data = await httpsGet(url);
    const latestVersion = data['dist-tags'] && data['dist-tags'].latest;
    const versionData = latestVersion && data.versions && data.versions[latestVersion];

    const deps = {};
    if (versionData) {
      Object.assign(deps, versionData.dependencies || {});
      Object.assign(deps, versionData.peerDependencies || {});
    }

    const hasMcpSdk = Object.keys(deps).some(d =>
      d.includes('modelcontextprotocol') || d.includes('mcp-sdk') || d.includes('@modelcontextprotocol/sdk')
    );

    return {
      hasMcpSdk,
      dependencies: deps,
      bin: versionData && versionData.bin ? Object.keys(versionData.bin) : [],
      repository: data.repository || null
    };
  } catch (e) {
    return { hasMcpSdk: false, dependencies: {}, bin: [], repository: null };
  }
}

async function searchNpm(query) {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=250`;
  console.log(`  Searching: ${query} ...`);
  try {
    const result = await httpsGet(url);
    console.log(`    Found ${result.objects ? result.objects.length : 0} results`);
    return result.objects || [];
  } catch (e) {
    console.error(`    Error searching "${query}": ${e.message}`);
    return [];
  }
}

async function main() {
  console.log('MCP-Lattice Server Harvester');
  console.log('========================\n');

  const allPackages = new Map();

  // Step 1: Search npm registry
  for (const query of SEARCH_QUERIES) {
    const results = await searchNpm(query);
    for (const obj of results) {
      const pkg = obj.package;
      if (!allPackages.has(pkg.name)) {
        allPackages.set(pkg.name, {
          name: pkg.name,
          version: pkg.version,
          description: pkg.description || '',
          weeklyDownloads: obj.score && obj.score.detail && obj.score.detail.popularity
            ? Math.round(obj.score.detail.popularity * 100000)
            : 0,
          score: obj.score ? obj.score.final : 0,
          links: pkg.links || {},
          searchScore: obj.searchScore || 0
        });
      }
    }
  }

  console.log(`\nTotal unique packages found: ${allPackages.size}`);

  // Step 2: Check each package for MCP SDK dependency
  console.log('\nChecking packages for MCP SDK dependency...');
  const packages = Array.from(allPackages.values());
  const mcpServers = [];

  // Process in batches of 10 to avoid overwhelming the registry
  const BATCH_SIZE = 10;
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const details = await Promise.all(
      batch.map(pkg => fetchPackageDetails(pkg.name))
    );

    for (let j = 0; j < batch.length; j++) {
      const pkg = batch[j];
      const detail = details[j];

      // Include if it has MCP SDK as dependency OR if name strongly suggests MCP server
      const nameIsMcpServer = pkg.name.includes('mcp-server') ||
                               pkg.name.includes('mcp_server') ||
                               pkg.name.startsWith('@modelcontextprotocol/server-');

      if (detail.hasMcpSdk || nameIsMcpServer) {
        mcpServers.push({
          name: pkg.name,
          version: pkg.version,
          description: pkg.description,
          weeklyDownloads: pkg.weeklyDownloads,
          score: pkg.score,
          hasMcpSdk: detail.hasMcpSdk,
          repository: detail.repository,
          hasBin: detail.bin.length > 0,
          binNames: detail.bin,
          installCommand: `npx -y ${pkg.name}`,
          links: pkg.links
        });
      }
    }

    process.stdout.write(`  Checked ${Math.min(i + BATCH_SIZE, packages.length)}/${packages.length} packages\r`);
  }

  console.log(`\n\nMCP Server packages found: ${mcpServers.length}`);

  // Sort by score (popularity)
  mcpServers.sort((a, b) => b.score - a.score);

  // Step 3: Save results
  const output = {
    metadata: {
      harvestDate: new Date().toISOString(),
      queries: SEARCH_QUERIES,
      totalSearchResults: allPackages.size,
      mcpServersFound: mcpServers.length
    },
    servers: mcpServers
  };

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2));
  console.log(`\nSaved to ${OUTPUT_FILE}`);

  // Print top 20
  console.log('\nTop 20 MCP Server packages:');
  console.log('-'.repeat(80));
  mcpServers.slice(0, 20).forEach((pkg, i) => {
    console.log(`  ${i + 1}. ${pkg.name}@${pkg.version} (score: ${pkg.score.toFixed(3)}, sdk: ${pkg.hasMcpSdk})`);
    console.log(`     ${pkg.description.substring(0, 70)}`);
  });
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
