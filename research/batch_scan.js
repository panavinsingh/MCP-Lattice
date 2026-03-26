#!/usr/bin/env node
/**
 * batch_scan.js
 *
 * Reads npm_mcp_servers.json, installs each MCP server via npx,
 * runs mcp-lattice against it, captures results, and aggregates.
 * Resilient: skips servers that fail to start, crash, or hang.
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const MCPLATTICE = path.join(__dirname, '..', 'bin', 'mcp-lattice.exe');
const SERVERS_FILE = path.join(__dirname, 'npm_mcp_servers.json');
const RESULTS_DIR = path.join(__dirname, 'results');
const AGGREGATE_FILE = path.join(__dirname, 'batch_scan_results.json');
const TIMEOUT_MS = 30000; // 30 seconds per server
const MAX_SERVERS = 100; // Scan up to 100 servers

// Ensure results directory exists
if (!fs.existsSync(RESULTS_DIR)) {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
}

function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9_-]/g, '_').replace(/@/g, '').replace(/\//g, '_');
}

function runScan(serverName, command, args) {
  return new Promise((resolve) => {
    const configFile = path.join(RESULTS_DIR, `${sanitizeFilename(serverName)}_config.json`);
    const outputFile = path.join(RESULTS_DIR, `${sanitizeFilename(serverName)}.json`);

    // Create temp config
    const config = {
      mcpServers: {
        [serverName]: {
          command: command,
          args: args
        }
      }
    };
    fs.writeFileSync(configFile, JSON.stringify(config, null, 2));

    const startTime = Date.now();
    let killed = false;

    try {
      const proc = spawn(MCPLATTICE, [
        'scan', '--config', configFile, '--format', 'json', '--output', outputFile
      ], {
        timeout: TIMEOUT_MS,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => { stdout += data.toString(); });
      proc.stderr.on('data', (data) => { stderr += data.toString(); });

      const timer = setTimeout(() => {
        killed = true;
        try { proc.kill('SIGKILL'); } catch (e) {}
      }, TIMEOUT_MS);

      proc.on('close', (code) => {
        clearTimeout(timer);
        const elapsed = Date.now() - startTime;

        let findings = null;
        let findingCount = 0;
        let severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

        if (fs.existsSync(outputFile)) {
          try {
            findings = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
            if (findings && findings.findings) {
              findingCount = findings.findings.length;
              findings.findings.forEach(f => {
                const sev = (f.severity || '').toLowerCase();
                if (severity.hasOwnProperty(sev)) severity[sev]++;
              });
            }
          } catch (e) {
            // Parse error, leave as null
          }
        }

        // Clean up temp config
        try { fs.unlinkSync(configFile); } catch (e) {}

        resolve({
          server: serverName,
          status: killed ? 'timeout' : (code === 0 ? 'success' : 'error'),
          exitCode: code,
          elapsed,
          findingCount,
          severity,
          error: killed ? 'Killed after timeout' : (code !== 0 ? stderr.substring(0, 500) : null)
        });
      });

      proc.on('error', (err) => {
        clearTimeout(timer);
        resolve({
          server: serverName,
          status: 'error',
          exitCode: -1,
          elapsed: Date.now() - startTime,
          findingCount: 0,
          severity,
          error: err.message
        });
      });
    } catch (e) {
      resolve({
        server: serverName,
        status: 'error',
        exitCode: -1,
        elapsed: Date.now() - startTime,
        findingCount: 0,
        severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        error: e.message
      });
    }
  });
}

async function main() {
  console.log('MCP-Lattice Batch Scanner');
  console.log('=====================\n');

  // Check mcp-lattice exists
  if (!fs.existsSync(MCPLATTICE)) {
    console.error(`ERROR: mcp-lattice.exe not found at ${MCPLATTICE}`);
    console.error('Build it first: go build -o bin/mcp-lattice.exe ./cmd/mcp-lattice/');
    process.exit(1);
  }

  // Read server list
  if (!fs.existsSync(SERVERS_FILE)) {
    console.error(`ERROR: ${SERVERS_FILE} not found. Run harvest_mcp_servers.js first.`);
    process.exit(1);
  }

  const data = JSON.parse(fs.readFileSync(SERVERS_FILE, 'utf8'));
  const servers = data.servers.slice(0, MAX_SERVERS);
  console.log(`Loaded ${servers.length} servers to scan (max ${MAX_SERVERS})\n`);

  const results = [];

  for (let i = 0; i < servers.length; i++) {
    const server = servers[i];
    const name = server.name;
    console.log(`[${i + 1}/${servers.length}] Scanning: ${name}...`);

    const result = await runScan(name, 'npx', ['-y', name]);
    results.push({
      ...result,
      packageName: name,
      version: server.version,
      description: server.description,
      weeklyDownloads: server.weeklyDownloads
    });

    const statusIcon = result.status === 'success' ? '✓' : result.status === 'timeout' ? '⏱' : '✗';
    console.log(`  ${statusIcon} ${result.status} (${result.elapsed}ms, ${result.findingCount} findings)`);

    if (result.findingCount > 0) {
      console.log(`    Severity: C=${result.severity.critical} H=${result.severity.high} M=${result.severity.medium} L=${result.severity.low}`);
    }
  }

  // Aggregate
  const aggregate = {
    metadata: {
      scanDate: new Date().toISOString(),
      mcp-latticeVersion: 'v0.1.0',
      totalServers: servers.length,
      timeoutMs: TIMEOUT_MS
    },
    summary: {
      total: results.length,
      success: results.filter(r => r.status === 'success').length,
      timeout: results.filter(r => r.status === 'timeout').length,
      error: results.filter(r => r.status === 'error').length,
      totalFindings: results.reduce((sum, r) => sum + r.findingCount, 0),
      severity: {
        critical: results.reduce((sum, r) => sum + r.severity.critical, 0),
        high: results.reduce((sum, r) => sum + r.severity.high, 0),
        medium: results.reduce((sum, r) => sum + r.severity.medium, 0),
        low: results.reduce((sum, r) => sum + r.severity.low, 0),
        info: results.reduce((sum, r) => sum + r.severity.info, 0)
      },
      serversWithFindings: results.filter(r => r.findingCount > 0).length,
      serversWithCritical: results.filter(r => r.severity.critical > 0).length
    },
    results: results
  };

  fs.writeFileSync(AGGREGATE_FILE, JSON.stringify(aggregate, null, 2));
  console.log(`\n${'='.repeat(60)}`);
  console.log('BATCH SCAN COMPLETE');
  console.log(`${'='.repeat(60)}`);
  console.log(`Total servers attempted: ${aggregate.summary.total}`);
  console.log(`Successful scans: ${aggregate.summary.success}`);
  console.log(`Timeouts: ${aggregate.summary.timeout}`);
  console.log(`Errors: ${aggregate.summary.error}`);
  console.log(`Total findings: ${aggregate.summary.totalFindings}`);
  console.log(`  Critical: ${aggregate.summary.severity.critical}`);
  console.log(`  High: ${aggregate.summary.severity.high}`);
  console.log(`  Medium: ${aggregate.summary.severity.medium}`);
  console.log(`  Low: ${aggregate.summary.severity.low}`);
  console.log(`Servers with findings: ${aggregate.summary.serversWithFindings} (${(aggregate.summary.serversWithFindings / aggregate.summary.total * 100).toFixed(1)}%)`);
  console.log(`Servers with Critical: ${aggregate.summary.serversWithCritical} (${(aggregate.summary.serversWithCritical / aggregate.summary.total * 100).toFixed(1)}%)`);
  console.log(`\nResults saved to ${AGGREGATE_FILE}`);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
