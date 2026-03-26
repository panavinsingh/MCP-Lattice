// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
	"github.com/panavinsingh/MCP-Lattice/internal/graph"
)

// HTMLReporter generates interactive HTML reports with capability graph visualization.
type HTMLReporter struct {
	servers map[string]*config.ServerResult
}

// NewHTMLReporter creates a new HTML reporter.
func NewHTMLReporter(servers map[string]*config.ServerResult) *HTMLReporter {
	return &HTMLReporter{servers: servers}
}

// Report writes an HTML report to the given writer.
func (r *HTMLReporter) Report(w io.Writer, result *config.ScanResult) error {
	counts := countBySeverity(result.Findings)

	graphData := graph.BuildGraphData(r.servers)
	graphJSON, _ := json.Marshal(graphData)

	data := htmlData{
		GeneratedAt:    time.Now().Format(time.RFC3339),
		ServersScanned: result.ServersFound,
		ToolsScanned:   result.ToolsScanned,
		TotalFindings:  len(result.Findings),
		Critical:       counts["critical"],
		High:           counts["high"],
		Medium:         counts["medium"],
		Low:            counts["low"],
		Info:           counts["info"],
		Findings:       result.Findings,
		GraphJSON:      string(graphJSON),
		Servers:        r.servers,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper":       strings.ToUpper,
		"sevClass":    severityClass,
		"joinStrings": strings.Join,
		"truncate":    truncate,
		"mul":         func(a, b float64) float64 { return a * b },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	return tmpl.Execute(w, data)
}

type htmlData struct {
	GeneratedAt    string
	ServersScanned int
	ToolsScanned   int
	TotalFindings  int
	Critical       int
	High           int
	Medium         int
	Low            int
	Info           int
	Findings       []config.Finding
	GraphJSON      string
	Servers        map[string]*config.ServerResult
}

func severityClass(s config.Severity) string {
	switch s {
	case config.SeverityCritical:
		return "critical"
	case config.SeverityHigh:
		return "high"
	case config.SeverityMedium:
		return "medium"
	case config.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP-Lattice Security Report</title>
<style>
:root { --bg: #0d1117; --fg: #c9d1d9; --card: #161b22; --border: #30363d; --crit: #f85149; --high: #d29922; --med: #a371f7; --low: #58a6ff; --info: #8b949e; --green: #3fb950; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--fg); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
.subtitle { color: var(--info); margin-bottom: 2rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
.stat .number { font-size: 2rem; font-weight: bold; }
.stat.critical .number { color: var(--crit); }
.stat.high .number { color: var(--high); }
.stat.medium .number { color: var(--med); }
.stat.low .number { color: var(--low); }
.stat.info .number { color: var(--info); }
.stat.total .number { color: var(--fg); }
.findings { margin-bottom: 2rem; }
.finding { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; border-left: 4px solid; }
.finding.critical { border-left-color: var(--crit); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--med); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.finding-title { font-weight: bold; font-size: 1rem; }
.badge { padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
.badge.critical { background: var(--crit); color: white; }
.badge.high { background: var(--high); color: black; }
.badge.medium { background: var(--med); color: white; }
.badge.low { background: var(--low); color: white; }
.badge.info { background: var(--info); color: white; }
.finding-meta { color: var(--info); font-size: 0.85rem; margin-bottom: 0.5rem; }
.finding-evidence { background: #1c2128; padding: 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; margin: 0.5rem 0; word-break: break-all; }
.finding-fix { color: var(--green); font-size: 0.85rem; }
.section-title { font-size: 1.3rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
.graph-container { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; min-height: 300px; }
.servers { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
.server-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
.server-name { font-weight: bold; margin-bottom: 0.5rem; }
.tool-list { list-style: none; }
.tool-list li { padding: 2px 0; font-size: 0.85rem; color: var(--info); }
footer { text-align: center; color: var(--info); font-size: 0.8rem; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); }
</style>
</head>
<body>
<div class="container">
<h1>MCP-Lattice Security Report</h1>
<p class="subtitle">Generated: {{.GeneratedAt}}</p>

<div class="summary">
<div class="stat total"><div class="number">{{.TotalFindings}}</div><div>Total Findings</div></div>
<div class="stat critical"><div class="number">{{.Critical}}</div><div>Critical</div></div>
<div class="stat high"><div class="number">{{.High}}</div><div>High</div></div>
<div class="stat medium"><div class="number">{{.Medium}}</div><div>Medium</div></div>
<div class="stat low"><div class="number">{{.Low}}</div><div>Low</div></div>
<div class="stat info"><div class="number">{{.ServersScanned}}</div><div>Servers</div></div>
</div>

<h2 class="section-title">Findings</h2>
<div class="findings">
{{range .Findings}}
<div class="finding {{sevClass .Severity}}">
<div class="finding-header">
<span class="finding-title">{{.Title}}</span>
<span class="badge {{sevClass .Severity}}">{{upper .Severity.String}}</span>
</div>
<div class="finding-meta">
Server: {{.ServerName}}{{if .ToolName}} | Tool: {{.ToolName}}{{end}} | Layer: L{{.Layer}} | Confidence: {{printf "%.0f" (mul .Confidence 100)}}%
</div>
{{if .Evidence}}<div class="finding-evidence">{{truncate .Evidence 300}}</div>{{end}}
{{if .Remediation}}<div class="finding-fix">Fix: {{truncate .Remediation 200}}</div>{{end}}
</div>
{{end}}
</div>

<h2 class="section-title">Capability Graph</h2>
<div class="graph-container" id="graph">
<p style="color: var(--info);">Capability graph data available in JSON. Visualization requires a graph rendering library.</p>
<pre style="font-size: 0.75rem; overflow-x: auto; margin-top: 1rem;">{{.GraphJSON}}</pre>
</div>

<h2 class="section-title">Servers</h2>
<div class="servers">
{{range $name, $sr := .Servers}}
<div class="server-card">
<div class="server-name">{{$name}}</div>
<div style="color: var(--info); font-size: 0.85rem; margin-bottom: 0.5rem;">
{{if $sr.Connected}}Connected | {{len $sr.Tools}} tools | {{len $sr.Resources}} resources
{{else}}Connection failed: {{$sr.Error}}{{end}}
</div>
{{if $sr.Connected}}
<ul class="tool-list">
{{range $sr.Tools}}<li>{{.Name}}</li>{{end}}
</ul>
{{end}}
</div>
{{end}}
</div>

<footer>Generated by MCP-Lattice v0.1.0 | github.com/panavinsingh/MCP-Lattice</footer>
</div>
</body>
</html>`

// htmlFuncMap provides template functions for HTML rendering.
var htmlFuncMap = template.FuncMap{
	"mul": func(a, b float64) float64 { return a * b },
}
