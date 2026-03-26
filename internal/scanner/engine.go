// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package scanner orchestrates the MCP security scanning process.
package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
	"github.com/panavinsingh/MCP-Lattice/internal/connector"
	"github.com/panavinsingh/MCP-Lattice/internal/detection"
	"github.com/panavinsingh/MCP-Lattice/internal/templates"
)

// Engine is the core scanning orchestrator.
type Engine struct {
	cfg       *config.ScanConfig
	templates []*templates.Template
	evaluator *templates.Evaluator
	capEngine *detection.CapabilityEngine

	// Progress callback
	OnProgress func(serverName string, status string)
}

// NewEngine creates a new scanning engine.
func NewEngine(cfg *config.ScanConfig, tmpls []*templates.Template) *Engine {
	patternEngine := detection.NewPatternEngine()
	semanticEngine := detection.NewSemanticEngine()
	capEngine := detection.NewCapabilityEngine()

	var sd templates.SemanticDetector
	if cfg.EnableL2 {
		sd = semanticEngine
	}

	var gd templates.GraphDetector
	if cfg.EnableL3 {
		gd = capEngine
	}

	evaluator := templates.NewEvaluator(patternEngine, sd, gd)

	return &Engine{
		cfg:       cfg,
		templates: tmpls,
		evaluator: evaluator,
		capEngine: capEngine,
	}
}

// Scan runs a full scan against the provided MCP server configs.
func (e *Engine) Scan(ctx context.Context, servers []config.MCPServerConfig) (*config.ScanResult, error) {
	result := &config.ScanResult{
		Servers: make(map[string]*config.ServerResult),
	}

	// Phase 1: Connect to all servers and enumerate tools
	e.progress("", "Connecting to MCP servers...")
	serverResults := e.enumerateServers(ctx, servers)

	for name, sr := range serverResults {
		result.Servers[name] = sr
		if sr.Connected {
			result.ServersFound++
			result.ToolsScanned += len(sr.Tools)
		}
	}

	// Phase 2: Run templates against each server
	e.progress("", "Running detection templates...")
	var allFindings []config.Finding

	for _, sr := range serverResults {
		if !sr.Connected {
			continue
		}

		evalCtx := &templates.EvalContext{
			Server:    sr.Config,
			Tools:     sr.Tools,
			Resources: sr.Resources,
		}

		for _, tmpl := range e.templates {
			evalResult := e.evaluator.Evaluate(tmpl, evalCtx)
			if evalResult.Matched {
				allFindings = append(allFindings, evalResult.Findings...)
			}
		}
	}

	// Phase 3: Cross-server capability graph analysis
	if e.cfg.EnableL3 {
		e.progress("", "Running capability graph analysis...")
		graphFindings := e.runCapabilityGraphAnalysis(serverResults)
		result.GraphFindings = graphFindings
		allFindings = append(allFindings, graphFindings...)
	}

	// Filter by severity threshold
	for _, f := range allFindings {
		if f.Severity >= e.cfg.SeverityThreshold {
			result.Findings = append(result.Findings, f)
		}
	}

	return result, nil
}

// ScanOffline runs templates against pre-collected server data (no connections).
func (e *Engine) ScanOffline(servers map[string]*config.ServerResult) (*config.ScanResult, error) {
	result := &config.ScanResult{
		Servers: servers,
	}

	var allFindings []config.Finding

	for _, sr := range servers {
		result.ServersFound++
		result.ToolsScanned += len(sr.Tools)

		evalCtx := &templates.EvalContext{
			Server:    sr.Config,
			Tools:     sr.Tools,
			Resources: sr.Resources,
		}

		for _, tmpl := range e.templates {
			evalResult := e.evaluator.Evaluate(tmpl, evalCtx)
			if evalResult.Matched {
				allFindings = append(allFindings, evalResult.Findings...)
			}
		}
	}

	// Filter by severity threshold
	for _, f := range allFindings {
		if f.Severity >= e.cfg.SeverityThreshold {
			result.Findings = append(result.Findings, f)
		}
	}

	return result, nil
}

// enumerateServers connects to each server and collects tools/resources.
func (e *Engine) enumerateServers(ctx context.Context, servers []config.MCPServerConfig) map[string]*config.ServerResult {
	results := make(map[string]*config.ServerResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, e.cfg.Concurrency)

	for _, server := range servers {
		wg.Add(1)
		go func(srv config.MCPServerConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			sr := e.enumerateServer(ctx, srv)

			mu.Lock()
			results[srv.Name] = sr
			mu.Unlock()
		}(server)
	}

	wg.Wait()
	return results
}

// enumerateServer connects to a single server and collects its tools/resources.
func (e *Engine) enumerateServer(ctx context.Context, srv config.MCPServerConfig) *config.ServerResult {
	sr := &config.ServerResult{
		Config: srv,
	}

	timeout := time.Duration(e.cfg.Timeout) * time.Second
	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	e.progress(srv.Name, "connecting...")

	client := connector.NewClient(srv)
	defer client.Close()

	if err := client.Connect(connCtx); err != nil {
		sr.Error = fmt.Sprintf("connection failed: %v", err)
		e.progress(srv.Name, "failed")
		return sr
	}

	sr.Connected = true
	e.progress(srv.Name, "connected, enumerating tools...")

	// List tools
	tools, err := client.ListTools(connCtx)
	if err != nil {
		sr.Error = fmt.Sprintf("tools/list failed: %v", err)
	} else {
		sr.Tools = tools
	}

	// List resources
	resources, err := client.ListResources(connCtx)
	if err == nil {
		sr.Resources = resources
	}

	e.progress(srv.Name, fmt.Sprintf("found %d tools, %d resources", len(sr.Tools), len(sr.Resources)))

	return sr
}

// runCapabilityGraphAnalysis performs cross-server capability graph analysis.
func (e *Engine) runCapabilityGraphAnalysis(servers map[string]*config.ServerResult) []config.Finding {
	// Collect all tools across all servers
	var allTools []config.Tool
	for _, sr := range servers {
		if sr.Connected {
			allTools = append(allTools, sr.Tools...)
		}
	}

	if len(allTools) < 2 {
		return nil
	}

	// Build capability graph
	graph := detection.NewCapabilityGraph()
	graph.BuildFromTools(allTools)

	// Find toxic combinations
	toxics := graph.FindToxicCombinations()

	var findings []config.Finding
	for _, tc := range toxics {
		capNames := make([]string, len(tc.Capabilities))
		for i, c := range tc.Capabilities {
			capNames[i] = string(c)
		}

		findings = append(findings, config.Finding{
			ID:          fmt.Sprintf("capability-graph-%s", joinCaps(capNames)),
			TemplateID:  "capability-graph-analysis",
			ServerName:  "cross-server",
			Severity:    tc.Severity,
			Title:       "Toxic Capability Combination Detected",
			Description: tc.Description,
			Evidence:    fmt.Sprintf("Tools involved: %s", joinCaps(tc.Tools)),
			Remediation: "Review the tool combination and consider restricting capabilities. Apply the principle of least privilege to each MCP server. Use separate servers for read-only and write/network operations.",
			Layer:       3,
			Confidence:  0.9,
			Tags:        []string{"capability-graph", "cross-server"},
			Classification: config.Classification{
				AttackClass:   "capability-graph",
				CosaiCategory: 7,
				OwaspAgentic:  "ASI10",
			},
		})
	}

	return findings
}

func (e *Engine) progress(server, status string) {
	if e.OnProgress != nil {
		e.OnProgress(server, status)
	}
}

func joinCaps(caps []string) string {
	result := ""
	for i, c := range caps {
		if i > 0 {
			result += ", "
		}
		result += c
	}
	return result
}
