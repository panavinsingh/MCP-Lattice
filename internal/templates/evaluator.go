// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// EvalContext provides data for template evaluation.
type EvalContext struct {
	Server    config.MCPServerConfig
	Tools     []config.Tool
	Resources []config.Resource
}

// EvalResult captures the output of evaluating a template.
type EvalResult struct {
	Matched  bool
	Findings []config.Finding
}

// Evaluator runs templates against MCP server data.
type Evaluator struct {
	patternDetector  PatternDetector
	semanticDetector SemanticDetector
	graphDetector    GraphDetector
}

// PatternDetector interface for L1 detection.
type PatternDetector interface {
	MatchPatterns(text string, patterns []Pattern) (bool, string, float64)
}

// SemanticDetector interface for L2 detection.
type SemanticDetector interface {
	CheckIntents(text string, intents []string, threshold float64) (bool, string, float64)
}

// GraphDetector interface for L3 detection.
type GraphDetector interface {
	CheckToxicCombinations(tools []config.Tool, combinations [][]string) (bool, string, float64)
}

// NewEvaluator creates a template evaluator with the given detectors.
func NewEvaluator(pd PatternDetector, sd SemanticDetector, gd GraphDetector) *Evaluator {
	return &Evaluator{
		patternDetector:  pd,
		semanticDetector: sd,
		graphDetector:    gd,
	}
}

// Evaluate runs a template against the given context.
func (e *Evaluator) Evaluate(tmpl *Template, ctx *EvalContext) *EvalResult {
	result := &EvalResult{}

	severity, _ := config.ParseSeverity(tmpl.Info.Severity)

	switch tmpl.MCP.Target {
	case "tools/list":
		e.evaluateToolsList(tmpl, ctx, result, severity)
	case "connection":
		e.evaluateConnection(tmpl, ctx, result, severity)
	case "resources/list":
		e.evaluateResourcesList(tmpl, ctx, result, severity)
	case "config":
		e.evaluateConfig(tmpl, ctx, result, severity)
	}

	return result
}

func (e *Evaluator) evaluateToolsList(tmpl *Template, ctx *EvalContext, result *EvalResult, severity config.Severity) {
	for _, tool := range ctx.Tools {
		// Check if tool matches filter
		if tmpl.MCP.ToolFilter != nil && !matchesFilter(tool, tmpl.MCP.ToolFilter) {
			continue
		}

		for _, analysis := range tmpl.MCP.Analysis {
			text := getAnalysisPart(tool, analysis.Part)
			if text == "" {
				continue
			}

			var matched bool
			var evidence string
			var confidence float64

			switch analysis.Type {
			case "pattern":
				if e.patternDetector != nil {
					matched, evidence, confidence = e.patternDetector.MatchPatterns(text, analysis.Patterns)
				}
			case "semantic":
				if e.semanticDetector != nil {
					threshold := analysis.Threshold
					if threshold == 0 {
						threshold = 0.72
					}
					matched, evidence, confidence = e.semanticDetector.CheckIntents(text, analysis.MaliciousIntents, threshold)
				}
			case "capability_graph":
				if e.graphDetector != nil {
					matched, evidence, confidence = e.graphDetector.CheckToxicCombinations(ctx.Tools, analysis.ToxicCombinations)
				}
			case "length":
				if analysis.LengthThreshold > 0 && len(text) > analysis.LengthThreshold {
					matched = true
					evidence = fmt.Sprintf("description length %d exceeds threshold %d", len(text), analysis.LengthThreshold)
					confidence = 0.6
				}
			}

			if matched {
				result.Matched = true
				result.Findings = append(result.Findings, config.Finding{
					ID:          fmt.Sprintf("%s-%s-%s", tmpl.ID, tool.ServerName, tool.Name),
					TemplateID:  tmpl.ID,
					ServerName:  tool.ServerName,
					ToolName:    tool.Name,
					Severity:    severity,
					Title:       tmpl.Info.Name,
					Description: tmpl.Info.Description,
					Evidence:    evidence,
					Remediation: tmpl.Info.Remediation,
					References:  tmpl.Info.References,
					Layer:       analysisTypeToLayer(analysis.Type),
					Confidence:  confidence,
					Tags:        tmpl.Info.Tags,
					Classification: config.Classification{
						AttackClass:   tmpl.Classification.AttackClass,
						CosaiCategory: tmpl.Classification.CosaiCategory,
						OwaspAgentic:  tmpl.Classification.OwaspAgentic,
						CVE:           tmpl.Classification.CVE,
					},
				})
			}
		}
	}
}

func (e *Evaluator) evaluateConnection(tmpl *Template, ctx *EvalContext, result *EvalResult, severity config.Severity) {
	// Connection-level checks (auth probes, binding checks, etc.)
	// These operate on the server config itself
	for _, analysis := range tmpl.MCP.Analysis {
		switch analysis.Type {
		case "pattern":
			// Check command/args for patterns
			text := ctx.Server.Command + " " + joinArgs(ctx.Server.Args)
			if e.patternDetector != nil {
				matched, evidence, confidence := e.patternDetector.MatchPatterns(text, analysis.Patterns)
				if matched {
					result.Matched = true
					result.Findings = append(result.Findings, config.Finding{
						ID:          fmt.Sprintf("%s-%s", tmpl.ID, ctx.Server.Name),
						TemplateID:  tmpl.ID,
						ServerName:  ctx.Server.Name,
						Severity:    severity,
						Title:       tmpl.Info.Name,
						Description: tmpl.Info.Description,
						Evidence:    evidence,
						Remediation: tmpl.Info.Remediation,
						References:  tmpl.Info.References,
						Layer:       1,
						Confidence:  confidence,
						Tags:        tmpl.Info.Tags,
						Classification: config.Classification{
							AttackClass:   tmpl.Classification.AttackClass,
							CosaiCategory: tmpl.Classification.CosaiCategory,
							OwaspAgentic:  tmpl.Classification.OwaspAgentic,
							CVE:           tmpl.Classification.CVE,
						},
					})
				}
			}
		}
	}
}

func (e *Evaluator) evaluateResourcesList(tmpl *Template, ctx *EvalContext, result *EvalResult, severity config.Severity) {
	for _, resource := range ctx.Resources {
		for _, analysis := range tmpl.MCP.Analysis {
			text := getResourcePart(resource, analysis.Part)
			if text == "" {
				continue
			}

			if analysis.Type == "pattern" && e.patternDetector != nil {
				matched, evidence, confidence := e.patternDetector.MatchPatterns(text, analysis.Patterns)
				if matched {
					result.Matched = true
					result.Findings = append(result.Findings, config.Finding{
						ID:          fmt.Sprintf("%s-%s-%s", tmpl.ID, resource.ServerName, resource.Name),
						TemplateID:  tmpl.ID,
						ServerName:  resource.ServerName,
						Severity:    severity,
						Title:       tmpl.Info.Name,
						Description: tmpl.Info.Description,
						Evidence:    evidence,
						Remediation: tmpl.Info.Remediation,
						References:  tmpl.Info.References,
						Layer:       1,
						Confidence:  confidence,
						Tags:        tmpl.Info.Tags,
						Classification: config.Classification{
							AttackClass:   tmpl.Classification.AttackClass,
							CosaiCategory: tmpl.Classification.CosaiCategory,
							OwaspAgentic:  tmpl.Classification.OwaspAgentic,
							CVE:           tmpl.Classification.CVE,
						},
					})
				}
			}
		}
	}
}

func (e *Evaluator) evaluateConfig(tmpl *Template, ctx *EvalContext, result *EvalResult, severity config.Severity) {
	// Config-level checks (env vars, credentials in config, etc.)
	for _, analysis := range tmpl.MCP.Analysis {
		if analysis.Type == "pattern" && e.patternDetector != nil {
			// Check env vars for sensitive data
			for k, v := range ctx.Server.Env {
				text := k + "=" + v
				matched, evidence, confidence := e.patternDetector.MatchPatterns(text, analysis.Patterns)
				if matched {
					result.Matched = true
					result.Findings = append(result.Findings, config.Finding{
						ID:          fmt.Sprintf("%s-%s-env", tmpl.ID, ctx.Server.Name),
						TemplateID:  tmpl.ID,
						ServerName:  ctx.Server.Name,
						Severity:    severity,
						Title:       tmpl.Info.Name,
						Description: tmpl.Info.Description,
						Evidence:    evidence,
						Remediation: tmpl.Info.Remediation,
						References:  tmpl.Info.References,
						Layer:       1,
						Confidence:  confidence,
						Tags:        tmpl.Info.Tags,
						Classification: config.Classification{
							AttackClass:   tmpl.Classification.AttackClass,
							CosaiCategory: tmpl.Classification.CosaiCategory,
							OwaspAgentic:  tmpl.Classification.OwaspAgentic,
							CVE:           tmpl.Classification.CVE,
						},
					})
				}
			}
		}
	}
}

func getAnalysisPart(tool config.Tool, part string) string {
	switch part {
	case "tool_description":
		return tool.Description
	case "tool_name":
		return tool.Name
	case "input_schema":
		if tool.InputSchema != nil {
			data, _ := json.Marshal(tool.InputSchema)
			return string(data)
		}
		return ""
	default:
		return tool.Description
	}
}

func getResourcePart(resource config.Resource, part string) string {
	switch part {
	case "resource_uri":
		return resource.URI
	case "resource_description":
		return resource.Description
	default:
		return resource.URI
	}
}

func matchesFilter(tool config.Tool, filter *ToolFilter) bool {
	if filter.NameMatch != "" {
		if !containsIgnoreCase(tool.Name, filter.NameMatch) {
			return false
		}
	}

	if len(filter.ParamTypes) > 0 && tool.InputSchema != nil {
		props, ok := tool.InputSchema["properties"].(map[string]interface{})
		if !ok {
			return false
		}
		found := false
		for paramName := range props {
			for _, pt := range filter.ParamTypes {
				if containsIgnoreCase(paramName, pt) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(substr) == 0 ||
		findIgnoreCase(s, substr))
}

func findIgnoreCase(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}

func joinArgs(args []string) string {
	return strings.Join(args, " ")
}

func analysisTypeToLayer(t string) int {
	switch t {
	case "pattern":
		return 1
	case "semantic":
		return 2
	case "capability_graph":
		return 3
	default:
		return 1
	}
}
