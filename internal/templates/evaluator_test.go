// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"testing"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// mockPatternDetector implements PatternDetector for testing.
type mockPatternDetector struct {
	matchFunc func(text string, patterns []Pattern) (bool, string, float64)
}

func (m *mockPatternDetector) MatchPatterns(text string, patterns []Pattern) (bool, string, float64) {
	if m.matchFunc != nil {
		return m.matchFunc(text, patterns)
	}
	return false, "", 0
}

// mockSemanticDetector implements SemanticDetector for testing.
type mockSemanticDetector struct {
	matchFunc func(text string, intents []string, threshold float64) (bool, string, float64)
}

func (m *mockSemanticDetector) CheckIntents(text string, intents []string, threshold float64) (bool, string, float64) {
	if m.matchFunc != nil {
		return m.matchFunc(text, intents, threshold)
	}
	return false, "", 0
}

// mockGraphDetector implements GraphDetector for testing.
type mockGraphDetector struct {
	matchFunc func(tools []config.Tool, combinations [][]string) (bool, string, float64)
}

func (m *mockGraphDetector) CheckToxicCombinations(tools []config.Tool, combinations [][]string) (bool, string, float64) {
	if m.matchFunc != nil {
		return m.matchFunc(tools, combinations)
	}
	return false, "", 0
}

func TestEvaluator_PatternMatch_Positive(t *testing.T) {
	pd := &mockPatternDetector{
		matchFunc: func(text string, patterns []Pattern) (bool, string, float64) {
			return true, "pattern match: malicious content", 0.85
		},
	}

	eval := NewEvaluator(pd, nil, nil)

	tmpl := &Template{
		ID:   "test-pattern",
		Info: TemplateInfo{Name: "Pattern Test", Severity: "critical", Description: "Test desc", Remediation: "Fix it"},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{Type: "pattern", Part: "tool_description", Patterns: []Pattern{{Regex: ".*"}}},
			},
		},
	}

	ctx := &EvalContext{
		Tools: []config.Tool{
			{Name: "evil_tool", Description: "malicious description", ServerName: "bad-server"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if !result.Matched {
		t.Error("expected match from pattern detector")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Layer != 1 {
		t.Errorf("expected layer 1 for pattern, got %d", result.Findings[0].Layer)
	}
	if result.Findings[0].Severity != config.SeverityCritical {
		t.Errorf("expected critical severity, got %s", result.Findings[0].Severity.String())
	}
}

func TestEvaluator_PatternMatch_Negative(t *testing.T) {
	pd := &mockPatternDetector{
		matchFunc: func(text string, patterns []Pattern) (bool, string, float64) {
			return false, "", 0
		},
	}

	eval := NewEvaluator(pd, nil, nil)

	tmpl := &Template{
		ID:   "test-no-match",
		Info: TemplateInfo{Name: "Safe Test", Severity: "high"},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{Type: "pattern", Part: "tool_description", Patterns: []Pattern{{Regex: "evil"}}},
			},
		},
	}

	ctx := &EvalContext{
		Tools: []config.Tool{
			{Name: "safe_tool", Description: "Adds two numbers together", ServerName: "math-server"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if result.Matched {
		t.Error("expected no match for safe tool")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestEvaluator_SemanticMatch(t *testing.T) {
	sd := &mockSemanticDetector{
		matchFunc: func(text string, intents []string, threshold float64) (bool, string, float64) {
			return true, "exfiltrate data", 0.85
		},
	}

	eval := NewEvaluator(nil, sd, nil)

	tmpl := &Template{
		ID:   "test-semantic",
		Info: TemplateInfo{Name: "Semantic Test", Severity: "high", Description: "desc", Remediation: "fix"},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{
					Type:             "semantic",
					Part:             "tool_description",
					Threshold:        0.72,
					MaliciousIntents: []string{"exfiltrate data"},
				},
			},
		},
	}

	ctx := &EvalContext{
		Tools: []config.Tool{
			{Name: "exfil_tool", Description: "sends data to external server", ServerName: "bad"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if !result.Matched {
		t.Error("expected semantic match")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Layer != 2 {
		t.Errorf("expected layer 2 for semantic, got %d", result.Findings[0].Layer)
	}
}

func TestEvaluator_CapabilityGraphMatch(t *testing.T) {
	gd := &mockGraphDetector{
		matchFunc: func(tools []config.Tool, combinations [][]string) (bool, string, float64) {
			return true, "toxic combination: reads_filesystem + sends_http", 0.9
		},
	}

	eval := NewEvaluator(nil, nil, gd)

	tmpl := &Template{
		ID:   "test-capability",
		Info: TemplateInfo{Name: "Capability Test", Severity: "critical", Description: "desc", Remediation: "fix"},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{
					Type:              "capability_graph",
					ToxicCombinations: [][]string{{"reads_filesystem", "sends_http"}},
				},
			},
		},
	}

	ctx := &EvalContext{
		Tools: []config.Tool{
			{Name: "read_file", Description: "reads files", ServerName: "fs"},
			{Name: "http_post", Description: "posts to URL", ServerName: "net"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if !result.Matched {
		t.Error("expected capability graph match")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	if result.Findings[0].Layer != 3 {
		t.Errorf("expected layer 3 for capability_graph, got %d", result.Findings[0].Layer)
	}
}

func TestEvaluator_LengthAnalysis(t *testing.T) {
	eval := NewEvaluator(nil, nil, nil)

	tmpl := &Template{
		ID:   "test-length",
		Info: TemplateInfo{Name: "Length Test", Severity: "medium", Description: "desc", Remediation: "fix"},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{Type: "length", Part: "tool_description", LengthThreshold: 50},
			},
		},
	}

	t.Run("long description triggers", func(t *testing.T) {
		ctx := &EvalContext{
			Tools: []config.Tool{
				{Name: "verbose_tool", Description: "This is a very long description that exceeds the threshold of fifty characters by quite a margin", ServerName: "srv"},
			},
		}
		result := eval.Evaluate(tmpl, ctx)
		if !result.Matched {
			t.Error("expected match for long description")
		}
	})

	t.Run("short description does not trigger", func(t *testing.T) {
		ctx := &EvalContext{
			Tools: []config.Tool{
				{Name: "brief_tool", Description: "Short description", ServerName: "srv"},
			},
		}
		result := eval.Evaluate(tmpl, ctx)
		if result.Matched {
			t.Error("expected no match for short description")
		}
	})
}

func TestEvaluator_ToolFilter(t *testing.T) {
	pd := &mockPatternDetector{
		matchFunc: func(text string, patterns []Pattern) (bool, string, float64) {
			return true, "match", 0.85
		},
	}

	eval := NewEvaluator(pd, nil, nil)

	tmpl := &Template{
		ID:   "test-filter",
		Info: TemplateInfo{Name: "Filter Test", Severity: "high", Description: "desc", Remediation: "fix"},
		MCP: MCPCheck{
			Target:     "tools/list",
			ToolFilter: &ToolFilter{NameMatch: "read"},
			Analysis: []Analysis{
				{Type: "pattern", Part: "tool_description", Patterns: []Pattern{{Regex: ".*"}}},
			},
		},
	}

	ctx := &EvalContext{
		Tools: []config.Tool{
			{Name: "read_file", Description: "reads files", ServerName: "srv"},
			{Name: "write_file", Description: "writes files", ServerName: "srv"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if !result.Matched {
		t.Error("expected match for filtered tool")
	}
	// Only the read_file tool should match the filter
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding (filtered to 'read'), got %d", len(result.Findings))
	}
	if result.Findings[0].ToolName != "read_file" {
		t.Errorf("expected finding for 'read_file', got %q", result.Findings[0].ToolName)
	}
}

func TestEvaluator_ConnectionTarget(t *testing.T) {
	pd := &mockPatternDetector{
		matchFunc: func(text string, patterns []Pattern) (bool, string, float64) {
			if text == "" {
				return false, "", 0
			}
			return true, "suspicious command", 0.8
		},
	}

	eval := NewEvaluator(pd, nil, nil)

	tmpl := &Template{
		ID:   "test-connection",
		Info: TemplateInfo{Name: "Connection Test", Severity: "high", Description: "desc", Remediation: "fix"},
		MCP: MCPCheck{
			Target: "connection",
			Analysis: []Analysis{
				{Type: "pattern", Patterns: []Pattern{{Regex: ".*"}}},
			},
		},
	}

	ctx := &EvalContext{
		Server: config.MCPServerConfig{
			Name:    "test-server",
			Command: "npx",
			Args:    []string{"-y", "malicious-package"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if !result.Matched {
		t.Error("expected connection-level pattern match")
	}
}

func TestEvaluator_FindingFields(t *testing.T) {
	pd := &mockPatternDetector{
		matchFunc: func(text string, patterns []Pattern) (bool, string, float64) {
			return true, "found malicious pattern", 0.9
		},
	}

	eval := NewEvaluator(pd, nil, nil)

	tmpl := &Template{
		ID: "CVE-2025-0001",
		Info: TemplateInfo{
			Name:        "Test Finding Fields",
			Severity:    "critical",
			Description: "Detects a specific vulnerability",
			Remediation: "Update to latest version",
			References:  []string{"https://cve.example.com/CVE-2025-0001"},
			Tags:        []string{"tool-poisoning", "exfiltration"},
		},
		Classification: Classification{
			AttackClass:   "tool-poisoning",
			CosaiCategory: 2,
			OwaspAgentic:  "ASI02",
			CVE:           "CVE-2025-0001",
		},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{Type: "pattern", Part: "tool_description", Patterns: []Pattern{{Regex: ".*"}}},
			},
		},
	}

	ctx := &EvalContext{
		Tools: []config.Tool{
			{Name: "evil", Description: "malicious", ServerName: "bad-server"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.TemplateID != "CVE-2025-0001" {
		t.Errorf("TemplateID = %q, want CVE-2025-0001", f.TemplateID)
	}
	if f.ServerName != "bad-server" {
		t.Errorf("ServerName = %q, want bad-server", f.ServerName)
	}
	if f.ToolName != "evil" {
		t.Errorf("ToolName = %q, want evil", f.ToolName)
	}
	if f.Classification.CVE != "CVE-2025-0001" {
		t.Errorf("CVE = %q, want CVE-2025-0001", f.Classification.CVE)
	}
	if f.Classification.AttackClass != "tool-poisoning" {
		t.Errorf("AttackClass = %q, want tool-poisoning", f.Classification.AttackClass)
	}
	if len(f.Tags) != 2 {
		t.Errorf("Tags len = %d, want 2", len(f.Tags))
	}
}

func TestEvaluator_NilDetectors(t *testing.T) {
	// All detectors nil should not panic
	eval := NewEvaluator(nil, nil, nil)

	tmpl := &Template{
		ID:   "test-nil",
		Info: TemplateInfo{Name: "Nil Test", Severity: "info"},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{Type: "pattern", Part: "tool_description"},
				{Type: "semantic", Part: "tool_description"},
				{Type: "capability_graph"},
			},
		},
	}

	ctx := &EvalContext{
		Tools: []config.Tool{
			{Name: "tool", Description: "some text", ServerName: "srv"},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if result.Matched {
		t.Error("expected no match with nil detectors")
	}
}

func TestAnalysisTypeToLayer(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"pattern", 1},
		{"semantic", 2},
		{"capability_graph", 3},
		{"unknown", 1},
		{"", 1},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := analysisTypeToLayer(tt.input)
			if got != tt.expected {
				t.Errorf("analysisTypeToLayer(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetAnalysisPart(t *testing.T) {
	tool := config.Tool{
		Name:        "test_tool",
		Description: "A test tool description",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"input": map[string]interface{}{"type": "string"},
			},
		},
	}

	tests := []struct {
		part     string
		expected string
	}{
		{"tool_description", "A test tool description"},
		{"tool_name", "test_tool"},
		{"input_schema", ""}, // non-empty JSON
		{"", "A test tool description"},
	}

	for _, tt := range tests {
		t.Run(tt.part, func(t *testing.T) {
			got := getAnalysisPart(tool, tt.part)
			if tt.part == "input_schema" {
				if got == "" {
					t.Error("expected non-empty input_schema JSON")
				}
			} else {
				if got != tt.expected {
					t.Errorf("getAnalysisPart(%q) = %q, want %q", tt.part, got, tt.expected)
				}
			}
		})
	}
}

func TestEvaluator_ConfigTarget(t *testing.T) {
	pd := &mockPatternDetector{
		matchFunc: func(text string, patterns []Pattern) (bool, string, float64) {
			if text == "" {
				return false, "", 0
			}
			return true, "sensitive env var", 0.8
		},
	}

	eval := NewEvaluator(pd, nil, nil)

	tmpl := &Template{
		ID:   "test-config",
		Info: TemplateInfo{Name: "Config Test", Severity: "high", Description: "desc", Remediation: "fix"},
		MCP: MCPCheck{
			Target: "config",
			Analysis: []Analysis{
				{Type: "pattern", Patterns: []Pattern{{Regex: ".*"}}},
			},
		},
	}

	ctx := &EvalContext{
		Server: config.MCPServerConfig{
			Name: "test-server",
			Env: map[string]string{
				"API_KEY": "sk-secret-value",
			},
		},
	}

	result := eval.Evaluate(tmpl, ctx)
	if !result.Matched {
		t.Error("expected config-level pattern match on env vars")
	}
}
