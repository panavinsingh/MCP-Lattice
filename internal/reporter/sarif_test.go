// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

func TestSARIFReporter_Report_EmptyFindings(t *testing.T) {
	reporter := NewSARIFReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	var sarif sarifLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("failed to parse SARIF output: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("Version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	if sarif.Runs[0].Tool.Driver.Name != "MCP-Lattice" {
		t.Errorf("Driver.Name = %q, want MCP-Lattice", sarif.Runs[0].Tool.Driver.Name)
	}
	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(sarif.Runs[0].Results))
	}
}

func TestSARIFReporter_Report_SingleFinding(t *testing.T) {
	reporter := NewSARIFReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{
			{
				ID:          "finding-001",
				TemplateID:  "tool-poisoning-001",
				ServerName:  "evil-server",
				ToolName:    "exfil_tool",
				Severity:    config.SeverityCritical,
				Title:       "Tool Poisoning Detected",
				Description: "Tool contains malicious description",
				Evidence:    "pattern match: send to evil.com",
				Remediation: "Remove the tool",
				Layer:       1,
				Confidence:  0.95,
				Tags:        []string{"tool-poisoning"},
				Classification: config.Classification{
					AttackClass:  "tool-poisoning",
					OwaspAgentic: "ASI02",
				},
			},
		},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	var sarif sarifLog
	json.Unmarshal(buf.Bytes(), &sarif)

	run := sarif.Runs[0]

	// Check rules
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(run.Tool.Driver.Rules))
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "tool-poisoning-001" {
		t.Errorf("Rule.ID = %q, want tool-poisoning-001", rule.ID)
	}
	if rule.DefaultConfig.Level != "error" {
		t.Errorf("Rule.Level = %q, want error (for critical)", rule.DefaultConfig.Level)
	}

	// Check results
	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != "tool-poisoning-001" {
		t.Errorf("Result.RuleID = %q, want tool-poisoning-001", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("Result.Level = %q, want error", r.Level)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}
	expectedURI := "mcp://evil-server/exfil_tool"
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != expectedURI {
		t.Errorf("Location URI = %q, want %q", r.Locations[0].PhysicalLocation.ArtifactLocation.URI, expectedURI)
	}
}

func TestSARIFReporter_Report_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity      config.Severity
		expectedLevel string
	}{
		{config.SeverityCritical, "error"},
		{config.SeverityHigh, "error"},
		{config.SeverityMedium, "warning"},
		{config.SeverityLow, "note"},
		{config.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			level := severityToSARIF(tt.severity)
			if level != tt.expectedLevel {
				t.Errorf("severityToSARIF(%s) = %q, want %q", tt.severity.String(), level, tt.expectedLevel)
			}
		})
	}
}

func TestSARIFReporter_Report_MultipleFindings(t *testing.T) {
	reporter := NewSARIFReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{
			{
				ID: "f1", TemplateID: "t1", ServerName: "s1", ToolName: "tool1",
				Severity: config.SeverityCritical, Title: "Critical Finding",
				Description: "d1", Remediation: "r1", Layer: 1, Confidence: 0.9,
			},
			{
				ID: "f2", TemplateID: "t2", ServerName: "s2", ToolName: "tool2",
				Severity: config.SeverityMedium, Title: "Medium Finding",
				Description: "d2", Remediation: "r2", Layer: 2, Confidence: 0.7,
			},
			{
				ID: "f3", TemplateID: "t3", ServerName: "s3", ToolName: "tool3",
				Severity: config.SeverityLow, Title: "Low Finding",
				Description: "d3", Remediation: "r3", Layer: 3, Confidence: 0.5,
			},
		},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	var sarif sarifLog
	json.Unmarshal(buf.Bytes(), &sarif)

	run := sarif.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(run.Results))
	}

	// Verify each result has the correct level
	expectedLevels := []string{"error", "warning", "note"}
	for i, r := range run.Results {
		if r.Level != expectedLevels[i] {
			t.Errorf("result %d: Level = %q, want %q", i, r.Level, expectedLevels[i])
		}
	}
}

func TestSARIFReporter_Report_DuplicateTemplateIDs(t *testing.T) {
	reporter := NewSARIFReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{
			{
				ID: "f1", TemplateID: "same-template", ServerName: "s1", ToolName: "t1",
				Severity: config.SeverityHigh, Title: "Finding 1", Description: "d1", Remediation: "r1",
			},
			{
				ID: "f2", TemplateID: "same-template", ServerName: "s2", ToolName: "t2",
				Severity: config.SeverityHigh, Title: "Finding 1", Description: "d1", Remediation: "r1",
			},
		},
	}

	var buf bytes.Buffer
	reporter.Report(&buf, result)

	var sarif sarifLog
	json.Unmarshal(buf.Bytes(), &sarif)

	// Rules should be deduplicated by template ID
	if len(sarif.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 rule (deduplicated), got %d", len(sarif.Runs[0].Tool.Driver.Rules))
	}
	// But results should not be deduplicated
	if len(sarif.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(sarif.Runs[0].Results))
	}
}

func TestSARIFReporter_Report_ValidJSON(t *testing.T) {
	reporter := NewSARIFReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{
			{
				ID: "valid-json", TemplateID: "t1",
				Severity:    config.SeverityHigh,
				Title:       "Test with \"quotes\" and\nnewlines",
				Description: "Description <with> special & chars",
				Remediation: "fix",
			},
		},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Error("SARIF output is not valid JSON")
	}
}

func TestSARIFReporter_Report_SchemaAndVersion(t *testing.T) {
	reporter := NewSARIFReporter()
	result := &config.ScanResult{Findings: []config.Finding{}}

	var buf bytes.Buffer
	reporter.Report(&buf, result)

	var sarif sarifLog
	json.Unmarshal(buf.Bytes(), &sarif)

	if sarif.Version != "2.1.0" {
		t.Errorf("Version = %q, want 2.1.0", sarif.Version)
	}
	expectedSchema := "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	if sarif.Schema != expectedSchema {
		t.Errorf("Schema = %q, want %q", sarif.Schema, expectedSchema)
	}
}

func TestSARIFReporter_Report_Properties(t *testing.T) {
	reporter := NewSARIFReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{
			{
				ID: "prop-test", TemplateID: "t1", ServerName: "srv", ToolName: "tool",
				Severity: config.SeverityHigh, Title: "Props", Description: "d", Remediation: "r",
				Layer: 2, Confidence: 0.88,
			},
		},
	}

	var buf bytes.Buffer
	reporter.Report(&buf, result)

	var sarif sarifLog
	json.Unmarshal(buf.Bytes(), &sarif)

	r := sarif.Runs[0].Results[0]
	if r.Properties == nil {
		t.Fatal("expected properties on result")
	}

	if r.Properties["server"] != "srv" {
		t.Errorf("Properties[server] = %v, want srv", r.Properties["server"])
	}
	if r.Properties["tool"] != "tool" {
		t.Errorf("Properties[tool] = %v, want tool", r.Properties["tool"])
	}

	// Layer is stored as float64 in JSON
	if layer, ok := r.Properties["layer"].(float64); !ok || layer != 2 {
		t.Errorf("Properties[layer] = %v, want 2", r.Properties["layer"])
	}
}

func TestSARIFReporter_Report_EvidenceInMessage(t *testing.T) {
	reporter := NewSARIFReporter()

	t.Run("with evidence", func(t *testing.T) {
		result := &config.ScanResult{
			Findings: []config.Finding{
				{
					ID: "ev1", TemplateID: "t1", Severity: config.SeverityHigh,
					Title: "Detection", Evidence: "found malicious pattern",
					Description: "d", Remediation: "r",
				},
			},
		}

		var buf bytes.Buffer
		reporter.Report(&buf, result)

		var sarif sarifLog
		json.Unmarshal(buf.Bytes(), &sarif)

		msg := sarif.Runs[0].Results[0].Message.Text
		if msg != "Detection: found malicious pattern" {
			t.Errorf("Message = %q, want 'Detection: found malicious pattern'", msg)
		}
	})

	t.Run("without evidence", func(t *testing.T) {
		result := &config.ScanResult{
			Findings: []config.Finding{
				{
					ID: "ev2", TemplateID: "t2", Severity: config.SeverityHigh,
					Title: "Detection", Description: "d", Remediation: "r",
				},
			},
		}

		var buf bytes.Buffer
		reporter.Report(&buf, result)

		var sarif sarifLog
		json.Unmarshal(buf.Bytes(), &sarif)

		msg := sarif.Runs[0].Results[0].Message.Text
		if msg != "Detection" {
			t.Errorf("Message = %q, want 'Detection'", msg)
		}
	})
}

func TestBuildRules(t *testing.T) {
	findings := []config.Finding{
		{
			TemplateID:  "t1",
			Title:       "Rule One",
			Description: "First rule description",
			Severity:    config.SeverityCritical,
			Remediation: "Fix rule one",
			Tags:        []string{"tag1"},
			Classification: config.Classification{
				AttackClass:  "class1",
				OwaspAgentic: "ASI01",
			},
		},
		{
			TemplateID:  "t2",
			Title:       "Rule Two",
			Description: "Second rule",
			Severity:    config.SeverityMedium,
			Remediation: "Fix rule two",
		},
	}

	rules := buildRules(findings)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].ID != "t1" {
		t.Errorf("rules[0].ID = %q, want t1", rules[0].ID)
	}
	if rules[0].DefaultConfig.Level != "error" {
		t.Errorf("rules[0].Level = %q, want error", rules[0].DefaultConfig.Level)
	}
	if rules[1].DefaultConfig.Level != "warning" {
		t.Errorf("rules[1].Level = %q, want warning", rules[1].DefaultConfig.Level)
	}
}
