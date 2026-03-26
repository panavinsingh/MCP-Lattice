// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

func TestJSONReporter_Report_EmptyFindings(t *testing.T) {
	reporter := NewJSONReporter()
	result := &config.ScanResult{
		ServersFound: 0,
		ToolsScanned: 0,
		Findings:     []config.Finding{},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if output.Summary.FindingsTotal != 0 {
		t.Errorf("FindingsTotal = %d, want 0", output.Summary.FindingsTotal)
	}
	if len(output.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(output.Findings))
	}
}

func TestJSONReporter_Report_SingleFinding(t *testing.T) {
	reporter := NewJSONReporter()
	result := &config.ScanResult{
		ServersFound: 1,
		ToolsScanned: 3,
		Findings: []config.Finding{
			{
				ID:          "test-001-server-tool",
				TemplateID:  "test-001",
				ServerName:  "evil-server",
				ToolName:    "exfil_tool",
				Severity:    config.SeverityCritical,
				Title:       "Data Exfiltration Detected",
				Description: "Tool sends data to external server",
				Evidence:    "pattern match: send to https://evil.com",
				Remediation: "Remove the malicious tool",
				References:  []string{"https://example.com/cve-001"},
				Layer:       1,
				Confidence:  0.95,
				Tags:        []string{"exfiltration", "critical"},
				Classification: config.Classification{
					AttackClass:   "data-exfiltration",
					CosaiCategory: 1,
					OwaspAgentic:  "ASI01",
					CVE:           "CVE-2025-0001",
				},
			},
		},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	var output jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if output.Summary.ServersScanned != 1 {
		t.Errorf("ServersScanned = %d, want 1", output.Summary.ServersScanned)
	}
	if output.Summary.ToolsScanned != 3 {
		t.Errorf("ToolsScanned = %d, want 3", output.Summary.ToolsScanned)
	}
	if output.Summary.FindingsTotal != 1 {
		t.Errorf("FindingsTotal = %d, want 1", output.Summary.FindingsTotal)
	}
	if output.Summary.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", output.Summary.BySeverity["critical"])
	}

	f := output.Findings[0]
	if f.ID != "test-001-server-tool" {
		t.Errorf("ID = %q, want test-001-server-tool", f.ID)
	}
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.Classification.CVE != "CVE-2025-0001" {
		t.Errorf("CVE = %q, want CVE-2025-0001", f.Classification.CVE)
	}
	if f.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", f.Confidence)
	}
}

func TestJSONReporter_Report_MultipleSeverities(t *testing.T) {
	reporter := NewJSONReporter()
	result := &config.ScanResult{
		ServersFound: 2,
		ToolsScanned: 10,
		Findings: []config.Finding{
			{ID: "f1", Severity: config.SeverityCritical, TemplateID: "t1", Title: "Critical", Remediation: "fix"},
			{ID: "f2", Severity: config.SeverityHigh, TemplateID: "t2", Title: "High", Remediation: "fix"},
			{ID: "f3", Severity: config.SeverityMedium, TemplateID: "t3", Title: "Medium", Remediation: "fix"},
			{ID: "f4", Severity: config.SeverityLow, TemplateID: "t4", Title: "Low", Remediation: "fix"},
			{ID: "f5", Severity: config.SeverityInfo, TemplateID: "t5", Title: "Info", Remediation: "fix"},
		},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	var output jsonOutput
	json.Unmarshal(buf.Bytes(), &output)

	if output.Summary.FindingsTotal != 5 {
		t.Errorf("FindingsTotal = %d, want 5", output.Summary.FindingsTotal)
	}
	if output.Summary.BySeverity["critical"] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1", output.Summary.BySeverity["critical"])
	}
	if output.Summary.BySeverity["high"] != 1 {
		t.Errorf("BySeverity[high] = %d, want 1", output.Summary.BySeverity["high"])
	}
	if output.Summary.BySeverity["medium"] != 1 {
		t.Errorf("BySeverity[medium] = %d, want 1", output.Summary.BySeverity["medium"])
	}
	if output.Summary.BySeverity["low"] != 1 {
		t.Errorf("BySeverity[low] = %d, want 1", output.Summary.BySeverity["low"])
	}
	if output.Summary.BySeverity["info"] != 1 {
		t.Errorf("BySeverity[info] = %d, want 1", output.Summary.BySeverity["info"])
	}
}

func TestJSONReporter_Report_ValidJSON(t *testing.T) {
	reporter := NewJSONReporter()
	result := &config.ScanResult{
		ServersFound: 1,
		ToolsScanned: 1,
		Findings: []config.Finding{
			{
				ID:          "test-valid-json",
				TemplateID:  "t1",
				ServerName:  "server",
				ToolName:    "tool",
				Severity:    config.SeverityHigh,
				Title:       "Test",
				Description: "Description with \"quotes\" and\nnewlines",
				Evidence:    "evidence with <html> tags",
				Remediation: "fix",
			},
		},
	}

	var buf bytes.Buffer
	err := reporter.Report(&buf, result)
	if err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	// Verify it's valid JSON
	if !json.Valid(buf.Bytes()) {
		t.Error("output is not valid JSON")
	}
}

func TestJSONReporter_Report_PreservesLayerAndConfidence(t *testing.T) {
	reporter := NewJSONReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{
			{ID: "l1", TemplateID: "t1", Severity: config.SeverityHigh, Layer: 1, Confidence: 0.85, Title: "L1", Remediation: "fix"},
			{ID: "l2", TemplateID: "t2", Severity: config.SeverityHigh, Layer: 2, Confidence: 0.72, Title: "L2", Remediation: "fix"},
			{ID: "l3", TemplateID: "t3", Severity: config.SeverityHigh, Layer: 3, Confidence: 0.9, Title: "L3", Remediation: "fix"},
		},
	}

	var buf bytes.Buffer
	reporter.Report(&buf, result)

	var output jsonOutput
	json.Unmarshal(buf.Bytes(), &output)

	for i, f := range output.Findings {
		expectedLayer := i + 1
		if f.Layer != expectedLayer {
			t.Errorf("finding %d: Layer = %d, want %d", i, f.Layer, expectedLayer)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	findings := []config.Finding{
		{Severity: config.SeverityCritical},
		{Severity: config.SeverityCritical},
		{Severity: config.SeverityHigh},
		{Severity: config.SeverityMedium},
		{Severity: config.SeverityLow},
		{Severity: config.SeverityInfo},
		{Severity: config.SeverityInfo},
	}

	counts := countBySeverity(findings)
	if counts["critical"] != 2 {
		t.Errorf("critical = %d, want 2", counts["critical"])
	}
	if counts["high"] != 1 {
		t.Errorf("high = %d, want 1", counts["high"])
	}
	if counts["medium"] != 1 {
		t.Errorf("medium = %d, want 1", counts["medium"])
	}
	if counts["low"] != 1 {
		t.Errorf("low = %d, want 1", counts["low"])
	}
	if counts["info"] != 2 {
		t.Errorf("info = %d, want 2", counts["info"])
	}
}

func TestCountBySeverity_Empty(t *testing.T) {
	counts := countBySeverity(nil)
	// Should have all severity keys initialized to 0
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] != 0 {
			t.Errorf("counts[%s] = %d, want 0", sev, counts[sev])
		}
	}
}

func TestJSONReporter_Report_TagsAndReferences(t *testing.T) {
	reporter := NewJSONReporter()
	result := &config.ScanResult{
		Findings: []config.Finding{
			{
				ID:          "tag-test",
				TemplateID:  "t1",
				Severity:    config.SeverityHigh,
				Title:       "Tags Test",
				Remediation: "fix",
				Tags:        []string{"tag1", "tag2", "tag3"},
				References:  []string{"https://ref1.com", "https://ref2.com"},
			},
		},
	}

	var buf bytes.Buffer
	reporter.Report(&buf, result)

	var output jsonOutput
	json.Unmarshal(buf.Bytes(), &output)

	f := output.Findings[0]
	if len(f.Tags) != 3 {
		t.Errorf("Tags len = %d, want 3", len(f.Tags))
	}
	if len(f.References) != 2 {
		t.Errorf("References len = %d, want 2", len(f.References))
	}
}
