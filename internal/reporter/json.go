// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package reporter formats scan results for output.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// JSONReporter outputs findings in JSON format.
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// Report writes the scan result as JSON to the given writer.
func (r *JSONReporter) Report(w io.Writer, result *config.ScanResult) error {
	output := &jsonOutput{
		Summary: jsonSummary{
			ServersScanned: result.ServersFound,
			ToolsScanned:   result.ToolsScanned,
			FindingsTotal:  len(result.Findings),
			BySeverity:     countBySeverity(result.Findings),
		},
		Findings: make([]jsonFinding, 0, len(result.Findings)),
	}

	for _, f := range result.Findings {
		output.Findings = append(output.Findings, jsonFinding{
			ID:          f.ID,
			TemplateID:  f.TemplateID,
			ServerName:  f.ServerName,
			ToolName:    f.ToolName,
			Severity:    f.Severity.String(),
			Title:       f.Title,
			Description: f.Description,
			Evidence:    f.Evidence,
			Remediation: f.Remediation,
			References:  f.References,
			Layer:       f.Layer,
			Confidence:  f.Confidence,
			Tags:        f.Tags,
			Classification: jsonClassification{
				AttackClass:   f.Classification.AttackClass,
				CosaiCategory: f.Classification.CosaiCategory,
				OwaspAgentic:  f.Classification.OwaspAgentic,
				CVE:           f.Classification.CVE,
			},
		})
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	_, err = w.Write(data)
	return err
}

type jsonOutput struct {
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

type jsonSummary struct {
	ServersScanned int            `json:"servers_scanned"`
	ToolsScanned   int            `json:"tools_scanned"`
	FindingsTotal  int            `json:"findings_total"`
	BySeverity     map[string]int `json:"by_severity"`
}

type jsonFinding struct {
	ID             string             `json:"id"`
	TemplateID     string             `json:"template_id"`
	ServerName     string             `json:"server_name"`
	ToolName       string             `json:"tool_name,omitempty"`
	Severity       string             `json:"severity"`
	Title          string             `json:"title"`
	Description    string             `json:"description"`
	Evidence       string             `json:"evidence,omitempty"`
	Remediation    string             `json:"remediation"`
	References     []string           `json:"references,omitempty"`
	Layer          int                `json:"layer"`
	Confidence     float64            `json:"confidence"`
	Tags           []string           `json:"tags,omitempty"`
	Classification jsonClassification `json:"classification"`
}

type jsonClassification struct {
	AttackClass   string `json:"attack_class"`
	CosaiCategory int    `json:"cosai_category"`
	OwaspAgentic  string `json:"owasp_agentic"`
	CVE           string `json:"cve,omitempty"`
}

func countBySeverity(findings []config.Finding) map[string]int {
	counts := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	for _, f := range findings {
		counts[f.Severity.String()]++
	}
	return counts
}
