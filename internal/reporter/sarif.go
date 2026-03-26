// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// SARIFReporter outputs findings in SARIF v2.1.0 format for GitHub/CI integration.
type SARIFReporter struct{}

// NewSARIFReporter creates a new SARIF reporter.
func NewSARIFReporter() *SARIFReporter {
	return &SARIFReporter{}
}

// Report writes findings as SARIF to the given writer.
func (r *SARIFReporter) Report(w io.Writer, result *config.ScanResult) error {
	sarif := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "MCP-Lattice",
					Version:        "0.1.0",
					InformationURI: "https://github.com/panavinsingh/MCP-Lattice",
					Rules:          buildRules(result.Findings),
				},
			},
			Results: buildResults(result.Findings),
		}},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SARIF: %w", err)
	}

	_, err = w.Write(data)
	return err
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	FullDescription  sarifMessage           `json:"fullDescription"`
	Help             sarifMessage           `json:"help"`
	DefaultConfig    sarifRuleConfig        `json:"defaultConfiguration"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func buildRules(findings []config.Finding) []sarifRule {
	seen := make(map[string]bool)
	var rules []sarifRule

	for _, f := range findings {
		if seen[f.TemplateID] {
			continue
		}
		seen[f.TemplateID] = true

		rules = append(rules, sarifRule{
			ID:               f.TemplateID,
			Name:             f.Title,
			ShortDescription: sarifMessage{Text: f.Title},
			FullDescription:  sarifMessage{Text: f.Description},
			Help:             sarifMessage{Text: f.Remediation},
			DefaultConfig:    sarifRuleConfig{Level: severityToSARIF(f.Severity)},
			Properties: map[string]interface{}{
				"tags":          f.Tags,
				"attack-class":  f.Classification.AttackClass,
				"owasp-agentic": f.Classification.OwaspAgentic,
			},
		})
	}

	return rules
}

func buildResults(findings []config.Finding) []sarifResult {
	var results []sarifResult

	for _, f := range findings {
		msg := f.Title
		if f.Evidence != "" {
			msg += ": " + f.Evidence
		}

		result := sarifResult{
			RuleID:  f.TemplateID,
			Level:   severityToSARIF(f.Severity),
			Message: sarifMessage{Text: msg},
			Properties: map[string]interface{}{
				"server":     f.ServerName,
				"tool":       f.ToolName,
				"layer":      f.Layer,
				"confidence": f.Confidence,
			},
		}

		// Use server config as the "location"
		result.Locations = []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifact{
					URI: fmt.Sprintf("mcp://%s/%s", f.ServerName, f.ToolName),
				},
			},
		}}

		results = append(results, result)
	}

	return results
}

func severityToSARIF(s config.Severity) string {
	switch s {
	case config.SeverityCritical, config.SeverityHigh:
		return "error"
	case config.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
