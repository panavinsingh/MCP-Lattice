// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"fmt"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// ServerSummary provides a human-readable summary of a server's capabilities.
type ServerSummary struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	ToolCount int      `json:"tool_count"`
	ResCount  int      `json:"resource_count"`
	ToolNames []string `json:"tool_names"`
	HasAuth   bool     `json:"has_auth"`
	Transport string   `json:"transport"`
}

// SummarizeServer creates a summary of an enumerated server.
func SummarizeServer(sr *config.ServerResult) *ServerSummary {
	summary := &ServerSummary{
		Name:      sr.Config.Name,
		ToolCount: len(sr.Tools),
		ResCount:  len(sr.Resources),
		Transport: sr.Config.Transport,
	}

	for _, t := range sr.Tools {
		summary.ToolNames = append(summary.ToolNames, t.Name)
	}

	return summary
}

// FormatToolDetails returns a detailed description of a tool for display.
func FormatToolDetails(tool config.Tool) string {
	result := fmt.Sprintf("Tool: %s\nServer: %s\nDescription: %s\n",
		tool.Name, tool.ServerName, tool.Description)

	if tool.InputSchema != nil {
		schema, _ := json.MarshalIndent(tool.InputSchema, "", "  ")
		result += fmt.Sprintf("Input Schema:\n%s\n", string(schema))
	}

	return result
}

// CountBySeverity counts findings by severity level.
func CountBySeverity(findings []config.Finding) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	for _, f := range findings {
		counts[f.Severity.String()]++
	}

	return counts
}
