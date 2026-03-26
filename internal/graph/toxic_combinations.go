// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"fmt"
	"strings"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
	"github.com/panavinsingh/MCP-Lattice/internal/detection"
)

// ToxicReport generates a human-readable report of toxic tool combinations.
type ToxicReport struct {
	Combinations []ToxicEntry
}

// ToxicEntry is a single toxic combination finding.
type ToxicEntry struct {
	Description string
	Severity    string
	Tools       []ToolInfo
	DataFlow    string
}

// ToolInfo captures info about a tool in a toxic combination.
type ToolInfo struct {
	Name         string
	Server       string
	Capabilities []string
}

// AnalyzeToxicCombinations builds and analyzes the capability graph.
func AnalyzeToxicCombinations(servers map[string]*config.ServerResult) *ToxicReport {
	report := &ToxicReport{}

	var allTools []config.Tool
	for _, sr := range servers {
		if sr.Connected {
			allTools = append(allTools, sr.Tools...)
		}
	}

	if len(allTools) < 2 {
		return report
	}

	graph := detection.NewCapabilityGraph()
	graph.BuildFromTools(allTools)
	toxics := graph.FindToxicCombinations()

	for _, tc := range toxics {
		entry := ToxicEntry{
			Description: tc.Description,
			Severity:    tc.Severity.String(),
		}

		for _, toolKey := range tc.Tools {
			node, ok := graph.GetNodes()[toolKey]
			if !ok {
				continue
			}
			caps := make([]string, len(node.Capabilities))
			for i, c := range node.Capabilities {
				caps[i] = string(c)
			}
			entry.Tools = append(entry.Tools, ToolInfo{
				Name:         node.Tool.Name,
				Server:       node.Tool.ServerName,
				Capabilities: caps,
			})
		}

		// Build data flow description
		if len(entry.Tools) >= 2 {
			flows := make([]string, len(entry.Tools))
			for i, t := range entry.Tools {
				flows[i] = fmt.Sprintf("%s/%s", t.Server, t.Name)
			}
			entry.DataFlow = strings.Join(flows, " -> ")
		}

		report.Combinations = append(report.Combinations, entry)
	}

	return report
}
