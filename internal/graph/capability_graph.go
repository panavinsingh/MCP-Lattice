// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package graph provides capability graph visualization and analysis.
package graph

import (
	"fmt"
	"strings"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
	"github.com/panavinsingh/MCP-Lattice/internal/detection"
)

// GraphData represents the full capability graph for visualization.
type GraphData struct {
	Nodes []NodeData  `json:"nodes"`
	Edges []EdgeData  `json:"edges"`
	Toxic []ToxicData `json:"toxic_combinations"`
}

// NodeData represents a tool node for visualization.
type NodeData struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Server       string   `json:"server"`
	Capabilities []string `json:"capabilities"`
	RiskScore    float64  `json:"risk_score"`
}

// EdgeData represents a data flow edge for visualization.
type EdgeData struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	FlowType string `json:"flow_type"`
}

// ToxicData represents a toxic combination for visualization.
type ToxicData struct {
	Tools       []string `json:"tools"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
}

// BuildGraphData constructs visualization-ready graph data from scan results.
func BuildGraphData(servers map[string]*config.ServerResult) *GraphData {
	graph := detection.NewCapabilityGraph()

	// Collect all tools
	var allTools []config.Tool
	for _, sr := range servers {
		if sr.Connected {
			allTools = append(allTools, sr.Tools...)
		}
	}

	graph.BuildFromTools(allTools)

	data := &GraphData{}

	// Convert nodes
	for id, node := range graph.GetNodes() {
		caps := make([]string, len(node.Capabilities))
		for i, c := range node.Capabilities {
			caps[i] = string(c)
		}
		data.Nodes = append(data.Nodes, NodeData{
			ID:           id,
			Label:        node.Tool.Name,
			Server:       node.Tool.ServerName,
			Capabilities: caps,
			RiskScore:    calculateRiskScore(node.Capabilities),
		})
	}

	// Convert edges
	for _, edge := range graph.GetEdges() {
		data.Edges = append(data.Edges, EdgeData{
			Source:   edge.From,
			Target:   edge.To,
			FlowType: edge.FlowType,
		})
	}

	// Find toxic combinations
	toxics := graph.FindToxicCombinations()
	for _, tc := range toxics {
		data.Toxic = append(data.Toxic, ToxicData{
			Tools:       tc.Tools,
			Description: tc.Description,
			Severity:    tc.Severity.String(),
		})
	}

	return data
}

// ToMermaid generates a Mermaid diagram from the graph data.
func (g *GraphData) ToMermaid() string {
	var sb strings.Builder
	sb.WriteString("graph LR\n")

	// Add nodes
	for _, node := range g.Nodes {
		shape := "["
		closeShape := "]"
		if node.RiskScore > 0.7 {
			shape = "(("
			closeShape = "))"
		} else if node.RiskScore > 0.4 {
			shape = "(["
			closeShape = "])"
		}

		nodeID := sanitizeMermaidID(node.ID)
		sb.WriteString(fmt.Sprintf("    %s%s%s: %s<br/>%s%s\n",
			nodeID, shape, nodeID, node.Label,
			strings.Join(node.Capabilities, ", "), closeShape))
	}

	sb.WriteString("\n")

	// Add edges
	for _, edge := range g.Edges {
		srcID := sanitizeMermaidID(edge.Source)
		tgtID := sanitizeMermaidID(edge.Target)
		sb.WriteString(fmt.Sprintf("    %s -->|%s| %s\n", srcID, edge.FlowType, tgtID))
	}

	// Style toxic nodes
	for _, toxic := range g.Toxic {
		for _, tool := range toxic.Tools {
			nodeID := sanitizeMermaidID(tool)
			sb.WriteString(fmt.Sprintf("    style %s fill:#ff6b6b,stroke:#c92a2a\n", nodeID))
		}
	}

	return sb.String()
}

func sanitizeMermaidID(id string) string {
	id = strings.ReplaceAll(id, "/", "_")
	id = strings.ReplaceAll(id, " ", "_")
	id = strings.ReplaceAll(id, "-", "_")
	id = strings.ReplaceAll(id, ".", "_")
	return id
}

func calculateRiskScore(caps []detection.Capability) float64 {
	highRisk := map[detection.Capability]float64{
		detection.CapExecutesCode:     0.9,
		detection.CapReadsCredentials: 0.8,
		detection.CapSendsHTTP:        0.6,
		detection.CapWritesExternal:   0.7,
		detection.CapReadsFilesystem:  0.5,
		detection.CapWritesFilesystem: 0.6,
		detection.CapAccessesNetwork:  0.5,
		detection.CapReadsEnv:         0.6,
		detection.CapDatabaseAccess:   0.5,
		detection.CapEmailSend:        0.6,
		detection.CapDNSLookup:        0.4,
		detection.CapProcessSpawn:     0.8,
	}

	maxScore := 0.0
	for _, cap := range caps {
		if score, ok := highRisk[cap]; ok {
			if score > maxScore {
				maxScore = score
			}
		}
	}
	return maxScore
}
