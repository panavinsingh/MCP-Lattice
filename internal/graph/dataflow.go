// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"github.com/panavinsingh/MCP-Lattice/internal/config"
	"github.com/panavinsingh/MCP-Lattice/internal/detection"
)

// DataFlowPath represents a path through the capability graph
// where data can flow from a source to a sink.
type DataFlowPath struct {
	Source   string          // Tool that produces data
	Sink     string          // Tool that consumes/sends data
	Via      []string        // Intermediate tools
	Risk     string          // Description of the risk
	Severity config.Severity // Risk severity
}

// TraceDataFlows finds all paths where sensitive data can flow
// from a source capability to a sink capability.
func TraceDataFlows(servers map[string]*config.ServerResult) []DataFlowPath {
	var allTools []config.Tool
	for _, sr := range servers {
		if sr.Connected {
			allTools = append(allTools, sr.Tools...)
		}
	}

	graph := detection.NewCapabilityGraph()
	graph.BuildFromTools(allTools)

	var paths []DataFlowPath

	// Find source -> sink paths
	sources := findToolsWithCapability(graph, detection.CapReadsFilesystem, detection.CapReadsCredentials, detection.CapReadsEnv, detection.CapDatabaseAccess)
	sinks := findToolsWithCapability(graph, detection.CapSendsHTTP, detection.CapWritesExternal, detection.CapEmailSend)

	for _, source := range sources {
		for _, sink := range sinks {
			if source != sink {
				paths = append(paths, DataFlowPath{
					Source:   source,
					Sink:     sink,
					Risk:     "Potential data exfiltration path",
					Severity: config.SeverityHigh,
				})
			}
		}
	}

	return paths
}

func findToolsWithCapability(graph *detection.CapabilityGraph, caps ...detection.Capability) []string {
	var result []string
	for key, node := range graph.GetNodes() {
		for _, nodeCap := range node.Capabilities {
			for _, targetCap := range caps {
				if nodeCap == targetCap {
					result = append(result, key)
					goto next
				}
			}
		}
	next:
	}
	return result
}
