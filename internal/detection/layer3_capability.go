// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// Capability represents a tool's security-relevant capability.
type Capability string

const (
	CapReadsFilesystem  Capability = "reads_filesystem"
	CapWritesFilesystem Capability = "writes_filesystem"
	CapReadsCredentials Capability = "reads_credentials"
	CapSendsHTTP        Capability = "sends_http"
	CapAccessesNetwork  Capability = "accesses_network"
	CapExecutesCode     Capability = "executes_code"
	CapReadsEnv         Capability = "reads_env"
	CapWritesExternal   Capability = "writes_external"
	CapDatabaseAccess   Capability = "database_access"
	CapEmailSend        Capability = "email_send"
	CapDNSLookup        Capability = "dns_lookup"
	CapProcessSpawn     Capability = "process_spawn"
)

// CapabilityNode represents a tool in the capability graph.
type CapabilityNode struct {
	Tool         config.Tool
	Capabilities []Capability
}

// CapabilityEdge represents a potential data flow between tools.
type CapabilityEdge struct {
	From     string // tool name
	To       string // tool name
	FlowType string // "data", "credential", "command"
}

// ToxicCombination is a dangerous pairing of capabilities.
type ToxicCombination struct {
	Capabilities []Capability
	Severity     config.Severity
	Description  string
	Tools        []string
}

// CapabilityGraph builds and analyzes the tool interaction graph.
type CapabilityGraph struct {
	nodes map[string]*CapabilityNode
	edges []CapabilityEdge
}

// NewCapabilityGraph creates a new capability graph.
func NewCapabilityGraph() *CapabilityGraph {
	return &CapabilityGraph{
		nodes: make(map[string]*CapabilityNode),
	}
}

// CapabilityEngine implements Layer 3 capability graph analysis.
type CapabilityEngine struct{}

// NewCapabilityEngine creates a new L3 detection engine.
func NewCapabilityEngine() *CapabilityEngine {
	return &CapabilityEngine{}
}

// CheckToxicCombinations analyzes tools for dangerous capability combinations.
func (e *CapabilityEngine) CheckToxicCombinations(tools []config.Tool, combinations [][]string) (bool, string, float64) {
	graph := NewCapabilityGraph()
	graph.BuildFromTools(tools)
	toxics := graph.FindToxicCombinations()

	// Also check template-defined combinations
	if len(combinations) > 0 {
		for _, combo := range combinations {
			if len(combo) >= 2 {
				caps := make([]Capability, len(combo))
				for i, c := range combo {
					caps[i] = Capability(c)
				}
				tc := graph.checkSpecificCombination(caps)
				toxics = append(toxics, tc...)
			}
		}
	}

	if len(toxics) > 0 {
		// Return the highest severity finding
		best := toxics[0]
		for _, tc := range toxics[1:] {
			if tc.Severity > best.Severity {
				best = tc
			}
		}

		evidence := fmt.Sprintf("%s (tools: %s)", best.Description, strings.Join(best.Tools, " + "))
		return true, evidence, 0.9
	}

	return false, "", 0
}

// BuildFromTools constructs the capability graph from enumerated tools.
func (g *CapabilityGraph) BuildFromTools(tools []config.Tool) {
	for _, tool := range tools {
		node := &CapabilityNode{
			Tool:         tool,
			Capabilities: inferCapabilities(tool),
		}
		key := fmt.Sprintf("%s/%s", tool.ServerName, tool.Name)
		g.nodes[key] = node
	}

	// Build edges based on data flow potential
	g.buildEdges()
}

// FindToxicCombinations detects predefined dangerous capability pairings.
func (g *CapabilityGraph) FindToxicCombinations() []ToxicCombination {
	var toxics []ToxicCombination

	// Predefined toxic combinations
	dangerousPairs := []struct {
		caps     []Capability
		severity config.Severity
		desc     string
	}{
		{
			caps:     []Capability{CapReadsFilesystem, CapSendsHTTP},
			severity: config.SeverityCritical,
			desc:     "Data exfiltration channel: filesystem read + HTTP send",
		},
		{
			caps:     []Capability{CapReadsCredentials, CapSendsHTTP},
			severity: config.SeverityCritical,
			desc:     "Credential theft: credential read + HTTP send",
		},
		{
			caps:     []Capability{CapReadsEnv, CapWritesExternal},
			severity: config.SeverityCritical,
			desc:     "Environment secret exfiltration: env read + external write",
		},
		{
			caps:     []Capability{CapExecutesCode, CapAccessesNetwork},
			severity: config.SeverityCritical,
			desc:     "Remote code execution + C2 channel: code execution + network access",
		},
		{
			caps:     []Capability{CapDatabaseAccess, CapEmailSend},
			severity: config.SeverityHigh,
			desc:     "Data leak via email: database access + email send",
		},
		{
			caps:     []Capability{CapDatabaseAccess, CapSendsHTTP},
			severity: config.SeverityHigh,
			desc:     "Data leak via HTTP: database access + HTTP send",
		},
		{
			caps:     []Capability{CapReadsFilesystem, CapEmailSend},
			severity: config.SeverityHigh,
			desc:     "File exfiltration via email: filesystem read + email send",
		},
		{
			caps:     []Capability{CapReadsFilesystem, CapDNSLookup},
			severity: config.SeverityHigh,
			desc:     "DNS exfiltration: filesystem read + DNS lookup",
		},
		{
			caps:     []Capability{CapWritesFilesystem, CapExecutesCode},
			severity: config.SeverityHigh,
			desc:     "Arbitrary code execution: file write + code execution",
		},
		{
			caps:     []Capability{CapReadsEnv, CapSendsHTTP},
			severity: config.SeverityHigh,
			desc:     "Secret exfiltration: env read + HTTP send",
		},
		{
			caps:     []Capability{CapProcessSpawn, CapAccessesNetwork},
			severity: config.SeverityHigh,
			desc:     "Reverse shell potential: process spawn + network access",
		},
	}

	// Collect all capabilities across all tools (cross-server)
	allCaps := make(map[Capability][]string) // cap -> tool names
	for key, node := range g.nodes {
		for _, cap := range node.Capabilities {
			allCaps[cap] = append(allCaps[cap], key)
		}
	}

	for _, pair := range dangerousPairs {
		allPresent := true
		var involvedTools []string

		for _, requiredCap := range pair.caps {
			tools, ok := allCaps[requiredCap]
			if !ok || len(tools) == 0 {
				allPresent = false
				break
			}
			involvedTools = append(involvedTools, tools...)
		}

		if allPresent {
			// Deduplicate tools
			seen := make(map[string]bool)
			var unique []string
			for _, t := range involvedTools {
				if !seen[t] {
					seen[t] = true
					unique = append(unique, t)
				}
			}

			toxics = append(toxics, ToxicCombination{
				Capabilities: pair.caps,
				Severity:     pair.severity,
				Description:  pair.desc,
				Tools:        unique,
			})
		}
	}

	return toxics
}

// checkSpecificCombination checks if a specific set of capabilities exists.
func (g *CapabilityGraph) checkSpecificCombination(caps []Capability) []ToxicCombination {
	allCaps := make(map[Capability][]string)
	for key, node := range g.nodes {
		for _, cap := range node.Capabilities {
			allCaps[cap] = append(allCaps[cap], key)
		}
	}

	allPresent := true
	var tools []string
	for _, c := range caps {
		t, ok := allCaps[c]
		if !ok || len(t) == 0 {
			allPresent = false
			break
		}
		tools = append(tools, t...)
	}

	if allPresent {
		capNames := make([]string, len(caps))
		for i, c := range caps {
			capNames[i] = string(c)
		}
		return []ToxicCombination{{
			Capabilities: caps,
			Severity:     config.SeverityHigh,
			Description:  fmt.Sprintf("toxic capability combination: %s", strings.Join(capNames, " + ")),
			Tools:        tools,
		}}
	}

	return nil
}

// buildEdges creates edges between tools based on data flow potential.
func (g *CapabilityGraph) buildEdges() {
	producers := make(map[Capability][]*CapabilityNode)
	consumers := make(map[Capability][]*CapabilityNode)

	// Producers output data, consumers accept data
	producerCaps := map[Capability]bool{
		CapReadsFilesystem: true, CapReadsCredentials: true,
		CapReadsEnv: true, CapDatabaseAccess: true, CapDNSLookup: true,
	}
	consumerCaps := map[Capability]bool{
		CapSendsHTTP: true, CapWritesExternal: true,
		CapEmailSend: true, CapExecutesCode: true, CapWritesFilesystem: true,
	}

	for _, node := range g.nodes {
		for _, cap := range node.Capabilities {
			if producerCaps[cap] {
				producers[cap] = append(producers[cap], node)
			}
			if consumerCaps[cap] {
				consumers[cap] = append(consumers[cap], node)
			}
		}
	}

	// Create edges from producers to consumers
	for _, pNodes := range producers {
		for _, cNodes := range consumers {
			for _, p := range pNodes {
				for _, c := range cNodes {
					pKey := fmt.Sprintf("%s/%s", p.Tool.ServerName, p.Tool.Name)
					cKey := fmt.Sprintf("%s/%s", c.Tool.ServerName, c.Tool.Name)
					if pKey != cKey {
						g.edges = append(g.edges, CapabilityEdge{
							From:     pKey,
							To:       cKey,
							FlowType: "data",
						})
					}
				}
			}
		}
	}
}

// GetNodes returns all nodes in the graph.
func (g *CapabilityGraph) GetNodes() map[string]*CapabilityNode {
	return g.nodes
}

// GetEdges returns all edges in the graph.
func (g *CapabilityGraph) GetEdges() []CapabilityEdge {
	return g.edges
}

// inferCapabilities analyzes a tool's description and schema to infer its capabilities.
func inferCapabilities(tool config.Tool) []Capability {
	var caps []Capability
	desc := strings.ToLower(tool.Description)
	name := strings.ToLower(tool.Name)

	// Combine name and description for analysis
	text := name + " " + desc

	// Also check input schema for parameter names
	var schemaText string
	if tool.InputSchema != nil {
		data, _ := json.Marshal(tool.InputSchema)
		schemaText = strings.ToLower(string(data))
	}
	fullText := text + " " + schemaText

	// Filesystem operations
	if containsAny(fullText, "read file", "read_file", "readfile", "get_file", "getfile",
		"file content", "file_content", "load file", "open file", "cat ", "head ", "tail ",
		"list directory", "list_directory", "listdir", "readdir", "glob", "find file") {
		caps = append(caps, CapReadsFilesystem)
	}

	if containsAny(fullText, "write file", "write_file", "writefile", "save file", "create file",
		"put_file", "putfile", "write to", "append file", "modify file", "edit file") {
		caps = append(caps, CapWritesFilesystem)
	}

	// Network/HTTP
	if containsAny(fullText, "http", "fetch", "request", "api call", "api_call", "webhook",
		"send request", "post ", "get request", "curl", "download", "upload",
		"rest api", "graphql", "endpoint") {
		caps = append(caps, CapSendsHTTP)
		caps = append(caps, CapAccessesNetwork)
	}

	if containsAny(fullText, "network access", "network request", "socket", "connect to",
		"tcp connection", "udp ", "open port", "listen on", "bind to", "dns query",
		"network call", "remote host", "remote server") {
		caps = append(caps, CapAccessesNetwork)
	}

	// Code execution — use specific phrases to avoid false positives on words like "execute"
	if containsAny(fullText, "execute command", "execute_command", "exec(", "eval(",
		"run command", "run_command", "run script", "shell command", "bash ", "cmd.exe",
		"powershell", "system(", "subprocess", "child_process", "child process",
		"spawn process", "run code", "execute code", "code execution") {
		caps = append(caps, CapExecutesCode)
	}

	// Credentials/secrets
	if containsAny(fullText, "credential", "password", "secret", "token", "api key",
		"api_key", "apikey", "auth", "login", "session", "cookie", "certificate",
		"private key", "private_key") {
		caps = append(caps, CapReadsCredentials)
	}

	// Environment variables
	if containsAny(fullText, "env", "environment", "getenv", "process.env",
		"os.environ", "env var", "env_var") {
		caps = append(caps, CapReadsEnv)
	}

	// External writes
	if containsAny(fullText, "send", "post", "publish", "push", "notify",
		"forward", "relay", "transmit", "broadcast") &&
		containsAny(fullText, "external", "remote", "server", "api", "endpoint", "webhook") {
		caps = append(caps, CapWritesExternal)
	}

	// Database
	if containsAny(fullText, "database", "db", "sql", "query", "table", "select",
		"insert", "update", "delete from", "mongo", "postgres", "mysql", "redis",
		"dynamo", "firestore") {
		caps = append(caps, CapDatabaseAccess)
	}

	// Email
	if containsAny(fullText, "email", "mail", "smtp", "send mail", "send_mail",
		"sendmail", "postmark", "sendgrid", "ses") {
		caps = append(caps, CapEmailSend)
	}

	// DNS
	if containsAny(fullText, "dns", "resolve", "lookup", "nslookup", "dig ") {
		caps = append(caps, CapDNSLookup)
	}

	// Process spawn
	if containsAny(fullText, "spawn process", "fork process", "child process", "child_process",
		"subprocess", "popen", "os.exec", "exec.command") {
		caps = append(caps, CapProcessSpawn)
	}

	return dedupCaps(caps)
}

func containsAny(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

func dedupCaps(caps []Capability) []Capability {
	seen := make(map[Capability]bool)
	var result []Capability
	for _, c := range caps {
		if !seen[c] {
			seen[c] = true
			result = append(result, c)
		}
	}
	return result
}
