// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package templates handles loading and parsing YAML detection templates.
package templates

// Template is the top-level YAML template structure.
type Template struct {
	ID             string         `yaml:"id"`
	SchemaVersion  int            `yaml:"schema_version"`
	Info           TemplateInfo   `yaml:"info"`
	Classification Classification `yaml:"classification"`
	MCP            MCPCheck       `yaml:"mcp"`
}

// TemplateInfo contains metadata about the template.
type TemplateInfo struct {
	Name               string   `yaml:"name"`
	Author             string   `yaml:"author"`
	Severity           string   `yaml:"severity"`
	Description        string   `yaml:"description"`
	Tags               []string `yaml:"tags"`
	References         []string `yaml:"references"`
	Remediation        string   `yaml:"remediation"`
	FalsePositiveNotes string   `yaml:"false_positive_notes"`
}

// Classification maps to threat frameworks.
type Classification struct {
	AttackClass   string `yaml:"attack-class"`
	CosaiCategory int    `yaml:"cosai-category"`
	OwaspAgentic  string `yaml:"owasp-agentic"`
	CVE           string `yaml:"cve,omitempty"`
}

// MCPCheck defines what and how to check.
type MCPCheck struct {
	Target     string      `yaml:"target"` // tools/list, tools/call, connection, resources/list
	ToolFilter *ToolFilter `yaml:"tool_filter,omitempty"`
	Analysis   []Analysis  `yaml:"analysis"`
	Checks     []Check     `yaml:"checks,omitempty"` // For connection-level checks
	Probes     []Probe     `yaml:"probes,omitempty"` // For active probing
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
}

// ToolFilter narrows which tools to check.
type ToolFilter struct {
	ParamTypes []string `yaml:"param_types,omitempty"` // url, uri, endpoint, etc.
	NameMatch  string   `yaml:"name_match,omitempty"`
}

// Analysis defines a detection analysis type.
type Analysis struct {
	Type              string     `yaml:"type"` // pattern, semantic, capability_graph
	Part              string     `yaml:"part"` // tool_description, tool_name, input_schema, resource_uri
	Patterns          []Pattern  `yaml:"patterns,omitempty"`
	Model             string     `yaml:"model,omitempty"`
	Threshold         float64    `yaml:"threshold,omitempty"`
	MaliciousIntents  []string   `yaml:"malicious_intents,omitempty"`
	ToxicCombinations [][]string `yaml:"toxic_combinations,omitempty"`
	LengthThreshold   int        `yaml:"length_threshold,omitempty"`
}

// Pattern defines a regex or special check pattern.
type Pattern struct {
	Regex       string `yaml:"regex,omitempty"`
	UnicodeTags bool   `yaml:"unicode_tags,omitempty"`
	ZeroWidth   bool   `yaml:"zero_width,omitempty"`
	Base64Check bool   `yaml:"base64_check,omitempty"`
	Homoglyphs  bool   `yaml:"homoglyphs,omitempty"`
}

// Check defines a connection-level check.
type Check struct {
	Type      string `yaml:"type"`
	Method    string `yaml:"method,omitempty"`
	Endpoint  string `yaml:"endpoint,omitempty"`
	Expect    string `yaml:"expect,omitempty"`
	ExpectNot string `yaml:"expect_not,omitempty"`
}

// Probe defines an active probe for testing tool parameters.
type Probe struct {
	Input         string `yaml:"input"`
	ExpectBlocked bool   `yaml:"expect_blocked"`
}

// Matcher defines response matching rules.
type Matcher struct {
	Type     string   `yaml:"type"` // response_contains, status_code, etc.
	Patterns []string `yaml:"patterns,omitempty"`
}
