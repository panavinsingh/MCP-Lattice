// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package config defines the scanner configuration and core types used throughout MCP-Lattice.
package config

import (
	"fmt"
	"strings"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (s Severity) ColorCode() string {
	switch s {
	case SeverityCritical:
		return "red"
	case SeverityHigh:
		return "yellow"
	case SeverityMedium:
		return "magenta"
	case SeverityLow:
		return "blue"
	default:
		return "white"
	}
}

func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "info", "informational":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium", "med":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical", "crit":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity: %s", s)
	}
}

// Classification maps a finding to threat frameworks.
type Classification struct {
	AttackClass   string `yaml:"attack-class" json:"attack_class"`
	CosaiCategory int    `yaml:"cosai-category" json:"cosai_category"`
	OwaspAgentic  string `yaml:"owasp-agentic" json:"owasp_agentic"`
	CVE           string `yaml:"cve,omitempty" json:"cve,omitempty"`
}

// MCPServerConfig represents a discovered MCP server configuration.
type MCPServerConfig struct {
	Name      string            `json:"name"`
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env,omitempty"`
	Source    string            `json:"source"`
	Transport string            `json:"transport"` // "stdio" or "http"
	URL       string            `json:"url,omitempty"`
}

// Tool represents an MCP tool from tools/list.
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
	ServerName  string                 `json:"server_name"`
}

// Resource represents an MCP resource from resources/list.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
	ServerName  string `json:"server_name"`
}

// Finding represents a single security finding from a scan.
type Finding struct {
	ID             string         `json:"id"`
	TemplateID     string         `json:"template_id"`
	ServerName     string         `json:"server_name"`
	ToolName       string         `json:"tool_name,omitempty"`
	Severity       Severity       `json:"severity"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Evidence       string         `json:"evidence,omitempty"`
	Remediation    string         `json:"remediation"`
	References     []string       `json:"references,omitempty"`
	Layer          int            `json:"layer"` // 1=pattern, 2=semantic, 3=capability graph
	Confidence     float64        `json:"confidence"`
	Tags           []string       `json:"tags,omitempty"`
	Classification Classification `json:"classification"`
}

// ScanResult is the aggregate result of scanning one or more MCP servers.
type ScanResult struct {
	Findings      []Finding                `json:"findings"`
	ServersFound  int                      `json:"servers_found"`
	ToolsScanned  int                      `json:"tools_scanned"`
	Servers       map[string]*ServerResult `json:"servers"`
	GraphFindings []Finding                `json:"graph_findings,omitempty"`
}

// ServerResult captures per-server scan data.
type ServerResult struct {
	Config    MCPServerConfig `json:"config"`
	Tools     []Tool          `json:"tools"`
	Resources []Resource      `json:"resources"`
	Connected bool            `json:"connected"`
	Error     string          `json:"error,omitempty"`
}

// ScanConfig holds runtime configuration for a scan.
type ScanConfig struct {
	ConfigPaths       []string `json:"config_paths,omitempty"`
	TemplateDirs      []string `json:"template_dirs"`
	OutputFormat      string   `json:"output_format"` // json, sarif, table, html
	OutputFile        string   `json:"output_file,omitempty"`
	SeverityThreshold Severity `json:"severity_threshold"`
	Concurrency       int      `json:"concurrency"`
	Timeout           int      `json:"timeout_seconds"`
	EnableL2          bool     `json:"enable_l2"`
	EnableL3          bool     `json:"enable_l3"`
	SemanticThreshold float64  `json:"semantic_threshold"`
	Verbose           bool     `json:"verbose"`
	NoColor           bool     `json:"no_color"`
}

// DefaultScanConfig returns a ScanConfig with sensible defaults.
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		OutputFormat:      "table",
		SeverityThreshold: SeverityInfo,
		Concurrency:       10,
		Timeout:           30,
		EnableL2:          true,
		EnableL3:          true,
		SemanticThreshold: 0.72,
		Verbose:           false,
		NoColor:           false,
	}
}
