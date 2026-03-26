// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

type vscodeParser struct{}

func (p *vscodeParser) Name() string { return "vscode" }

func (p *vscodeParser) ConfigPaths() []string {
	paths := []string{}

	if isWindows() {
		base := filepath.Join(os.Getenv("APPDATA"), "Code", "User")
		paths = append(paths,
			filepath.Join(base, "settings.json"),
			filepath.Join(base, "globalStorage", "mcp.json"),
		)
	} else if isDarwin() {
		base := filepath.Join(homeDir(), "Library", "Application Support", "Code", "User")
		paths = append(paths,
			filepath.Join(base, "settings.json"),
			filepath.Join(base, "globalStorage", "mcp.json"),
		)
	} else {
		base := filepath.Join(appDataDir(), "Code", "User")
		paths = append(paths,
			filepath.Join(base, "settings.json"),
			filepath.Join(base, "globalStorage", "mcp.json"),
		)
	}

	// Project-level
	cwd, err := os.Getwd()
	if err == nil {
		paths = append(paths,
			filepath.Join(cwd, ".vscode", "mcp.json"),
			filepath.Join(cwd, ".vscode", "settings.json"),
		)
	}

	return paths
}

type vscodeSettings struct {
	MCPServers map[string]vscodeServerDef `json:"mcp.servers"`
	MCP        *vscodeMCPSection          `json:"mcp"`
}

type vscodeMCPSection struct {
	Servers map[string]vscodeServerDef `json:"servers"`
}

type vscodeServerDef struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
}

func (p *vscodeParser) Parse(path string) ([]config.MCPServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vscode config: %w", err)
	}

	// Try as direct MCP config first
	var directCfg map[string]vscodeServerDef
	if err := json.Unmarshal(data, &directCfg); err == nil {
		servers := parseVSCodeServers(directCfg)
		if len(servers) > 0 {
			return servers, nil
		}
	}

	// Try as settings.json with mcp.servers or mcp.servers key
	var settings vscodeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("parsing vscode config: %w", err)
	}

	var servers []config.MCPServerConfig

	if len(settings.MCPServers) > 0 {
		servers = append(servers, parseVSCodeServers(settings.MCPServers)...)
	}

	if settings.MCP != nil && len(settings.MCP.Servers) > 0 {
		servers = append(servers, parseVSCodeServers(settings.MCP.Servers)...)
	}

	return servers, nil
}

func parseVSCodeServers(defs map[string]vscodeServerDef) []config.MCPServerConfig {
	var servers []config.MCPServerConfig
	for name, def := range defs {
		transport := "stdio"
		if def.URL != "" || def.Type == "http" || def.Type == "sse" {
			transport = "http"
		}
		servers = append(servers, config.MCPServerConfig{
			Name:      name,
			Command:   def.Command,
			Args:      def.Args,
			Env:       def.Env,
			Transport: transport,
			URL:       def.URL,
		})
	}
	return servers
}
