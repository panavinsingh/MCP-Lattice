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

type windsurfParser struct{}

func (p *windsurfParser) Name() string { return "windsurf" }

func (p *windsurfParser) ConfigPaths() []string {
	paths := []string{}

	if isWindows() {
		paths = append(paths,
			filepath.Join(os.Getenv("APPDATA"), "Windsurf", "mcp_config.json"),
			filepath.Join(homeDir(), ".codeium", "windsurf", "mcp_config.json"),
		)
	} else if isDarwin() {
		paths = append(paths,
			filepath.Join(homeDir(), "Library", "Application Support", "Windsurf", "mcp_config.json"),
			filepath.Join(homeDir(), ".codeium", "windsurf", "mcp_config.json"),
		)
	} else {
		paths = append(paths,
			filepath.Join(appDataDir(), "Windsurf", "mcp_config.json"),
			filepath.Join(homeDir(), ".codeium", "windsurf", "mcp_config.json"),
		)
	}

	return paths
}

type windsurfConfig struct {
	MCPServers map[string]windsurfServerDef `json:"mcpServers"`
}

type windsurfServerDef struct {
	Command  string            `json:"command"`
	Args     []string          `json:"args"`
	Env      map[string]string `json:"env"`
	URL      string            `json:"url"`
	ServerID string            `json:"serverId"`
}

func (p *windsurfParser) Parse(path string) ([]config.MCPServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading windsurf config: %w", err)
	}

	var cfg windsurfConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing windsurf config: %w", err)
	}

	var servers []config.MCPServerConfig
	for name, def := range cfg.MCPServers {
		transport := "stdio"
		if def.URL != "" {
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

	return servers, nil
}
