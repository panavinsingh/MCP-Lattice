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

type cursorParser struct{}

func (p *cursorParser) Name() string { return "cursor" }

func (p *cursorParser) ConfigPaths() []string {
	paths := []string{
		filepath.Join(homeDir(), ".cursor", "mcp.json"),
	}

	// Also check project-level configs
	cwd, err := os.Getwd()
	if err == nil {
		paths = append(paths, filepath.Join(cwd, ".cursor", "mcp.json"))
	}

	return paths
}

type cursorConfig struct {
	MCPServers map[string]cursorServerDef `json:"mcpServers"`
}

type cursorServerDef struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

func (p *cursorParser) Parse(path string) ([]config.MCPServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading cursor config: %w", err)
	}

	var cfg cursorConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing cursor config: %w", err)
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
