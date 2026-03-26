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

type claudeParser struct{}

func (p *claudeParser) Name() string { return "claude-desktop" }

func (p *claudeParser) ConfigPaths() []string {
	paths := []string{}

	if isWindows() {
		paths = append(paths,
			filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json"),
		)
	} else if isDarwin() {
		paths = append(paths,
			filepath.Join(homeDir(), "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		)
	} else {
		paths = append(paths,
			filepath.Join(appDataDir(), "Claude", "claude_desktop_config.json"),
			filepath.Join(homeDir(), ".config", "claude", "claude_desktop_config.json"),
		)
	}

	return paths
}

type claudeConfig struct {
	MCPServers map[string]claudeServerDef `json:"mcpServers"`
}

type claudeServerDef struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

func (p *claudeParser) Parse(path string) ([]config.MCPServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading claude config: %w", err)
	}

	var cfg claudeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing claude config: %w", err)
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
