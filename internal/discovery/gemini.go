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

type geminiParser struct{}

func (p *geminiParser) Name() string { return "gemini-cli" }

func (p *geminiParser) ConfigPaths() []string {
	paths := []string{}

	// Gemini CLI settings
	paths = append(paths,
		filepath.Join(homeDir(), ".gemini", "settings.json"),
		filepath.Join(homeDir(), ".gemini", "mcp.json"),
	)

	if isWindows() {
		paths = append(paths,
			filepath.Join(os.Getenv("APPDATA"), "gemini", "settings.json"),
		)
	}

	return paths
}

type geminiConfig struct {
	MCPServers map[string]geminiServerDef `json:"mcpServers"`
}

type geminiServerDef struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	URL       string            `json:"url"`
	CWD       string            `json:"cwd"`
	Transport string            `json:"transport"`
}

func (p *geminiParser) Parse(path string) ([]config.MCPServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading gemini config: %w", err)
	}

	var cfg geminiConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing gemini config: %w", err)
	}

	var servers []config.MCPServerConfig
	for name, def := range cfg.MCPServers {
		transport := "stdio"
		if def.URL != "" || def.Transport == "http" || def.Transport == "sse" {
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
