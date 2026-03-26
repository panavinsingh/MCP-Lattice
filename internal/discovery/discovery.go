// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package discovery auto-discovers MCP server configurations across
// Claude Desktop, Cursor, Windsurf, VS Code, and Gemini CLI.
package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// Discoverer finds MCP server configurations on the local machine.
type Discoverer struct {
	parsers []configParser
}

type configParser interface {
	Name() string
	ConfigPaths() []string
	Parse(path string) ([]config.MCPServerConfig, error)
}

// New creates a Discoverer with all supported config parsers.
func New() *Discoverer {
	return &Discoverer{
		parsers: []configParser{
			&claudeParser{},
			&cursorParser{},
			&windsurfParser{},
			&vscodeParser{},
			&geminiParser{},
		},
	}
}

// Discover finds all MCP server configurations on the machine.
func (d *Discoverer) Discover() ([]config.MCPServerConfig, error) {
	var allConfigs []config.MCPServerConfig
	var errors []error

	for _, parser := range d.parsers {
		for _, path := range parser.ConfigPaths() {
			expanded := expandPath(path)
			if _, err := os.Stat(expanded); os.IsNotExist(err) {
				continue
			}

			configs, err := parser.Parse(expanded)
			if err != nil {
				errors = append(errors, fmt.Errorf("%s (%s): %w", parser.Name(), expanded, err))
				continue
			}

			for i := range configs {
				configs[i].Source = fmt.Sprintf("%s:%s", parser.Name(), expanded)
			}
			allConfigs = append(allConfigs, configs...)
		}
	}

	if len(allConfigs) == 0 && len(errors) > 0 {
		return nil, fmt.Errorf("no MCP configurations found, errors: %v", errors)
	}

	return allConfigs, nil
}

// DiscoverFromPath parses a specific config file.
func (d *Discoverer) DiscoverFromPath(path string) ([]config.MCPServerConfig, error) {
	for _, parser := range d.parsers {
		configs, err := parser.Parse(path)
		if err == nil && len(configs) > 0 {
			for i := range configs {
				configs[i].Source = fmt.Sprintf("manual:%s", path)
			}
			return configs, nil
		}
	}
	return nil, fmt.Errorf("could not parse config file: %s", path)
}

func expandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[1:])
		}
	}
	return os.ExpandEnv(path)
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

func appDataDir() string {
	if isWindows() {
		return os.Getenv("APPDATA")
	}
	if isDarwin() {
		return filepath.Join(homeDir(), "Library", "Application Support")
	}
	// Linux: XDG_CONFIG_HOME or ~/.config
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg != "" {
		return xdg
	}
	return filepath.Join(homeDir(), ".config")
}
