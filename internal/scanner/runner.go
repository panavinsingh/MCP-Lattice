// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"runtime"
)

// FindTemplateDirs returns the default template directories to search.
func FindTemplateDirs() []string {
	var dirs []string

	// 1. Check for templates relative to the executable
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		candidate := filepath.Join(exeDir, "templates")
		if isDir(candidate) {
			dirs = append(dirs, candidate)
		}
		// Also check one level up (for development)
		candidate = filepath.Join(exeDir, "..", "templates")
		if isDir(candidate) {
			dirs = append(dirs, candidate)
		}
	}

	// 2. Check current working directory
	cwd, err := os.Getwd()
	if err == nil {
		candidate := filepath.Join(cwd, "templates")
		if isDir(candidate) {
			dirs = append(dirs, candidate)
		}
	}

	// 3. Check user-level template directory
	home, err := os.UserHomeDir()
	if err == nil {
		candidate := filepath.Join(home, ".mcp-lattice", "templates")
		if isDir(candidate) {
			dirs = append(dirs, candidate)
		}
	}

	// 4. System-level on Linux/macOS
	if runtime.GOOS != "windows" {
		candidates := []string{
			"/usr/local/share/mcp-lattice/templates",
			"/usr/share/mcp-lattice/templates",
		}
		for _, c := range candidates {
			if isDir(c) {
				dirs = append(dirs, c)
			}
		}
	}

	return dirs
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
