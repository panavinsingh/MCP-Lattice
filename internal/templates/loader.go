// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Loader loads and validates YAML detection templates.
type Loader struct {
	dirs []string
}

// NewLoader creates a template loader for the given directories.
func NewLoader(dirs []string) *Loader {
	return &Loader{dirs: dirs}
}

// LoadAll loads all templates from all configured directories.
func (l *Loader) LoadAll() ([]*Template, error) {
	var templates []*Template
	seen := make(map[string]bool)

	for _, dir := range l.dirs {
		dirTemplates, err := l.loadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("loading templates from %s: %w", dir, err)
		}

		for _, t := range dirTemplates {
			if seen[t.ID] {
				continue // skip duplicates, first wins
			}
			seen[t.ID] = true
			templates = append(templates, t)
		}
	}

	return templates, nil
}

// loadDir loads all YAML files from a directory recursively.
func (l *Loader) loadDir(dir string) ([]*Template, error) {
	var templates []*Template

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		t, err := l.loadFile(path)
		if err != nil {
			return fmt.Errorf("loading %s: %w", path, err)
		}

		templates = append(templates, t)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return templates, nil
}

// loadFile parses a single YAML template file.
func (l *Loader) loadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	if err := validate(&t); err != nil {
		return nil, fmt.Errorf("validation error in %s: %w", path, err)
	}

	return &t, nil
}

// validate checks a template for required fields and valid values.
func validate(t *Template) error {
	if t.ID == "" {
		return fmt.Errorf("missing required field: id")
	}

	if t.Info.Name == "" {
		return fmt.Errorf("missing required field: info.name")
	}

	if t.Info.Severity == "" {
		return fmt.Errorf("missing required field: info.severity")
	}

	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if !validSeverities[strings.ToLower(t.Info.Severity)] {
		return fmt.Errorf("invalid severity: %s", t.Info.Severity)
	}

	if t.MCP.Target == "" {
		return fmt.Errorf("missing required field: mcp.target")
	}

	validTargets := map[string]bool{
		"tools/list": true, "tools/call": true, "connection": true,
		"resources/list": true, "config": true,
	}
	if !validTargets[t.MCP.Target] {
		return fmt.Errorf("invalid target: %s", t.MCP.Target)
	}

	for i, analysis := range t.MCP.Analysis {
		validTypes := map[string]bool{
			"pattern": true, "semantic": true, "capability_graph": true, "length": true,
		}
		if !validTypes[analysis.Type] {
			return fmt.Errorf("analysis[%d]: invalid type: %s", i, analysis.Type)
		}
	}

	return nil
}

// ValidateTemplateDir validates all templates in a directory and returns errors.
func ValidateTemplateDir(dir string) []error {
	var errs []error

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return nil
		}

		var t Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			errs = append(errs, fmt.Errorf("%s: YAML parse error: %w", path, err))
			return nil
		}

		if err := validate(&t); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
		}

		return nil
	})

	return errs
}
