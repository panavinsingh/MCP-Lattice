// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoader_LoadAll_ValidTemplates(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid template file
	validYAML := `id: test-template-001
schema_version: 1
info:
  name: Test Template
  severity: high
  description: A test template for unit testing
  remediation: Fix the issue
mcp:
  target: tools/list
  analysis:
    - type: pattern
      part: tool_description
      patterns:
        - regex: "(?i)malicious"
`
	err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(validYAML), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	loader := NewLoader([]string{tmpDir})
	templates, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll returned error: %v", err)
	}

	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}

	if templates[0].ID != "test-template-001" {
		t.Errorf("expected ID 'test-template-001', got %q", templates[0].ID)
	}
	if templates[0].Info.Name != "Test Template" {
		t.Errorf("expected name 'Test Template', got %q", templates[0].Info.Name)
	}
	if templates[0].Info.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", templates[0].Info.Severity)
	}
}

func TestLoader_LoadAll_MultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	for i, sev := range []string{"critical", "high", "medium", "low", "info"} {
		yaml := `id: template-` + sev + `
schema_version: 1
info:
  name: Template ` + sev + `
  severity: ` + sev + `
  description: Test template
  remediation: Fix it
mcp:
  target: tools/list
  analysis:
    - type: pattern
      part: tool_description
`
		fname := filepath.Join(tmpDir, "test"+string(rune('a'+i))+".yaml")
		if err := os.WriteFile(fname, []byte(yaml), 0644); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
	}

	loader := NewLoader([]string{tmpDir})
	templates, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll returned error: %v", err)
	}

	if len(templates) != 5 {
		t.Errorf("expected 5 templates, got %d", len(templates))
	}
}

func TestLoader_LoadAll_DuplicateIDs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	yaml1 := `id: duplicate-id
schema_version: 1
info:
  name: First Template
  severity: high
  description: First version
  remediation: Fix
mcp:
  target: tools/list
  analysis:
    - type: pattern
      part: tool_description
`
	yaml2 := `id: duplicate-id
schema_version: 1
info:
  name: Second Template
  severity: low
  description: Second version
  remediation: Fix
mcp:
  target: tools/list
  analysis:
    - type: pattern
      part: tool_description
`
	os.WriteFile(filepath.Join(dir1, "t1.yaml"), []byte(yaml1), 0644)
	os.WriteFile(filepath.Join(dir2, "t2.yaml"), []byte(yaml2), 0644)

	loader := NewLoader([]string{dir1, dir2})
	templates, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll returned error: %v", err)
	}

	// Duplicates should be skipped (first wins)
	if len(templates) != 1 {
		t.Errorf("expected 1 template (first wins), got %d", len(templates))
	}
	if templates[0].Info.Name != "First Template" {
		t.Errorf("expected first template to win, got %q", templates[0].Info.Name)
	}
}

func TestLoader_LoadAll_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()

	badYAML := `this is: [not valid yaml: {{{`
	os.WriteFile(filepath.Join(tmpDir, "bad.yaml"), []byte(badYAML), 0644)

	loader := NewLoader([]string{tmpDir})
	_, err := loader.LoadAll()
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoader_LoadAll_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "missing id",
			yaml: `schema_version: 1
info:
  name: Test
  severity: high
mcp:
  target: tools/list
  analysis:
    - type: pattern
`,
		},
		{
			name: "missing info.name",
			yaml: `id: test-missing-name
schema_version: 1
info:
  severity: high
mcp:
  target: tools/list
  analysis:
    - type: pattern
`,
		},
		{
			name: "missing info.severity",
			yaml: `id: test-missing-severity
schema_version: 1
info:
  name: Test
mcp:
  target: tools/list
  analysis:
    - type: pattern
`,
		},
		{
			name: "missing mcp.target",
			yaml: `id: test-missing-target
schema_version: 1
info:
  name: Test
  severity: high
mcp:
  analysis:
    - type: pattern
`,
		},
		{
			name: "invalid severity value",
			yaml: `id: test-invalid-severity
schema_version: 1
info:
  name: Test
  severity: extreme
mcp:
  target: tools/list
  analysis:
    - type: pattern
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			os.WriteFile(filepath.Join(tmpDir, "bad.yaml"), []byte(tt.yaml), 0644)

			loader := NewLoader([]string{tmpDir})
			_, err := loader.LoadAll()
			if err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

func TestLoader_LoadAll_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	loader := NewLoader([]string{tmpDir})
	templates, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("unexpected error for empty dir: %v", err)
	}
	if len(templates) != 0 {
		t.Errorf("expected 0 templates from empty dir, got %d", len(templates))
	}
}

func TestLoader_LoadAll_NonexistentDirectory(t *testing.T) {
	loader := NewLoader([]string{"/nonexistent/path/that/should/not/exist"})
	templates, err := loader.LoadAll()
	// filepath.Walk returns nil for nonexistent dirs (it just doesn't walk anything)
	if err != nil {
		t.Logf("got error (acceptable): %v", err)
	}
	if len(templates) != 0 {
		t.Errorf("expected 0 templates from nonexistent dir, got %d", len(templates))
	}
}

func TestLoader_LoadAll_SkipsNonYAMLFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a .txt file and a .json file alongside a .yaml file
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not a template"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "data.json"), []byte(`{"key":"value"}`), 0644)

	validYAML := `id: valid-template
schema_version: 1
info:
  name: Valid
  severity: info
  description: desc
  remediation: fix
mcp:
  target: tools/list
  analysis:
    - type: pattern
      part: tool_description
`
	os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(validYAML), 0644)

	loader := NewLoader([]string{tmpDir})
	templates, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 1 {
		t.Errorf("expected 1 template (only .yaml), got %d", len(templates))
	}
}

func TestLoader_LoadAll_YMLExtension(t *testing.T) {
	tmpDir := t.TempDir()

	validYAML := `id: yml-extension-template
schema_version: 1
info:
  name: YML Template
  severity: medium
  description: Template with .yml extension
  remediation: fix
mcp:
  target: tools/list
  analysis:
    - type: pattern
      part: tool_description
`
	os.WriteFile(filepath.Join(tmpDir, "template.yml"), []byte(validYAML), 0644)

	loader := NewLoader([]string{tmpDir})
	templates, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(templates) != 1 {
		t.Errorf("expected 1 template with .yml extension, got %d", len(templates))
	}
}

func TestValidate_InvalidTarget(t *testing.T) {
	tmpl := &Template{
		ID:   "test",
		Info: TemplateInfo{Name: "Test", Severity: "high"},
		MCP:  MCPCheck{Target: "invalid/target"},
	}
	err := validate(tmpl)
	if err == nil {
		t.Error("expected error for invalid target")
	}
}

func TestValidate_InvalidAnalysisType(t *testing.T) {
	tmpl := &Template{
		ID:   "test",
		Info: TemplateInfo{Name: "Test", Severity: "high"},
		MCP: MCPCheck{
			Target: "tools/list",
			Analysis: []Analysis{
				{Type: "invalid_type"},
			},
		},
	}
	err := validate(tmpl)
	if err == nil {
		t.Error("expected error for invalid analysis type")
	}
}

func TestValidate_AllValidTargets(t *testing.T) {
	targets := []string{"tools/list", "tools/call", "connection", "resources/list", "config"}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			tmpl := &Template{
				ID:   "test-" + target,
				Info: TemplateInfo{Name: "Test", Severity: "high"},
				MCP:  MCPCheck{Target: target},
			}
			err := validate(tmpl)
			if err != nil {
				t.Errorf("expected no error for valid target %q, got: %v", target, err)
			}
		})
	}
}

func TestValidateTemplateDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Write one good and one bad template
	goodYAML := `id: good
schema_version: 1
info:
  name: Good
  severity: high
mcp:
  target: tools/list
`
	badYAML := `id: bad
schema_version: 1
info:
  name: Bad
mcp:
  target: tools/list
`
	os.WriteFile(filepath.Join(tmpDir, "good.yaml"), []byte(goodYAML), 0644)
	os.WriteFile(filepath.Join(tmpDir, "bad.yaml"), []byte(badYAML), 0644)

	errs := ValidateTemplateDir(tmpDir)
	if len(errs) == 0 {
		t.Error("expected at least 1 validation error for bad template")
	}
}
