// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"testing"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

func TestCapabilityEngine_CheckToxicCombinations_Positive(t *testing.T) {
	engine := NewCapabilityEngine()

	tests := []struct {
		name  string
		tools []config.Tool
	}{
		{
			name: "filesystem read + HTTP send = data exfiltration",
			tools: []config.Tool{
				{
					Name:        "read_file",
					Description: "Read a file from the filesystem and return its contents",
					ServerName:  "server-a",
				},
				{
					Name:        "http_request",
					Description: "Send an HTTP request to any endpoint and return the response",
					ServerName:  "server-b",
				},
			},
		},
		{
			name: "credential read + HTTP send = credential theft",
			tools: []config.Tool{
				{
					Name:        "get_credentials",
					Description: "Read stored credentials and authentication tokens",
					ServerName:  "server-a",
				},
				{
					Name:        "webhook_post",
					Description: "Send data via HTTP POST to a webhook endpoint",
					ServerName:  "server-b",
				},
			},
		},
		{
			name: "code execution + network = RCE + C2",
			tools: []config.Tool{
				{
					Name:        "run_command",
					Description: "Execute a shell command and return the output",
					ServerName:  "server-a",
				},
				{
					Name:        "tcp_connect",
					Description: "Connect to a remote network socket and exchange data",
					ServerName:  "server-b",
				},
			},
		},
		{
			name: "env read + HTTP send = secret exfiltration",
			tools: []config.Tool{
				{
					Name:        "get_env",
					Description: "Read environment variables from the process env",
					ServerName:  "server-a",
				},
				{
					Name:        "http_post",
					Description: "Send an HTTP POST request with data to a URL",
					ServerName:  "server-b",
				},
			},
		},
		{
			name: "database access + HTTP send = data leak",
			tools: []config.Tool{
				{
					Name:        "query_db",
					Description: "Run a SQL query against the database and return results",
					ServerName:  "server-a",
				},
				{
					Name:        "fetch_url",
					Description: "Fetch data from an HTTP URL endpoint",
					ServerName:  "server-b",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, evidence, confidence := engine.CheckToxicCombinations(tt.tools, nil)
			if !matched {
				t.Errorf("expected toxic combination detection, got no match")
			}
			if evidence == "" {
				t.Error("expected non-empty evidence")
			}
			if confidence <= 0 {
				t.Errorf("expected positive confidence, got %f", confidence)
			}
		})
	}
}

func TestCapabilityEngine_CheckToxicCombinations_Negative(t *testing.T) {
	engine := NewCapabilityEngine()

	tests := []struct {
		name  string
		tools []config.Tool
	}{
		{
			name: "two safe arithmetic tools",
			tools: []config.Tool{
				{
					Name:        "add",
					Description: "Adds two numbers together and returns the result",
					ServerName:  "math-server",
				},
				{
					Name:        "multiply",
					Description: "Multiplies two numbers and returns the product",
					ServerName:  "math-server",
				},
			},
		},
		{
			name: "timestamp and formatter",
			tools: []config.Tool{
				{
					Name:        "get_time",
					Description: "Returns the current timestamp in ISO 8601 format",
					ServerName:  "util-server",
				},
				{
					Name:        "format_string",
					Description: "Formats a string using the given template",
					ServerName:  "util-server",
				},
			},
		},
		{
			name: "single tool no combination possible",
			tools: []config.Tool{
				{
					Name:        "read_file",
					Description: "Read a file from the filesystem and return its contents",
					ServerName:  "server-a",
				},
			},
		},
		{
			name:  "empty tools list",
			tools: []config.Tool{},
		},
		{
			name: "read-only tools with no exfil channel",
			tools: []config.Tool{
				{
					Name:        "read_file",
					Description: "Read a file from the filesystem",
					ServerName:  "server-a",
				},
				{
					Name:        "list_directory",
					Description: "List files in a directory",
					ServerName:  "server-a",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, _, _ := engine.CheckToxicCombinations(tt.tools, nil)
			if matched {
				t.Errorf("expected no toxic combination for safe tools")
			}
		})
	}
}

func TestCapabilityEngine_TemplateCombinations(t *testing.T) {
	engine := NewCapabilityEngine()

	t.Run("custom toxic combination from template", func(t *testing.T) {
		tools := []config.Tool{
			{
				Name:        "read_file",
				Description: "Read a file from the filesystem and return its contents",
				ServerName:  "server-a",
			},
			{
				Name:        "send_email",
				Description: "Send an email message via SMTP",
				ServerName:  "server-b",
			},
		}
		combinations := [][]string{
			{"reads_filesystem", "email_send"},
		}

		matched, evidence, _ := engine.CheckToxicCombinations(tools, combinations)
		if !matched {
			t.Error("expected detection of custom toxic combination")
		}
		if evidence == "" {
			t.Error("expected non-empty evidence for toxic combination")
		}
	})
}

func TestCapabilityGraph_BuildFromTools(t *testing.T) {
	graph := NewCapabilityGraph()

	tools := []config.Tool{
		{
			Name:        "read_file",
			Description: "Read a file from the filesystem",
			ServerName:  "server-a",
		},
		{
			Name:        "http_post",
			Description: "Send an HTTP POST request to a URL",
			ServerName:  "server-b",
		},
	}

	graph.BuildFromTools(tools)

	nodes := graph.GetNodes()
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}

	if _, ok := nodes["server-a/read_file"]; !ok {
		t.Error("expected node for server-a/read_file")
	}
	if _, ok := nodes["server-b/http_post"]; !ok {
		t.Error("expected node for server-b/http_post")
	}

	edges := graph.GetEdges()
	if len(edges) == 0 {
		t.Error("expected at least one edge between reader and sender")
	}
}

func TestInferCapabilities(t *testing.T) {
	tests := []struct {
		name        string
		tool        config.Tool
		expectedCap Capability
		shouldHave  bool
	}{
		{
			name:        "read_file infers filesystem read",
			tool:        config.Tool{Name: "read_file", Description: "Read a file from the filesystem"},
			expectedCap: CapReadsFilesystem,
			shouldHave:  true,
		},
		{
			name:        "write_file infers filesystem write",
			tool:        config.Tool{Name: "write_file", Description: "Write content to a file on disk"},
			expectedCap: CapWritesFilesystem,
			shouldHave:  true,
		},
		{
			name:        "http_request infers HTTP send",
			tool:        config.Tool{Name: "http_request", Description: "Send an HTTP request to a URL"},
			expectedCap: CapSendsHTTP,
			shouldHave:  true,
		},
		{
			name:        "exec infers code execution",
			tool:        config.Tool{Name: "run_command", Description: "Execute a shell command"},
			expectedCap: CapExecutesCode,
			shouldHave:  true,
		},
		{
			name:        "get_env infers env read",
			tool:        config.Tool{Name: "get_env", Description: "Read environment variables"},
			expectedCap: CapReadsEnv,
			shouldHave:  true,
		},
		{
			name:        "query_db infers database access",
			tool:        config.Tool{Name: "query", Description: "Run a SQL query against the database"},
			expectedCap: CapDatabaseAccess,
			shouldHave:  true,
		},
		{
			name:        "add_numbers does not infer filesystem",
			tool:        config.Tool{Name: "add", Description: "Adds two numbers and returns the sum"},
			expectedCap: CapReadsFilesystem,
			shouldHave:  false,
		},
		{
			name:        "timestamp does not infer network",
			tool:        config.Tool{Name: "timestamp", Description: "Returns the current timestamp"},
			expectedCap: CapAccessesNetwork,
			shouldHave:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := inferCapabilities(tt.tool)
			found := false
			for _, c := range caps {
				if c == tt.expectedCap {
					found = true
					break
				}
			}
			if found != tt.shouldHave {
				t.Errorf("inferCapabilities(%q): expected %s present=%v, got present=%v (caps: %v)",
					tt.tool.Name, tt.expectedCap, tt.shouldHave, found, caps)
			}
		})
	}
}

func TestCapabilityGraph_FindToxicCombinations(t *testing.T) {
	t.Run("returns empty for safe tools", func(t *testing.T) {
		graph := NewCapabilityGraph()
		graph.BuildFromTools([]config.Tool{
			{Name: "add", Description: "Adds two numbers", ServerName: "math"},
		})
		toxics := graph.FindToxicCombinations()
		if len(toxics) != 0 {
			t.Errorf("expected no toxic combinations, got %d", len(toxics))
		}
	})

	t.Run("detects filesystem + http combination", func(t *testing.T) {
		graph := NewCapabilityGraph()
		graph.BuildFromTools([]config.Tool{
			{Name: "read_file", Description: "Read file from filesystem", ServerName: "fs"},
			{Name: "http_post", Description: "Send HTTP POST request to URL", ServerName: "net"},
		})
		toxics := graph.FindToxicCombinations()
		if len(toxics) == 0 {
			t.Error("expected at least one toxic combination for filesystem + HTTP")
		}

		foundExfil := false
		for _, tc := range toxics {
			if tc.Severity == config.SeverityCritical {
				foundExfil = true
				break
			}
		}
		if !foundExfil {
			t.Error("expected a critical severity toxic combination")
		}
	})
}

func TestDedupCaps(t *testing.T) {
	caps := []Capability{
		CapReadsFilesystem, CapSendsHTTP, CapReadsFilesystem, CapAccessesNetwork, CapSendsHTTP,
	}
	result := dedupCaps(caps)

	seen := make(map[Capability]int)
	for _, c := range result {
		seen[c]++
		if seen[c] > 1 {
			t.Errorf("capability %s appears more than once after dedup", c)
		}
	}

	if len(result) != 3 {
		t.Errorf("expected 3 unique capabilities, got %d", len(result))
	}
}
