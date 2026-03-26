// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// mockTransport implements Transport for testing.
type mockTransport struct {
	startErr  error
	sendErr   error
	closeErr  error
	responses []*JSONRPCResponse
	respIdx   int
	sent      []JSONRPCRequest
}

func (m *mockTransport) Start(ctx context.Context) error {
	return m.startErr
}

func (m *mockTransport) Send(req JSONRPCRequest) error {
	m.sent = append(m.sent, req)
	return m.sendErr
}

func (m *mockTransport) Receive(ctx context.Context) (*JSONRPCResponse, error) {
	if m.respIdx >= len(m.responses) {
		return nil, fmt.Errorf("no more responses")
	}
	resp := m.responses[m.respIdx]
	m.respIdx++
	return resp, nil
}

func (m *mockTransport) SendNotification(notif JSONRPCNotification) error {
	return m.sendErr
}

func (m *mockTransport) Close() error {
	return m.closeErr
}

func TestNewClient(t *testing.T) {
	cfg := config.MCPServerConfig{
		Name:      "test-server",
		Command:   "node",
		Args:      []string{"server.js"},
		Transport: "stdio",
	}

	client := NewClient(cfg)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.ServerName() != "test-server" {
		t.Errorf("ServerName() = %q, want %q", client.ServerName(), "test-server")
	}
	if client.ServerInfo() != nil {
		t.Error("ServerInfo() should be nil before connection")
	}
}

func TestClient_ListTools_NotConnected(t *testing.T) {
	client := NewClient(config.MCPServerConfig{Name: "test"})
	_, err := client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error when not connected")
	}
	if err.Error() != "not connected" {
		t.Errorf("expected 'not connected' error, got: %v", err)
	}
}

func TestClient_ListResources_NotConnected(t *testing.T) {
	client := NewClient(config.MCPServerConfig{Name: "test"})
	_, err := client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error when not connected")
	}
	if err.Error() != "not connected" {
		t.Errorf("expected 'not connected' error, got: %v", err)
	}
}

func TestClient_Close_NotConnected(t *testing.T) {
	client := NewClient(config.MCPServerConfig{Name: "test"})
	err := client.Close()
	if err != nil {
		t.Errorf("Close() on unconnected client should not error, got: %v", err)
	}
}

func TestClient_ListTools_WithMockTransport(t *testing.T) {
	toolsResult := ToolsListResult{
		Tools: []MCPTool{
			{
				Name:        "read_file",
				Description: "Read a file from the filesystem",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"path": map[string]interface{}{"type": "string"},
					},
				},
			},
			{
				Name:        "add_numbers",
				Description: "Adds two numbers together",
			},
		},
	}
	resultData, _ := json.Marshal(toolsResult)

	mt := &mockTransport{
		responses: []*JSONRPCResponse{
			{JSONRPC: "2.0", ID: 1, Result: resultData},
		},
	}

	client := NewClient(config.MCPServerConfig{Name: "test-server"})
	client.transport = mt
	client.connected = true

	tools, err := client.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools returned error: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	if tools[0].Name != "read_file" {
		t.Errorf("first tool name = %q, want 'read_file'", tools[0].Name)
	}
	if tools[0].ServerName != "test-server" {
		t.Errorf("first tool server name = %q, want 'test-server'", tools[0].ServerName)
	}
	if tools[1].Description != "Adds two numbers together" {
		t.Errorf("second tool description mismatch")
	}
}

func TestClient_ListResources_WithMockTransport(t *testing.T) {
	resourcesResult := ResourcesListResult{
		Resources: []MCPResource{
			{
				URI:         "file:///etc/config.yaml",
				Name:        "config",
				Description: "Server configuration file",
				MimeType:    "text/yaml",
			},
		},
	}
	resultData, _ := json.Marshal(resourcesResult)

	mt := &mockTransport{
		responses: []*JSONRPCResponse{
			{JSONRPC: "2.0", ID: 1, Result: resultData},
		},
	}

	client := NewClient(config.MCPServerConfig{Name: "test-server"})
	client.transport = mt
	client.connected = true

	resources, err := client.ListResources(context.Background())
	if err != nil {
		t.Fatalf("ListResources returned error: %v", err)
	}

	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	if resources[0].URI != "file:///etc/config.yaml" {
		t.Errorf("resource URI = %q, want 'file:///etc/config.yaml'", resources[0].URI)
	}
	if resources[0].ServerName != "test-server" {
		t.Errorf("resource server name = %q, want 'test-server'", resources[0].ServerName)
	}
}

func TestClient_ListResources_ErrorResponse(t *testing.T) {
	mt := &mockTransport{
		responses: []*JSONRPCResponse{
			{JSONRPC: "2.0", ID: 1, Error: &JSONRPCError{Code: -32601, Message: "method not found"}},
		},
	}

	client := NewClient(config.MCPServerConfig{Name: "test"})
	client.transport = mt
	client.connected = true

	resources, err := client.ListResources(context.Background())
	// Error response for resources/list should return nil, nil (not supported)
	if err != nil {
		t.Errorf("expected nil error for unsupported resources/list, got: %v", err)
	}
	if resources != nil {
		t.Errorf("expected nil resources for unsupported, got: %v", resources)
	}
}

func TestClient_ListTools_ErrorResponse(t *testing.T) {
	mt := &mockTransport{
		responses: []*JSONRPCResponse{
			{JSONRPC: "2.0", ID: 1, Error: &JSONRPCError{Code: -32601, Message: "method not found"}},
		},
	}

	client := NewClient(config.MCPServerConfig{Name: "test"})
	client.transport = mt
	client.connected = true

	_, err := client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for error response")
	}
}

func TestJSONRPCError_Error(t *testing.T) {
	err := &JSONRPCError{Code: -32601, Message: "Method not found"}
	expected := "JSON-RPC error -32601: Method not found"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestJSONRPCRequest_Marshal(t *testing.T) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)

	if decoded["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", decoded["jsonrpc"])
	}
	if decoded["method"] != "tools/list" {
		t.Errorf("method = %v, want tools/list", decoded["method"])
	}
}

func TestJSONRPCResponse_Unmarshal(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`
	var resp JSONRPCResponse
	err := json.Unmarshal([]byte(data), &resp)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want 2.0", resp.JSONRPC)
	}
	if resp.ID != 1 {
		t.Errorf("ID = %d, want 1", resp.ID)
	}
	if resp.Error != nil {
		t.Error("Error should be nil")
	}
}

func TestMCPTool_Unmarshal(t *testing.T) {
	data := `{
		"name": "read_file",
		"description": "Reads a file",
		"inputSchema": {
			"type": "object",
			"properties": {
				"path": {"type": "string"}
			}
		}
	}`

	var tool MCPTool
	err := json.Unmarshal([]byte(data), &tool)
	if err != nil {
		t.Fatalf("failed to unmarshal MCPTool: %v", err)
	}
	if tool.Name != "read_file" {
		t.Errorf("Name = %q, want read_file", tool.Name)
	}
	if tool.InputSchema == nil {
		t.Error("InputSchema should not be nil")
	}
}

func TestClient_NextID(t *testing.T) {
	client := NewClient(config.MCPServerConfig{Name: "test"})

	id1 := client.nextID()
	id2 := client.nextID()
	id3 := client.nextID()

	if id1 != 1 {
		t.Errorf("first ID = %d, want 1", id1)
	}
	if id2 != 2 {
		t.Errorf("second ID = %d, want 2", id2)
	}
	if id3 != 3 {
		t.Errorf("third ID = %d, want 3", id3)
	}
}

func TestClient_Close_WithTransport(t *testing.T) {
	mt := &mockTransport{}
	client := NewClient(config.MCPServerConfig{Name: "test"})
	client.transport = mt
	client.connected = true

	err := client.Close()
	if err != nil {
		t.Errorf("Close returned unexpected error: %v", err)
	}
}

func TestInitializeResult_Structure(t *testing.T) {
	data := `{
		"protocolVersion": "2025-03-26",
		"serverInfo": {"name": "test-server", "version": "1.0"},
		"capabilities": {
			"tools": {"listChanged": true},
			"resources": {"subscribe": false, "listChanged": true}
		}
	}`

	var result InitializeResult
	err := json.Unmarshal([]byte(data), &result)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result.ProtocolVersion != "2025-03-26" {
		t.Errorf("ProtocolVersion = %q", result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "test-server" {
		t.Errorf("ServerInfo.Name = %q", result.ServerInfo.Name)
	}
	if result.Capabilities.Tools == nil {
		t.Error("Capabilities.Tools should not be nil")
	}
}
