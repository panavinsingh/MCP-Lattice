// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

// Package connector implements MCP client connections for scanning.
// It supports both STDIO and HTTP (Streamable HTTP) transports.
package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/panavinsingh/MCP-Lattice/internal/config"
)

// JSONRPCRequest is a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSONRPCNotification is a JSON-RPC 2.0 notification (no ID field).
type JSONRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError is a JSON-RPC 2.0 error.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// InitializeResult is the response from MCP initialize.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Capabilities    Capabilities `json:"capabilities"`
}

// ServerInfo from MCP initialize response.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Capabilities from MCP initialize response.
type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ToolsListResult is the response from tools/list.
type ToolsListResult struct {
	Tools []MCPTool `json:"tools"`
}

// MCPTool is a tool from the MCP tools/list response.
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

// ResourcesListResult is the response from resources/list.
type ResourcesListResult struct {
	Resources []MCPResource `json:"resources"`
}

// MCPResource is a resource from the MCP resources/list response.
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// Client connects to an MCP server and enumerates its capabilities.
type Client struct {
	config     config.MCPServerConfig
	transport  Transport
	idCounter  atomic.Int64
	mu         sync.Mutex
	connected  bool
	initResult *InitializeResult
}

// Transport is the interface for MCP communication.
type Transport interface {
	Start(ctx context.Context) error
	Send(req JSONRPCRequest) error
	SendNotification(notif JSONRPCNotification) error
	Receive(ctx context.Context) (*JSONRPCResponse, error)
	Close() error
}

// NewClient creates an MCP client for the given server config.
func NewClient(cfg config.MCPServerConfig) *Client {
	return &Client{
		config: cfg,
	}
}

// Connect establishes a connection to the MCP server.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var t Transport
	switch c.config.Transport {
	case "http", "sse":
		t = NewHTTPTransport(c.config.URL)
	default:
		t = NewSTDIOTransport(c.config.Command, c.config.Args, c.config.Env)
	}
	c.transport = t

	if err := c.transport.Start(ctx); err != nil {
		return fmt.Errorf("starting transport: %w", err)
	}

	// Send initialize
	initReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      c.nextID(),
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "mcp-lattice",
				"version": "0.1.0",
			},
		},
	}

	if err := c.transport.Send(initReq); err != nil {
		return fmt.Errorf("sending initialize: %w", err)
	}

	resp, err := c.transport.Receive(ctx)
	if err != nil {
		return fmt.Errorf("receiving initialize response: %w", err)
	}

	if resp.Error != nil {
		return resp.Error
	}

	var initResult InitializeResult
	if err := json.Unmarshal(resp.Result, &initResult); err != nil {
		return fmt.Errorf("parsing initialize result: %w", err)
	}
	c.initResult = &initResult

	// Send initialized notification (no ID per JSON-RPC 2.0 spec)
	notif := JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	if err := c.transport.SendNotification(notif); err != nil {
		return fmt.Errorf("sending initialized notification: %w", err)
	}

	c.connected = true
	return nil
}

// ListTools calls tools/list on the MCP server.
func (c *Client) ListTools(ctx context.Context) ([]config.Tool, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      c.nextID(),
		Method:  "tools/list",
	}

	if err := c.transport.Send(req); err != nil {
		return nil, fmt.Errorf("sending tools/list: %w", err)
	}

	resp, err := c.transport.Receive(ctx)
	if err != nil {
		return nil, fmt.Errorf("receiving tools/list response: %w", err)
	}

	if resp.Error != nil {
		return nil, resp.Error
	}

	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing tools/list result: %w", err)
	}

	var tools []config.Tool
	for _, t := range result.Tools {
		tools = append(tools, config.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
			ServerName:  c.config.Name,
		})
	}

	return tools, nil
}

// ListResources calls resources/list on the MCP server.
func (c *Client) ListResources(ctx context.Context) ([]config.Resource, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      c.nextID(),
		Method:  "resources/list",
	}

	if err := c.transport.Send(req); err != nil {
		return nil, fmt.Errorf("sending resources/list: %w", err)
	}

	resp, err := c.transport.Receive(ctx)
	if err != nil {
		return nil, fmt.Errorf("receiving resources/list response: %w", err)
	}

	if resp.Error != nil {
		// resources/list not supported is not an error
		return nil, nil
	}

	var result ResourcesListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing resources/list result: %w", err)
	}

	var resources []config.Resource
	for _, r := range result.Resources {
		resources = append(resources, config.Resource{
			URI:         r.URI,
			Name:        r.Name,
			Description: r.Description,
			MimeType:    r.MimeType,
			ServerName:  c.config.Name,
		})
	}

	return resources, nil
}

// ServerName returns the configured server name.
func (c *Client) ServerName() string {
	return c.config.Name
}

// ServerInfo returns the server info from initialization.
func (c *Client) ServerInfo() *InitializeResult {
	return c.initResult
}

// Close disconnects from the MCP server.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = false
	if c.transport != nil {
		return c.transport.Close()
	}
	return nil
}

func (c *Client) nextID() int64 {
	return c.idCounter.Add(1)
}
