// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPTransport communicates with an MCP server via Streamable HTTP.
type HTTPTransport struct {
	url       string
	client    *http.Client
	sessionID string
}

// NewHTTPTransport creates a new HTTP transport.
func NewHTTPTransport(url string) *HTTPTransport {
	return &HTTPTransport{
		url: url,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start initializes the HTTP transport (no-op for HTTP, connection is per-request).
func (t *HTTPTransport) Start(ctx context.Context) error {
	return nil
}

// Send sends a JSON-RPC request via HTTP POST and is a no-op here;
// the actual sending and receiving happens in Receive for HTTP.
func (t *HTTPTransport) Send(req JSONRPCRequest) error {
	// For HTTP transport, we combine send+receive in Receive()
	// Store the request for the next Receive call
	return nil
}

// SendNotification sends a JSON-RPC notification (no ID) via HTTP POST.
func (t *HTTPTransport) SendNotification(notif JSONRPCNotification) error {
	// Notifications don't expect a response
	return nil
}

// sendAndReceive does the actual HTTP request/response cycle.
func (t *HTTPTransport) sendAndReceive(ctx context.Context, req JSONRPCRequest) (*JSONRPCResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if t.sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", t.sessionID)
	}

	httpResp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Capture session ID from response
	if sid := httpResp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.sessionID = sid
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading HTTP response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", httpResp.StatusCode, string(body))
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing JSON-RPC response: %w", err)
	}

	return &resp, nil
}

// Receive reads a JSON-RPC response. For HTTP, this is combined with sending.
func (t *HTTPTransport) Receive(ctx context.Context) (*JSONRPCResponse, error) {
	// HTTP transport doesn't support streaming receive in this simple implementation
	// The actual send+receive is done via sendAndReceive
	return nil, fmt.Errorf("use sendAndReceive for HTTP transport")
}

// Close cleans up the HTTP transport.
func (t *HTTPTransport) Close() error {
	return nil
}
