// Copyright 2026 MCP-Lattice Contributors
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

// STDIOTransport communicates with an MCP server via stdin/stdout.
type STDIOTransport struct {
	command string
	args    []string
	env     map[string]string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	mu      sync.Mutex
}

// NewSTDIOTransport creates a new STDIO transport.
func NewSTDIOTransport(command string, args []string, env map[string]string) *STDIOTransport {
	return &STDIOTransport{
		command: command,
		args:    args,
		env:     env,
	}
}

// Start spawns the MCP server process.
func (t *STDIOTransport) Start(ctx context.Context) error {
	// Resolve command - handle npx, node, python etc.
	command := t.command
	args := t.args

	// Handle npx-style commands
	if command == "npx" || command == "npx.cmd" {
		// npx is fine as-is, just resolve the path
		resolved, err := exec.LookPath(command)
		if err != nil {
			// Try npx.cmd on Windows
			resolved, err = exec.LookPath("npx.cmd")
			if err != nil {
				return fmt.Errorf("npx not found: %w", err)
			}
		}
		command = resolved
	} else {
		resolved, err := exec.LookPath(command)
		if err != nil {
			return fmt.Errorf("command not found: %s: %w", command, err)
		}
		command = resolved
	}

	t.cmd = exec.CommandContext(ctx, command, args...)

	// Set environment variables
	if len(t.env) > 0 {
		env := t.cmd.Environ()
		for k, v := range t.env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		t.cmd.Env = env
	}

	var err error
	t.stdin, err = t.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	stdoutPipe, err := t.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}
	t.stdout = bufio.NewReader(stdoutPipe)

	// Discard stderr to avoid blocking
	t.cmd.Stderr = nil

	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("starting process [%s %s]: %w", command, strings.Join(args, " "), err)
	}

	return nil
}

// Send writes a JSON-RPC request to the server's stdin.
func (t *STDIOTransport) Send(req JSONRPCRequest) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	// MCP uses newline-delimited JSON over STDIO
	data = append(data, '\n')

	_, err = t.stdin.Write(data)
	if err != nil {
		return fmt.Errorf("writing to stdin: %w", err)
	}

	return nil
}

// SendNotification writes a JSON-RPC notification (no ID) to the server's stdin.
func (t *STDIOTransport) SendNotification(notif JSONRPCNotification) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	data, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("marshaling notification: %w", err)
	}

	data = append(data, '\n')

	_, err = t.stdin.Write(data)
	if err != nil {
		return fmt.Errorf("writing notification to stdin: %w", err)
	}

	return nil
}

// Receive reads a JSON-RPC response from the server's stdout.
func (t *STDIOTransport) Receive(ctx context.Context) (*JSONRPCResponse, error) {
	// Read lines until we get a valid JSON-RPC response (not a notification)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		line, err := t.stdout.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("reading from stdout: %w", err)
		}

		line = []byte(strings.TrimSpace(string(line)))
		if len(line) == 0 {
			continue
		}

		// Try to parse as a JSON object first
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			// Skip non-JSON lines (server might print logs to stdout)
			continue
		}

		// Skip server-sent notifications (messages without an "id" field)
		if _, hasID := raw["id"]; !hasID {
			continue
		}

		var resp JSONRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}

		return &resp, nil
	}
}

// Close terminates the server process.
func (t *STDIOTransport) Close() error {
	if t.stdin != nil {
		t.stdin.Close()
	}
	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}
	return nil
}
