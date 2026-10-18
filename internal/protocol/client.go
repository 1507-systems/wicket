// Package protocol provides a Unix socket client for sending requests
// to the wicket daemon and receiving responses.
package protocol

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client connects to the wicket daemon over a Unix socket.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// LoadTimeout is the client timeout for requests that make the daemon load
// every provider (reload, unlock). Loading reads each credential from coffer
// in turn, which took ~12s for 91 providers on Verve, well past
// the 5s default, and 42s right after a coffer set (2026-10-15). The daemon
// extends its own deadline for these requests to the same value.
const LoadTimeout = 120 * time.Second

// StartupWait is how long the daemon holds a request that arrives while its
// startup provider load is still running before answering it with an error.
// The daemon listens on its socket before that load (which took 54-93s on a
// cold boot, 2026-10-17), so early callers wait instead of finding no socket.
const StartupWait = 120 * time.Second

// LoadingMarker is what the daemon writes first, before the real response,
// when it is holding a request for the startup load. It is a lone newline, so
// any JSON decoder (including clients that predate it) skips it as
// whitespace; a current client takes it as the cue to extend its deadline by
// StartupWait. A daemon never otherwise writes leading whitespace.
const LoadingMarker = "\n"

// NewClient creates a client that connects to the given socket path.
func NewClient(socketPath string) *Client {
	return &Client{
		SocketPath: socketPath,
		Timeout:    5 * time.Second,
	}
}

// Send sends a request to the daemon and returns the raw JSON response.
// The caller is responsible for decoding the response into the appropriate type.
func (c *Client) Send(req *Request) (json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", c.SocketPath, c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to wicket daemon at %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Encode and send the request as a single JSON line
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read the response. A leading LoadingMarker means the daemon is still
	// loading providers and will answer once it is done: stretch the deadline
	// to cover that instead of timing out on the short default.
	br := bufio.NewReader(conn)
	if b, err := br.Peek(1); err == nil && b[0] == LoadingMarker[0] {
		if err := conn.SetDeadline(time.Now().Add(StartupWait + c.Timeout)); err != nil {
			return nil, fmt.Errorf("failed to set connection deadline: %w", err)
		}
	}
	decoder := json.NewDecoder(br)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return raw, nil
}

// SendAndCheck sends a request and checks if the response is an error.
// If the response contains an "error" field, it returns an ErrorResponse.
// Otherwise it returns the raw JSON for the caller to decode.
func (c *Client) SendAndCheck(req *Request) (json.RawMessage, error) {
	raw, err := c.Send(req)
	if err != nil {
		return nil, err
	}

	// Check if the response is an error
	var errResp ErrorResponse
	if err := json.Unmarshal(raw, &errResp); err == nil && errResp.Error != "" {
		return nil, fmt.Errorf("[%s] %s", errResp.Code, errResp.Error)
	}

	return raw, nil
}
