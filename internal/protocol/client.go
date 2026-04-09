// Package protocol provides a Unix socket client for sending requests
// to the wicket daemon and receiving responses.
package protocol

import (
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

	// Read the response
	decoder := json.NewDecoder(conn)
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
