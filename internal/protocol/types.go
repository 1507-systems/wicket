// Package protocol defines the JSON request/response types for the wicket
// Unix socket protocol. All communication is newline-delimited JSON;
// each connection handles exactly one request-response pair.
package protocol

import "time"

// Request represents a client request sent over the Unix socket.
type Request struct {
	Action   string         `json:"action"`             // "get", "status", "providers", "audit", "lock"
	Provider string         `json:"provider,omitempty"` // required for "get"
	Scope    string         `json:"scope,omitempty"`    // required for "get"
	Options  map[string]any `json:"options,omitempty"`  // provider-specific overrides
}

// Response represents a successful token response.
type Response struct {
	Token     string     `json:"token,omitempty"`
	ExpiresAt *time.Time `json:"expires_at"` // nil for passthrough tokens
	Provider  string     `json:"provider,omitempty"`
	Scope     string     `json:"scope,omitempty"`
	Type      string     `json:"type,omitempty"` // "short-lived" or "passthrough"
}

// ErrorResponse represents an error from the daemon.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// Error codes returned by the daemon.
const (
	ErrProviderNotFound     = "PROVIDER_NOT_FOUND"
	ErrScopeNotFound        = "SCOPE_NOT_FOUND"
	ErrTokenExchangeFailed  = "TOKEN_EXCHANGE_FAILED"
	ErrLocked               = "LOCKED"
	ErrUnauthorized         = "UNAUTHORIZED"
	ErrInternalError        = "INTERNAL_ERROR"
	ErrInvalidRequest       = "INVALID_REQUEST"
)

// StatusResponse is returned by the "status" action.
type StatusResponse struct {
	Status          string     `json:"status"`           // "running" or "locked"
	Locked          bool       `json:"locked"`
	UptimeSeconds   int64      `json:"uptime_seconds"`
	ProvidersLoaded int        `json:"providers_loaded"`
	TokensIssued    int64      `json:"tokens_issued"`
	LastRequest     *time.Time `json:"last_request"`
}

// ProviderInfo describes a loaded provider for the "providers" action.
type ProviderInfo struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Scopes  []string `json:"scopes"`
	Healthy bool     `json:"healthy"`
}

// ProvidersResponse is returned by the "providers" action.
type ProvidersResponse struct {
	Providers []ProviderInfo `json:"providers"`
}

// AuditResponse is returned by the "audit" action.
type AuditResponse struct {
	Entries []AuditEntry `json:"entries"`
}

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp    time.Time  `json:"timestamp"`
	Action       string     `json:"action"`
	Provider     string     `json:"provider,omitempty"`
	Scope        string     `json:"scope,omitempty"`
	CallerPID    int32      `json:"caller_pid"`
	CallerUID    uint32     `json:"caller_uid"`
	CallerBinary string     `json:"caller_binary,omitempty"`
	TokenType    string     `json:"token_type,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Success      bool       `json:"success"`
	Error        string     `json:"error,omitempty"`
}

// LockResponse is returned by the "lock" action.
type LockResponse struct {
	Status string `json:"status"` // "locked"
}
