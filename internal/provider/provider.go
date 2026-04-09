// Package provider defines the TokenProvider interface and common types
// used by all credential providers. Each provider exchanges root credentials
// (held in memory) for short-lived, scoped tokens.
package provider

import (
	"context"
	"time"
)

// TokenProvider is the interface that all credential providers implement.
// Each provider knows how to exchange its root credentials for scoped,
// short-lived tokens (or pass through static credentials).
type TokenProvider interface {
	// Name returns the provider's configured name.
	Name() string

	// Type returns the provider type (e.g., "cloudflare", "passthrough").
	Type() string

	// Scopes returns the list of available scope names.
	Scopes() []string

	// GetToken exchanges root credentials for a scoped, short-lived token.
	// The scope must be one of the values returned by Scopes().
	// Options may contain provider-specific overrides (e.g., custom TTL).
	GetToken(ctx context.Context, scope string, opts map[string]any) (*Token, error)

	// Healthy returns whether the provider can currently issue tokens.
	// A provider is unhealthy if its root credentials are missing or the
	// last token exchange failed.
	Healthy() bool

	// Close cleans up resources and zeros credential memory. After Close
	// is called, the provider must not be used.
	Close() error
}

// Token represents an issued credential, either short-lived or passthrough.
type Token struct {
	Value     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at"` // nil for passthrough tokens
	Provider  string     `json:"provider"`
	Scope     string     `json:"scope"`
	Type      string     `json:"type"` // "short-lived" or "passthrough"
}

// zeroBytes overwrites a byte slice with zeros. This is a best-effort
// approach to clearing credentials from memory -- Go's GC may have copied
// the data, but this at least zeroes the primary reference.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroString attempts to zero the backing bytes of a string by converting
// to a byte slice. Due to Go's string immutability, this creates a copy
// and zeros that -- the original string memory is not guaranteed to be
// zeroed. This is a documented limitation of the threat model.
func zeroString(s *string) {
	if s == nil {
		return
	}
	b := []byte(*s)
	zeroBytes(b)
	*s = ""
}
