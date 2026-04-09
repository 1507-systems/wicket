// Passthrough provider returns static credentials directly from the vault
// without any token exchange. Used for services that don't support
// short-lived token generation (e.g., Home Assistant, SwitchBot).
//
// The passthrough provider still provides value: credentials flow through
// wicket's audit log, Claude Code never reads the vault, and callers use
// the same interface regardless of provider type.
package provider

import (
	"context"
	"fmt"
	"sync"
)

// Passthrough holds a static credential and returns it on every GetToken call.
type Passthrough struct {
	name       string
	credential string
	scopes     []string
	healthy    bool
	mu         sync.RWMutex
}

// NewPassthrough creates a passthrough provider with the given credential.
// The scope name defaults to "token" if no scopes are configured.
func NewPassthrough(name, credential string, scopes []string) *Passthrough {
	if len(scopes) == 0 {
		scopes = []string{"token"}
	}
	return &Passthrough{
		name:       name,
		credential: credential,
		scopes:     scopes,
		healthy:    credential != "",
	}
}

func (p *Passthrough) Name() string { return p.name }
func (p *Passthrough) Type() string { return "passthrough" }

func (p *Passthrough) Scopes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := make([]string, len(p.scopes))
	copy(s, p.scopes)
	return s
}

func (p *Passthrough) Healthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy
}

// GetToken returns the static credential. The scope must match one of the
// configured scopes. Passthrough tokens have no expiration.
func (p *Passthrough) GetToken(_ context.Context, scope string, _ map[string]any) (*Token, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.healthy {
		return nil, fmt.Errorf("passthrough provider %q is not healthy (credential missing)", p.name)
	}

	// Validate scope
	found := false
	for _, s := range p.scopes {
		if s == scope {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("scope %q not available for passthrough provider %q (available: %v)", scope, p.name, p.scopes)
	}

	return &Token{
		Value:     p.credential,
		ExpiresAt: nil, // passthrough tokens don't expire
		Provider:  p.name,
		Scope:     scope,
		Type:      "passthrough",
	}, nil
}

// Close zeros the credential memory.
func (p *Passthrough) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	zeroString(&p.credential)
	p.healthy = false
	return nil
}
