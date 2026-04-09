package provider

import (
	"context"
	"testing"
)

func TestPassthroughGetToken(t *testing.T) {
	p := NewPassthrough("ha", "my-secret-token", []string{"token"})

	token, err := p.GetToken(context.Background(), "token", nil)
	if err != nil {
		t.Fatalf("GetToken() error: %v", err)
	}

	if token.Value != "my-secret-token" {
		t.Errorf("token.Value = %q, want my-secret-token", token.Value)
	}
	if token.ExpiresAt != nil {
		t.Errorf("token.ExpiresAt = %v, want nil (passthrough)", token.ExpiresAt)
	}
	if token.Provider != "ha" {
		t.Errorf("token.Provider = %q, want ha", token.Provider)
	}
	if token.Scope != "token" {
		t.Errorf("token.Scope = %q, want token", token.Scope)
	}
	if token.Type != "passthrough" {
		t.Errorf("token.Type = %q, want passthrough", token.Type)
	}
}

func TestPassthroughDefaultScope(t *testing.T) {
	p := NewPassthrough("test", "cred", nil)

	scopes := p.Scopes()
	if len(scopes) != 1 || scopes[0] != "token" {
		t.Errorf("Scopes() = %v, want [token]", scopes)
	}
}

func TestPassthroughInvalidScope(t *testing.T) {
	p := NewPassthrough("ha", "my-secret", []string{"token"})

	_, err := p.GetToken(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for invalid scope, got nil")
	}
}

func TestPassthroughHealthy(t *testing.T) {
	p := NewPassthrough("ha", "cred", []string{"token"})
	if !p.Healthy() {
		t.Error("expected Healthy()=true with valid credential")
	}

	empty := NewPassthrough("ha", "", []string{"token"})
	if empty.Healthy() {
		t.Error("expected Healthy()=false with empty credential")
	}
}

func TestPassthroughClose(t *testing.T) {
	p := NewPassthrough("ha", "secret-cred", []string{"token"})

	if err := p.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	if p.Healthy() {
		t.Error("expected Healthy()=false after Close()")
	}

	// GetToken should fail after Close
	_, err := p.GetToken(context.Background(), "token", nil)
	if err == nil {
		t.Fatal("expected error after Close(), got nil")
	}
}

func TestPassthroughNameAndType(t *testing.T) {
	p := NewPassthrough("myservice", "cred", nil)

	if p.Name() != "myservice" {
		t.Errorf("Name() = %q, want myservice", p.Name())
	}
	if p.Type() != "passthrough" {
		t.Errorf("Type() = %q, want passthrough", p.Type())
	}
}

func TestPassthroughMultipleScopes(t *testing.T) {
	p := NewPassthrough("switchbot", "api-key", []string{"api", "secret"})

	scopes := p.Scopes()
	if len(scopes) != 2 {
		t.Fatalf("Scopes() returned %d scopes, want 2", len(scopes))
	}

	// Both scopes should work
	for _, scope := range []string{"api", "secret"} {
		token, err := p.GetToken(context.Background(), scope, nil)
		if err != nil {
			t.Errorf("GetToken(%q) error: %v", scope, err)
			continue
		}
		if token.Value != "api-key" {
			t.Errorf("GetToken(%q) value = %q, want api-key", scope, token.Value)
		}
	}
}
