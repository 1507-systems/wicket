package provider

import (
	"context"
	"strings"
	"testing"
	"time"
)

// newTestCloudflare builds a Cloudflare provider with one scope and a 15m
// default TTL. It is sufficient for exercising the TTL-clamp validation, which
// runs before any network call.
func newTestCloudflare() *Cloudflare {
	cfg := CloudflareConfig{Scopes: map[string]CloudflareScope{
		"dns": {Permissions: []string{"zone:dns_records:edit"}},
	}}
	return NewCloudflare("cf", "meta-token", 15*time.Minute, cfg)
}

func TestCloudflareTTLOverrideRejectsTooLarge(t *testing.T) {
	c := newTestCloudflare()
	// 1h > 15m default: must be rejected without making a network request.
	_, err := c.GetToken(context.Background(), "dns", map[string]any{"ttl": "1h"})
	if err == nil {
		t.Fatal("expected error for ttl larger than configured default, got nil")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCloudflareTTLOverrideRejectsNonPositive(t *testing.T) {
	c := newTestCloudflare()
	for _, v := range []string{"0", "-5m"} {
		_, err := c.GetToken(context.Background(), "dns", map[string]any{"ttl": v})
		if err == nil {
			t.Fatalf("expected error for non-positive ttl %q, got nil", v)
		}
	}
}

func TestCloudflareTTLOverrideRejectsUnparseable(t *testing.T) {
	c := newTestCloudflare()
	_, err := c.GetToken(context.Background(), "dns", map[string]any{"ttl": "not-a-duration"})
	if err == nil {
		t.Fatal("expected error for unparseable ttl, got nil")
	}
	if !strings.Contains(err.Error(), "invalid ttl") {
		t.Errorf("unexpected error: %v", err)
	}
}
