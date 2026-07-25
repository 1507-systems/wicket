package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// ── Expired-token grooming ───────────────────────────────────────────────────
//
// Cloudflare caps user API tokens (~50) and EXPIRED tokens still count against
// that cap, so a mint-only client eventually wedges itself: every mint fails and
// already-issued tokens start returning code 10000, which is indistinguishable
// from the normal fresh-token propagation delay. These tests pin the behavior
// that keeps that from recurring.

// newCloudflareAgainst points a provider at a stub server standing in for the
// Cloudflare API.
func newCloudflareAgainst(t *testing.T, handler http.Handler) (*Cloudflare, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg := CloudflareConfig{Scopes: map[string]CloudflareScope{
		"dns": {Permissions: []string{"zone:dns_records:edit"}},
	}}
	c := NewCloudflare("cf", "meta-token", 15*time.Minute, cfg)
	c.client = srv.Client()
	c.apiBase = srv.URL
	return c, srv
}

func TestGroomOnlyDeletesExpiredWicketTokens(t *testing.T) {
	var deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens", func(w http.ResponseWriter, r *http.Request) {
		// Mixed inventory: only the expired wicket-* entry may be removed.
		fmt.Fprint(w, `{"success":true,"result":[
			{"id":"1","name":"wicket-cf-dns-1","status":"expired"},
			{"id":"2","name":"wicket-cf-dns-2","status":"active"},
			{"id":"3","name":"ephemeral-other-tool","status":"expired"},
			{"id":"4","name":"cortex-backup-ci","status":"expired"}
		]}`)
	})
	mux.HandleFunc("/user/tokens/", func(w http.ResponseWriter, r *http.Request) {
		deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/user/tokens/"))
		fmt.Fprint(w, `{"success":true}`)
	})

	c, _ := newCloudflareAgainst(t, mux)
	pruned, err := c.groomExpiredTokens(context.Background(), "meta-token")
	if err != nil {
		t.Fatalf("groomExpiredTokens: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1", pruned)
	}
	if len(deleted) != 1 || deleted[0] != "1" {
		t.Errorf("deleted = %v, want [1] — an active wicket token, another tool's "+
			"ephemeral, and a human's named token must all survive", deleted)
	}
}

func TestMintRetriesAfterGroomingReclaimsSlots(t *testing.T) {
	var mintAttempts int
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"success":true,"result":[{"id":"1","name":"wicket-cf-dns-old","status":"expired"}]}`)
			return
		}
		mintAttempts++
		if mintAttempts == 1 {
			// First mint fails the way an exhausted cap does.
			fmt.Fprint(w, `{"success":false,"errors":[{"message":"too many tokens"}]}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":{"value":"cfut_recovered"}}`)
	})
	mux.HandleFunc("/user/tokens/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true}`)
	})

	c, _ := newCloudflareAgainst(t, mux)
	tok, err := c.GetToken(context.Background(), "dns", nil)
	if err != nil {
		t.Fatalf("GetToken should recover after grooming: %v", err)
	}
	if tok.Value != "cfut_recovered" {
		t.Errorf("token = %q, want cfut_recovered", tok.Value)
	}
	if mintAttempts != 2 {
		t.Errorf("mintAttempts = %d, want exactly 2 (one retry, not a loop)", mintAttempts)
	}
}

func TestMintDoesNotRetryWhenNothingWasReclaimable(t *testing.T) {
	var mintAttempts int
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Nothing groomable: the cap is not the problem, so retrying would
			// only double the failure latency and muddy the reported error.
			fmt.Fprint(w, `{"success":true,"result":[{"id":"9","name":"wicket-cf-dns-live","status":"active"}]}`)
			return
		}
		mintAttempts++
		fmt.Fprint(w, `{"success":false,"errors":[{"message":"bad policy"}]}`)
	})

	c, _ := newCloudflareAgainst(t, mux)
	if _, err := c.GetToken(context.Background(), "dns", nil); err == nil {
		t.Fatal("expected the original mint error to surface")
	} else if !strings.Contains(err.Error(), "bad policy") {
		t.Errorf("want the ORIGINAL error preserved, got: %v", err)
	}
	if mintAttempts != 1 {
		t.Errorf("mintAttempts = %d, want 1 (no pointless retry)", mintAttempts)
	}
}
