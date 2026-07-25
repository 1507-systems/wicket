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

// TestTokenIsDeadHandlesCloudflareLazyStatus pins the predicate that every
// previous cleaner in this fleet got wrong.
//
// Cloudflare leaves status=="active" long after expires_on passes (postmortem
// 2026-06-03 observed 9d23h). A status-only filter therefore never reaps the
// tokens that actually fill the quota, which is why the cap kept being hit.
func TestTokenIsDeadHandlesCloudflareLazyStatus(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	rfc := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }

	cases := []struct {
		name      string
		status    string
		expiresOn string
		want      bool
		why       string
	}{
		{"cloudflare says expired", "expired", rfc(-time.Hour), true,
			"the easy case every old cleaner already handled"},
		{"THE GHOST: long past expiry but still active", "active", rfc(-240 * time.Hour), true,
			"the actual quota filler — status lags by days, so expires_on must decide"},
		{"just past expiry, still active", "active", rfc(-5 * time.Minute), true,
			"past the grace period, so reclaimable"},
		{"expired seconds ago", "active", rfc(-10 * time.Second), false,
			"inside the grace period: a caller may still be holding it"},
		{"live token", "active", rfc(2 * time.Hour), false,
			"must never be touched"},
		{"no expires_on", "active", "", false,
			"cannot reason about it, so leave it alone"},
		{"garbage expires_on", "active", "not-a-timestamp", false,
			"unparseable must fail safe, not delete"},
		{"expired status wins over garbage date", "expired", "not-a-timestamp", true,
			"cloudflare's own verdict is authoritative"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenIsDead(tc.status, tc.expiresOn, now); got != tc.want {
				t.Errorf("tokenIsDead(%q, %q) = %v, want %v — %s",
					tc.status, tc.expiresOn, got, tc.want, tc.why)
			}
		})
	}
}

// TestGroomReapsTimeExpiredGhost proves the groomer acts on a ghost end to end,
// not just that the predicate is right in isolation.
func TestGroomReapsTimeExpiredGhost(t *testing.T) {
	past := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)

	var deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"success":true,"result":[
			{"id":"ghost","name":"wicket-cf-dns-ghost","status":"active","expires_on":%q},
			{"id":"live","name":"wicket-cf-dns-live","status":"active","expires_on":%q},
			{"id":"foreign","name":"ephemeral-other","status":"active","expires_on":%q}
		]}`, past, future, past)
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
	if len(deleted) != 1 || deleted[0] != "ghost" {
		t.Errorf("deleted = %v, want [ghost] — the live wicket token and another "+
			"tool's expired ephemeral must both survive", deleted)
	}
}
