package daemon

import (
	"testing"
	"time"

	"github.com/1507-systems/wicket/internal/provider"
)

// mkToken builds a short-lived token issued at issuedAt with the given TTL.
func mkToken(value string, issuedAt time.Time, ttl time.Duration) *provider.Token {
	exp := issuedAt.Add(ttl)
	return &provider.Token{
		Value:     value,
		ExpiresAt: &exp,
		Provider:  "p",
		Scope:     "s",
		Type:      "short-lived",
	}
}

func TestTokenCacheReusesFreshToken(t *testing.T) {
	c := newTokenCache()
	issued := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	tok := mkToken("tok-1", issued, 100*time.Minute)
	c.put("p", "s", tok, issued)

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"immediately after issuance", issued, true},
		{"50% TTL remaining", issued.Add(50 * time.Minute), true},
		{"just above 30% remaining", issued.Add(69 * time.Minute), true},
		{"exactly 30% remaining is NOT reused", issued.Add(70 * time.Minute), false},
		{"below 30% remaining", issued.Add(71 * time.Minute), false},
		{"expired", issued.Add(200 * time.Minute), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Re-put before each case since a stale get evicts the entry.
			c.put("p", "s", tok, issued)
			got := c.get("p", "s", tc.now)
			if (got != nil) != tc.want {
				t.Errorf("get at %v: hit=%v, want %v", tc.now, got != nil, tc.want)
			}
			if tc.want && got.Value != "tok-1" {
				t.Errorf("got token %q, want tok-1", got.Value)
			}
		})
	}
}

func TestTokenCacheEvictsStaleEntry(t *testing.T) {
	c := newTokenCache()
	issued := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	c.put("p", "s", mkToken("tok-1", issued, 10*time.Minute), issued)

	// Stale lookup evicts the entry...
	if got := c.get("p", "s", issued.Add(9*time.Minute)); got != nil {
		t.Fatalf("expected stale token to miss, got %q", got.Value)
	}
	// ...so even a lookup at a fresh time now misses.
	if got := c.get("p", "s", issued); got != nil {
		t.Errorf("expected evicted entry to stay gone, got %q", got.Value)
	}
}

func TestTokenCacheKeysByProviderAndScope(t *testing.T) {
	c := newTokenCache()
	issued := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	c.put("p1", "s1", mkToken("tok-a", issued, time.Hour), issued)
	c.put("p1", "s2", mkToken("tok-b", issued, time.Hour), issued)

	if got := c.get("p1", "s1", issued); got == nil || got.Value != "tok-a" {
		t.Errorf("p1/s1 = %v, want tok-a", got)
	}
	if got := c.get("p1", "s2", issued); got == nil || got.Value != "tok-b" {
		t.Errorf("p1/s2 = %v, want tok-b", got)
	}
	if got := c.get("p2", "s1", issued); got != nil {
		t.Errorf("p2/s1 = %q, want miss", got.Value)
	}
}

func TestTokenCacheSkipsTokensWithoutExpiry(t *testing.T) {
	c := newTokenCache()
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	c.put("p", "s", &provider.Token{Value: "static", Type: "passthrough"}, now)

	if got := c.get("p", "s", now); got != nil {
		t.Errorf("passthrough token should not be cached, got %q", got.Value)
	}
}

func TestTokenCacheClear(t *testing.T) {
	c := newTokenCache()
	issued := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	c.put("p", "s", mkToken("tok-1", issued, time.Hour), issued)

	c.clear()

	if got := c.get("p", "s", issued); got != nil {
		t.Errorf("expected empty cache after clear, got %q", got.Value)
	}
}
