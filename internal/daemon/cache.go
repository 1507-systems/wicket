package daemon

import (
	"sync"
	"time"

	"github.com/1507-systems/wicket/internal/provider"
)

// minTTLFraction is the minimum fraction of a token's original TTL that must
// remain for a cached token to be reused (SPEC "Token Caching": >30%).
const minTTLFraction = 0.30

// cacheEntry pairs an issued token with its issuance time so the original
// TTL can be reconstructed when deciding whether the token is still fresh.
type cacheEntry struct {
	token    *provider.Token
	issuedAt time.Time
}

// tokenCache is an in-memory cache of issued tokens keyed by provider/scope.
// A cached token is reused while more than minTTLFraction of its original
// TTL remains; otherwise the entry is evicted and a fresh token is minted.
// Tokens without an expiry (passthrough) are never cached -- the provider
// returns them instantly and there is no TTL to reason about.
type tokenCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

func newTokenCache() *tokenCache {
	return &tokenCache{entries: make(map[string]cacheEntry)}
}

func cacheKey(providerName, scope string) string {
	return providerName + "/" + scope
}

// get returns the cached token for provider/scope if, at time now, it still
// has more than minTTLFraction of its original TTL remaining. Stale entries
// are evicted and nil is returned.
func (c *tokenCache) get(providerName, scope string, now time.Time) *provider.Token {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(providerName, scope)
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !reusable(e, now) {
		delete(c.entries, key)
		return nil
	}
	return e.token
}

// reusable reports whether a cache entry still has more than minTTLFraction
// of its original TTL remaining at time now.
func reusable(e cacheEntry, now time.Time) bool {
	if e.token == nil || e.token.ExpiresAt == nil {
		return false
	}
	total := e.token.ExpiresAt.Sub(e.issuedAt)
	if total <= 0 {
		return false
	}
	remaining := e.token.ExpiresAt.Sub(now)
	return float64(remaining) > minTTLFraction*float64(total)
}

// put stores an issued token. Tokens without an expiry are not cached.
func (c *tokenCache) put(providerName, scope string, tok *provider.Token, issuedAt time.Time) {
	if tok == nil || tok.ExpiresAt == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cacheKey(providerName, scope)] = cacheEntry{token: tok, issuedAt: issuedAt}
}

// clear drops all cached tokens. Called on lock and shutdown so cached
// token values do not outlive the credentials that minted them.
func (c *tokenCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}
