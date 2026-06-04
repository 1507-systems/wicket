// Tailscale OAuth provider exchanges client credentials for short-lived
// access tokens using the OAuth client_credentials grant.
//
// Token exchange: POST https://api.tailscale.com/api/v2/oauth/token
// with grant_type=client_credentials.
//
// Scopes are set on the OAuth client in Tailscale admin; wicket requests
// the intersection of configured scopes.
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const tsOAuthEndpoint = "https://api.tailscale.com/api/v2/oauth/token"

// TailscaleConfig holds the scope configuration for the Tailscale provider.
type TailscaleConfig struct {
	Scopes map[string]TailscaleScope
}

// TailscaleScope defines the Tailscale-specific scopes to request.
type TailscaleScope struct {
	TailscaleScopes []string // e.g., "devices:read", "dns:read"
}

// Tailscale exchanges OAuth client credentials for access tokens.
type Tailscale struct {
	name         string
	clientID     string
	clientSecret string
	config       TailscaleConfig
	client       *http.Client
	healthy      bool
	mu           sync.RWMutex
}

// NewTailscale creates a Tailscale OAuth provider.
func NewTailscale(name, clientID, clientSecret string, config TailscaleConfig) *Tailscale {
	return &Tailscale{
		name:         name,
		clientID:     clientID,
		clientSecret: clientSecret,
		config:       config,
		client:       &http.Client{Timeout: 30 * time.Second},
		healthy:      clientID != "" && clientSecret != "",
	}
}

func (t *Tailscale) Name() string { return t.name }
func (t *Tailscale) Type() string { return "tailscale_oauth" }

func (t *Tailscale) Scopes() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	scopes := make([]string, 0, len(t.config.Scopes))
	for s := range t.config.Scopes {
		scopes = append(scopes, s)
	}
	return scopes
}

func (t *Tailscale) Healthy() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.healthy
}

// GetToken performs the OAuth client_credentials exchange to obtain an
// access token. Returns a token valid for approximately 1 hour.
func (t *Tailscale) GetToken(ctx context.Context, scope string, _ map[string]any) (*Token, error) {
	t.mu.RLock()
	scopeCfg, ok := t.config.Scopes[scope]
	clientID := t.clientID
	clientSecret := t.clientSecret
	t.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("scope %q not configured for tailscale provider %q", scope, t.name)
	}

	// Build form data for the token request
	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	// Add scopes if configured
	if len(scopeCfg.TailscaleScopes) > 0 {
		form.Set("scope", strings.Join(scopeCfg.TailscaleScopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tsOAuthEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		t.mu.Lock()
		t.healthy = false
		t.mu.Unlock()
		return nil, fmt.Errorf("tailscale OAuth request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read tailscale response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.mu.Lock()
		t.healthy = false
		t.mu.Unlock()
		// Log the full upstream body to the daemon's own log only; do not
		// echo it back to the client (it may contain sensitive detail).
		slog.Error("tailscale OAuth error", "provider", t.name, "status", resp.StatusCode, "body", string(respBody))
		return nil, fmt.Errorf("tailscale OAuth returned status %d", resp.StatusCode)
	}

	var oauthResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(respBody, &oauthResp); err != nil {
		return nil, fmt.Errorf("failed to parse tailscale response: %w", err)
	}

	if oauthResp.AccessToken == "" {
		return nil, fmt.Errorf("tailscale returned empty access token")
	}

	expiresAt := time.Now().UTC().Add(time.Duration(oauthResp.ExpiresIn) * time.Second)

	t.mu.Lock()
	t.healthy = true
	t.mu.Unlock()

	return &Token{
		Value:     oauthResp.AccessToken,
		ExpiresAt: &expiresAt,
		Provider:  t.name,
		Scope:     scope,
		Type:      "short-lived",
	}, nil
}

// Close zeros the client credentials from memory.
func (t *Tailscale) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	zeroString(&t.clientID)
	zeroString(&t.clientSecret)
	t.healthy = false
	return nil
}
