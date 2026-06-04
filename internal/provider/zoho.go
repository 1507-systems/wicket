// Zoho OAuth provider exchanges a refresh token for short-lived access
// tokens. If Zoho issues a new refresh token during the exchange, it is
// written back to coffer immediately to prevent token invalidation.
//
// Token exchange: POST https://accounts.zoho.com/oauth/v2/token
// with grant_type=refresh_token.
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

	"github.com/1507-systems/wicket/internal/coffer"
	"github.com/1507-systems/wicket/internal/notify"
)

// ZohoConfig holds the scope configuration for the Zoho provider.
type ZohoConfig struct {
	Scopes map[string]ZohoScope
}

// ZohoScope defines the Zoho-specific OAuth scopes to request.
type ZohoScope struct {
	ZohoScopes []string // e.g., "ZohoCRM.modules.ALL"
}

// Zoho exchanges a refresh token for OAuth access tokens.
type Zoho struct {
	name           string
	clientID       string
	clientSecret   string
	refreshToken   string
	refreshPath    string // coffer path for persisting rotated refresh tokens
	domain         string // zoho.com, zoho.eu, etc.
	config         ZohoConfig
	cofferReader  *coffer.Reader
	notifier       *notify.Notifier
	client         *http.Client
	healthy        bool
	mu             sync.RWMutex
}

// NewZoho creates a Zoho OAuth provider.
func NewZoho(name, clientID, clientSecret, refreshToken, refreshPath, domain string, config ZohoConfig, lr *coffer.Reader, notifier *notify.Notifier) *Zoho {
	if domain == "" {
		domain = "zoho.com"
	}
	return &Zoho{
		name:          name,
		clientID:      clientID,
		clientSecret:  clientSecret,
		refreshToken:  refreshToken,
		refreshPath:   refreshPath,
		domain:        domain,
		config:        config,
		cofferReader: lr,
		notifier:      notifier,
		client:        &http.Client{Timeout: 30 * time.Second},
		healthy:       clientID != "" && clientSecret != "" && refreshToken != "",
	}
}

func (z *Zoho) Name() string { return z.name }
func (z *Zoho) Type() string { return "zoho_oauth" }

func (z *Zoho) Scopes() []string {
	z.mu.RLock()
	defer z.mu.RUnlock()
	scopes := make([]string, 0, len(z.config.Scopes))
	for s := range z.config.Scopes {
		scopes = append(scopes, s)
	}
	return scopes
}

func (z *Zoho) Healthy() bool {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.healthy
}

// GetToken performs the OAuth refresh_token exchange to obtain an access token.
// If Zoho issues a new refresh token, it is persisted back to coffer.
func (z *Zoho) GetToken(ctx context.Context, scope string, _ map[string]any) (*Token, error) {
	z.mu.RLock()
	scopeCfg, ok := z.config.Scopes[scope]
	clientID := z.clientID
	clientSecret := z.clientSecret
	refreshToken := z.refreshToken
	z.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("scope %q not configured for zoho provider %q", scope, z.name)
	}

	endpoint := fmt.Sprintf("https://accounts.%s/oauth/v2/token", z.domain)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	}

	// Add scopes if configured
	if len(scopeCfg.ZohoScopes) > 0 {
		form.Set("scope", strings.Join(scopeCfg.ZohoScopes, ","))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := z.client.Do(req)
	if err != nil {
		z.mu.Lock()
		z.healthy = false
		z.mu.Unlock()
		return nil, fmt.Errorf("zoho OAuth request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read zoho response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		z.mu.Lock()
		z.healthy = false
		z.mu.Unlock()
		// Log the full upstream body to the daemon's own log only; do not
		// echo it back to the client (it may contain sensitive detail).
		slog.Error("zoho OAuth error", "provider", z.name, "status", resp.StatusCode, "body", string(respBody))
		return nil, fmt.Errorf("zoho OAuth returned status %d", resp.StatusCode)
	}

	var oauthResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"` // may be issued on rotation
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Error        string `json:"error"`
	}

	if err := json.Unmarshal(respBody, &oauthResp); err != nil {
		return nil, fmt.Errorf("failed to parse zoho response: %w", err)
	}

	if oauthResp.Error != "" {
		z.mu.Lock()
		z.healthy = false
		z.mu.Unlock()
		return nil, fmt.Errorf("zoho OAuth error: %s", oauthResp.Error)
	}

	if oauthResp.AccessToken == "" {
		return nil, fmt.Errorf("zoho returned empty access token")
	}

	// If Zoho issued a new refresh token, persist it back to coffer immediately.
	// This is critical: the old refresh token may now be invalidated.
	if oauthResp.RefreshToken != "" && oauthResp.RefreshToken != refreshToken {
		slog.Info("zoho issued new refresh token, persisting to coffer", "provider", z.name)

		if err := z.cofferReader.Set(z.refreshPath, oauthResp.RefreshToken); err != nil {
			// This is a critical failure: the old refresh token may be invalidated
			errMsg := fmt.Sprintf("CRITICAL: failed to persist new Zoho refresh token to coffer: %v", err)
			slog.Error(errMsg, "provider", z.name)

			if z.notifier != nil {
				z.notifier.Send("zoho_refresh_writeback", "Wicket: Zoho Refresh Token Failure", errMsg)
			}

			return nil, fmt.Errorf("%s", errMsg)
		}

		// Update in-memory refresh token
		z.mu.Lock()
		z.refreshToken = oauthResp.RefreshToken
		z.mu.Unlock()
	}

	expiresAt := time.Now().UTC().Add(time.Duration(oauthResp.ExpiresIn) * time.Second)

	z.mu.Lock()
	z.healthy = true
	z.mu.Unlock()

	return &Token{
		Value:     oauthResp.AccessToken,
		ExpiresAt: &expiresAt,
		Provider:  z.name,
		Scope:     scope,
		Type:      "short-lived",
	}, nil
}

// Close zeros all credential memory.
func (z *Zoho) Close() error {
	z.mu.Lock()
	defer z.mu.Unlock()
	zeroString(&z.clientID)
	zeroString(&z.clientSecret)
	zeroString(&z.refreshToken)
	z.healthy = false
	return nil
}
