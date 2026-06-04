// GitHub provider generates installation access tokens using a GitHub App's
// private key. The flow is:
//   1. Generate a JWT signed with the App's RSA private key
//   2. POST to /app/installations/{id}/access_tokens to get an installation token
//
// Installation tokens are valid for 1 hour (GitHub controls the exact
// expiration; we cannot request shorter).
package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ghAPIBase = "https://api.github.com"

// GitHubConfig holds the scope configuration for the GitHub provider.
type GitHubConfig struct {
	Scopes map[string]GitHubScope
}

// GitHubScope defines the permissions and repository filter for a single
// GitHub installation token scope.
type GitHubScope struct {
	Permissions  map[string]string // e.g., {"contents": "write", "pull_requests": "write"}
	Repositories []string          // repo names to scope to, or ["*"] for all
}

// GitHub exchanges an App private key for installation access tokens.
type GitHub struct {
	name           string
	appID          int64
	installationID int64
	privateKeyPEM  []byte
	privateKey     *rsa.PrivateKey
	config         GitHubConfig
	client         *http.Client
	healthy        bool
	mu             sync.RWMutex
}

// NewGitHub creates a GitHub App provider. The privateKeyPEM is the PEM-encoded
// RSA private key for the GitHub App.
func NewGitHub(name string, appID, installationID int64, privateKeyPEM []byte, config GitHubConfig) (*GitHub, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("github provider %q: failed to decode PEM private key", name)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format as fallback
		keyAny, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("github provider %q: failed to parse private key: %w (also tried PKCS8: %v)", name, err, err2)
		}
		var ok bool
		key, ok = keyAny.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("github provider %q: private key is not RSA", name)
		}
	}

	return &GitHub{
		name:           name,
		appID:          appID,
		installationID: installationID,
		privateKeyPEM:  privateKeyPEM,
		privateKey:     key,
		config:         config,
		client:         &http.Client{Timeout: 30 * time.Second},
		healthy:        true,
	}, nil
}

func (g *GitHub) Name() string { return g.name }
func (g *GitHub) Type() string { return "github" }

func (g *GitHub) Scopes() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	scopes := make([]string, 0, len(g.config.Scopes))
	for s := range g.config.Scopes {
		scopes = append(scopes, s)
	}
	return scopes
}

func (g *GitHub) Healthy() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.healthy
}

// GetToken generates a JWT, exchanges it for an installation access token,
// and returns the token scoped to the requested permissions.
func (g *GitHub) GetToken(ctx context.Context, scope string, _ map[string]any) (*Token, error) {
	g.mu.RLock()
	scopeCfg, ok := g.config.Scopes[scope]
	g.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("scope %q not configured for github provider %q", scope, g.name)
	}

	// Generate the JWT for authentication
	jwt, err := g.generateJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to generate GitHub JWT: %w", err)
	}

	// Build the installation token request
	body := map[string]any{
		"permissions": scopeCfg.Permissions,
	}

	// Only include repositories filter if not wildcard
	if len(scopeCfg.Repositories) > 0 && scopeCfg.Repositories[0] != "*" {
		body["repositories"] = scopeCfg.Repositories
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal installation token request: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", ghAPIBase, g.installationID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		g.mu.Lock()
		g.healthy = false
		g.mu.Unlock()
		return nil, fmt.Errorf("github API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		g.mu.Lock()
		g.healthy = false
		g.mu.Unlock()
		// Log the full upstream body to the daemon's own log only; do not
		// echo it back to the client (it may contain sensitive detail).
		slog.Error("github API error", "provider", g.name, "status", resp.StatusCode, "body", string(respBody))
		return nil, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var ghResp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	if err := json.Unmarshal(respBody, &ghResp); err != nil {
		return nil, fmt.Errorf("failed to parse github response: %w", err)
	}

	if ghResp.Token == "" {
		return nil, fmt.Errorf("github returned empty token")
	}

	g.mu.Lock()
	g.healthy = true
	g.mu.Unlock()

	return &Token{
		Value:     ghResp.Token,
		ExpiresAt: &ghResp.ExpiresAt,
		Provider:  g.name,
		Scope:     scope,
		Type:      "short-lived",
	}, nil
}

// generateJWT creates a signed JWT for GitHub App authentication.
// The JWT is valid for 10 minutes (GitHub's maximum).
func (g *GitHub) generateJWT() (string, error) {
	now := time.Now()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(), // 60 seconds in the past for clock skew
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": g.appID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64URLEncode(headerJSON)
	claimsB64 := base64URLEncode(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	sigB64 := base64URLEncode(sig)
	return signingInput + "." + sigB64, nil
}

// Close zeros the private key from memory.
func (g *GitHub) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	zeroBytes(g.privateKeyPEM)
	g.privateKey = nil
	g.healthy = false
	return nil
}

// base64URLEncode encodes bytes using URL-safe base64 without padding.
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}
