// Cloudflare provider exchanges a root meta-token for short-lived,
// scoped API tokens using the Cloudflare API. The meta-token must have
// "Create Additional Tokens" permission.
//
// Token exchange: POST https://api.cloudflare.com/client/v4/user/tokens
// with a policies array defining permission groups + resource scoping,
// and an expires_on field set to now + configured TTL (default 15min).
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	cfAPIBase   = "https://api.cloudflare.com/client/v4"
	cfDefaultTTL = 15 * time.Minute
)

// CloudflareConfig holds the scope configuration for the Cloudflare provider.
type CloudflareConfig struct {
	Scopes map[string]CloudflareScope
}

// CloudflareScope defines the permissions and resource constraints for a
// single Cloudflare token scope.
type CloudflareScope struct {
	Permissions []string // e.g., "zone:dns_records:edit"
	ZoneIDs     []string // zone resource scoping
	AccountIDs  []string // account resource scoping
}

// Cloudflare exchanges a root meta-token for short-lived scoped tokens.
type Cloudflare struct {
	name      string
	metaToken string
	ttl       time.Duration
	config    CloudflareConfig
	client    *http.Client
	healthy   bool
	mu        sync.RWMutex
}

// NewCloudflare creates a Cloudflare provider.
func NewCloudflare(name, metaToken string, ttl time.Duration, config CloudflareConfig) *Cloudflare {
	if ttl <= 0 {
		ttl = cfDefaultTTL
	}
	return &Cloudflare{
		name:      name,
		metaToken: metaToken,
		ttl:       ttl,
		config:    config,
		client:    &http.Client{Timeout: 30 * time.Second},
		healthy:   metaToken != "",
	}
}

func (c *Cloudflare) Name() string { return c.name }
func (c *Cloudflare) Type() string { return "cloudflare" }

func (c *Cloudflare) Scopes() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	scopes := make([]string, 0, len(c.config.Scopes))
	for s := range c.config.Scopes {
		scopes = append(scopes, s)
	}
	return scopes
}

func (c *Cloudflare) Healthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

// GetToken creates a short-lived Cloudflare API token scoped to the
// requested permissions. The token auto-expires after the configured TTL.
func (c *Cloudflare) GetToken(ctx context.Context, scope string, opts map[string]any) (*Token, error) {
	c.mu.RLock()
	scopeCfg, ok := c.config.Scopes[scope]
	metaToken := c.metaToken
	ttl := c.ttl
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("scope %q not configured for cloudflare provider %q", scope, c.name)
	}

	// Allow TTL override via options
	if opts != nil {
		if ttlStr, ok := opts["ttl"].(string); ok {
			if parsed, err := time.ParseDuration(ttlStr); err == nil {
				ttl = parsed
			}
		}
	}

	expiresOn := time.Now().UTC().Add(ttl)

	// Build the token creation request body
	// Cloudflare API expects policies with permission groups and resources
	policies := buildCFPolicies(scopeCfg)

	body := map[string]any{
		"name":       fmt.Sprintf("wicket-%s-%s-%d", c.name, scope, time.Now().Unix()),
		"policies":   policies,
		"expires_on": expiresOn.Format(time.RFC3339),
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cfAPIBase+"/user/tokens", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+metaToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		return nil, fmt.Errorf("cloudflare API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read cloudflare response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		return nil, fmt.Errorf("cloudflare API returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the response to extract the token value
	var cfResp struct {
		Success bool `json:"success"`
		Result  struct {
			Value string `json:"value"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("failed to parse cloudflare response: %w", err)
	}

	if !cfResp.Success || cfResp.Result.Value == "" {
		errMsg := "unknown error"
		if len(cfResp.Errors) > 0 {
			errMsg = cfResp.Errors[0].Message
		}
		return nil, fmt.Errorf("cloudflare token creation failed: %s", errMsg)
	}

	c.mu.Lock()
	c.healthy = true
	c.mu.Unlock()

	return &Token{
		Value:     cfResp.Result.Value,
		ExpiresAt: &expiresOn,
		Provider:  c.name,
		Scope:     scope,
		Type:      "short-lived",
	}, nil
}

// Close zeros the meta-token from memory.
func (c *Cloudflare) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	zeroString(&c.metaToken)
	c.healthy = false
	return nil
}

// buildCFPolicies converts scope config into Cloudflare policy format.
func buildCFPolicies(scope CloudflareScope) []map[string]any {
	// Build permission groups from the scope's permissions list
	permGroups := make([]map[string]any, 0, len(scope.Permissions))
	for _, perm := range scope.Permissions {
		permGroups = append(permGroups, map[string]any{
			"id": perm, // The actual permission group ID would be resolved from config
		})
	}

	// Build resource scoping
	resources := make(map[string]string)
	for _, zoneID := range scope.ZoneIDs {
		if zoneID == "*" {
			resources["com.cloudflare.api.account.zone.*"] = "*"
		} else {
			resources["com.cloudflare.api.account.zone."+zoneID] = "*"
		}
	}
	for _, accountID := range scope.AccountIDs {
		resources["com.cloudflare.api.account."+accountID] = "*"
	}

	return []map[string]any{
		{
			"effect":            "allow",
			"permission_groups": permGroups,
			"resources":         resources,
		},
	}
}
