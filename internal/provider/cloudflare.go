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
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	cfAPIBase    = "https://api.cloudflare.com/client/v4"
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
	// apiBase is the Cloudflare API root. Overridable so tests can point at a
	// stub server without mutating package state.
	apiBase string
}

// NewCloudflare creates a Cloudflare provider.
func NewCloudflare(name, metaToken string, ttl time.Duration, config CloudflareConfig) *Cloudflare {
	if ttl <= 0 {
		ttl = cfDefaultTTL
	}
	return &Cloudflare{
		apiBase:   cfAPIBase,
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

	// Allow TTL override via options, but only to SHORTEN the lifetime.
	// A caller-supplied ttl must be positive and no greater than the
	// configured default; anything larger (or non-positive) is rejected so a
	// client cannot extend a token's lifetime beyond the configured policy.
	if opts != nil {
		if ttlStr, ok := opts["ttl"].(string); ok {
			parsed, err := time.ParseDuration(ttlStr)
			if err != nil {
				return nil, fmt.Errorf("invalid ttl option %q: %w", ttlStr, err)
			}
			if parsed <= 0 || parsed > ttl {
				return nil, fmt.Errorf("ttl option %s out of range: must be > 0 and <= configured default %s", parsed, ttl)
			}
			ttl = parsed
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

	// Mint, and if it fails, groom this machine's own expired tokens and try
	// ONCE more. Cloudflare caps user API tokens (~50) and EXPIRED tokens still
	// count against that cap, so a mint-only client eventually wedges itself:
	// every subsequent mint fails, and already-issued tokens start returning
	// code 10000 "Authentication error" — indistinguishable from the normal
	// fresh-token propagation delay, which sends operators into retry loops that
	// can never succeed. This has bitten repeatedly (see Cortex
	// ext:reference_cf_api_token_cap_exhaustion). Grooming on failure rather
	// than on every mint keeps the happy path free of an extra list call, and
	// makes the wedge self-healing instead of something a human must remember.
	value, err := c.mintToken(ctx, metaToken, bodyJSON)
	if err != nil {
		pruned, gErr := c.groomExpiredTokens(ctx, metaToken)
		if gErr != nil {
			slog.Warn("cloudflare token grooming failed after a failed mint",
				"provider", c.name, "mint_error", err, "groom_error", gErr)
			return nil, err
		}
		if pruned == 0 {
			// Nothing was reclaimable, so the cap is not the problem. Return
			// the original error rather than pretending a retry would help.
			return nil, err
		}
		slog.Info("groomed expired cloudflare tokens after a failed mint, retrying",
			"provider", c.name, "pruned", pruned)
		value, err = c.mintToken(ctx, metaToken, bodyJSON)
		if err != nil {
			return nil, err
		}
	}

	c.mu.Lock()
	c.healthy = true
	c.mu.Unlock()

	return &Token{
		Value:     value,
		ExpiresAt: &expiresOn,
		Provider:  c.name,
		Scope:     scope,
		Type:      "short-lived",
	}, nil
}

// mintToken performs the raw token-creation call and returns the token value.
// Split out of GetToken so a failed mint can be retried after grooming.
func (c *Cloudflare) mintToken(ctx context.Context, metaToken string, bodyJSON []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiBase+"/user/tokens", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+metaToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		return "", fmt.Errorf("cloudflare API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read cloudflare response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		c.mu.Lock()
		c.healthy = false
		c.mu.Unlock()
		// Log the full upstream body to the daemon's own log only; do not
		// echo it back to the client (it may contain sensitive detail).
		slog.Error("cloudflare API error", "provider", c.name, "status", resp.StatusCode, "body", string(respBody))
		return "", fmt.Errorf("cloudflare API returned status %d", resp.StatusCode)
	}

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
		return "", fmt.Errorf("failed to parse cloudflare response: %w", err)
	}
	if !cfResp.Success || cfResp.Result.Value == "" {
		errMsg := "unknown error"
		if len(cfResp.Errors) > 0 {
			errMsg = cfResp.Errors[0].Message
		}
		return "", fmt.Errorf("cloudflare token creation failed: %s", errMsg)
	}
	return cfResp.Result.Value, nil
}

// groomExpiredTokens deletes EXPIRED tokens that wicket itself minted, and
// returns how many it removed.
//
// Deliberately conservative on two axes, because this runs unattended:
//   - only status=="expired" — an active token may still be in a caller's hand
//   - only names with the "wicket-" prefix — never a human's long-lived named
//     token, and never another tool's ephemerals, even when expired
//
// A delete failure is logged and skipped rather than aborting the sweep: one
// stubborn token must not prevent reclaiming the rest.
func (c *Cloudflare) groomExpiredTokens(ctx context.Context, metaToken string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.apiBase+"/user/tokens?per_page=100", nil)
	if err != nil {
		return 0, fmt.Errorf("failed to build token list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+metaToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to list cloudflare tokens: %w", err)
	}
	defer resp.Body.Close()

	listBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read token list: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("cloudflare token list returned status %d", resp.StatusCode)
	}

	var listResp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal(listBody, &listResp); err != nil {
		return 0, fmt.Errorf("failed to parse token list: %w", err)
	}
	if !listResp.Success {
		return 0, fmt.Errorf("cloudflare token list was unsuccessful")
	}

	pruned := 0
	for _, t := range listResp.Result {
		if t.Status != "expired" || !strings.HasPrefix(t.Name, "wicket-") {
			continue
		}
		delReq, err := http.NewRequestWithContext(ctx, "DELETE", c.apiBase+"/user/tokens/"+t.ID, nil)
		if err != nil {
			slog.Warn("could not build token delete request", "provider", c.name, "token", t.Name, "error", err)
			continue
		}
		delReq.Header.Set("Authorization", "Bearer "+metaToken)
		delResp, err := c.client.Do(delReq)
		if err != nil {
			slog.Warn("failed to delete expired token", "provider", c.name, "token", t.Name, "error", err)
			continue
		}
		delResp.Body.Close()
		if delResp.StatusCode != http.StatusOK {
			slog.Warn("unexpected status deleting expired token", "provider", c.name, "token", t.Name, "status", delResp.StatusCode)
			continue
		}
		pruned++
	}
	return pruned, nil
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
