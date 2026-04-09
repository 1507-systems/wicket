package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `
coffer_path: ~/dev/coffer
idle_timeout: "4h"
audit_log: /tmp/wicket-test-audit.log
providers:
  homeassistant:
    type: passthrough
    credential: home-automation/ha-token
  cloudflare:
    type: cloudflare
    root_credential: cloudflare/meta-token
    default_ttl: "15m"
    scopes:
      dns:
        permissions:
          - "zone:dns_records:edit"
        zone_ids:
          - "*"
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.IdleTimeout.Duration.Hours() != 4 {
		t.Errorf("idle_timeout = %v, want 4h", cfg.IdleTimeout.Duration)
	}

	if cfg.AuditLog != "/tmp/wicket-test-audit.log" {
		t.Errorf("audit_log = %q, want /tmp/wicket-test-audit.log", cfg.AuditLog)
	}

	if len(cfg.Providers) != 2 {
		t.Errorf("providers count = %d, want 2", len(cfg.Providers))
	}

	ha, ok := cfg.Providers["homeassistant"]
	if !ok {
		t.Fatal("missing homeassistant provider")
	}
	if ha.Type != "passthrough" {
		t.Errorf("homeassistant type = %q, want passthrough", ha.Type)
	}
	if ha.Credential != "home-automation/ha-token" {
		t.Errorf("homeassistant credential = %q, want home-automation/ha-token", ha.Credential)
	}

	cf, ok := cfg.Providers["cloudflare"]
	if !ok {
		t.Fatal("missing cloudflare provider")
	}
	if cf.DefaultTTL.Duration.Minutes() != 15 {
		t.Errorf("cloudflare default_ttl = %v, want 15m", cf.DefaultTTL.Duration)
	}

	dns, ok := cf.Scopes["dns"]
	if !ok {
		t.Fatal("missing dns scope in cloudflare provider")
	}
	if len(dns.Permissions) != 1 || dns.Permissions[0] != "zone:dns_records:edit" {
		t.Errorf("dns permissions = %v, want [zone:dns_records:edit]", dns.Permissions)
	}
}

func TestLoadMissingCofferPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `
providers:
  test:
    type: passthrough
    credential: test/cred
`
	os.WriteFile(cfgPath, []byte(yaml), 0600)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for missing coffer_path, got nil")
	}
}

func TestLoadNoProviders(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `
coffer_path: ~/dev/coffer
`
	os.WriteFile(cfgPath, []byte(yaml), 0600)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for no providers, got nil")
	}
}

func TestLoadInvalidProviderType(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `
coffer_path: ~/dev/coffer
providers:
  test:
    type: invalid_type
    credential: test/cred
`
	os.WriteFile(cfgPath, []byte(yaml), 0600)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid provider type, got nil")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestDurationParsing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `
coffer_path: ~/dev/coffer
idle_timeout: "0"
providers:
  test:
    type: passthrough
    credential: test/cred
`
	os.WriteFile(cfgPath, []byte(yaml), 0600)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.IdleTimeout.Duration != 0 {
		t.Errorf("idle_timeout = %v, want 0 (disabled)", cfg.IdleTimeout.Duration)
	}
}

func TestValidateCloudflareRequiresRootCredential(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `
coffer_path: ~/dev/coffer
providers:
  cf:
    type: cloudflare
    scopes:
      dns:
        permissions: ["zone:dns_records:edit"]
`
	os.WriteFile(cfgPath, []byte(yaml), 0600)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for cloudflare without root_credential, got nil")
	}
}

func TestValidateGitHubRequiresFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yaml := `
coffer_path: ~/dev/coffer
providers:
  gh:
    type: github
    private_key: github/key
    scopes:
      repos:
        permissions:
          contents: write
`
	os.WriteFile(cfgPath, []byte(yaml), 0600)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for github without app_id, got nil")
	}
}
