// Package config handles parsing and validation of the wicket YAML
// configuration file. The config defines the socket path, coffer vault
// location, idle timeout, audit log path, and provider definitions.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfigPath returns the default config file location:
// ~/.config/wicket/config.yaml
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "wicket", "config.yaml")
}

// DefaultSocketPath returns the UID-suffixed socket path.
func DefaultSocketPath() string {
	return fmt.Sprintf("/tmp/wicket-%d.sock", os.Getuid())
}

// DefaultAuditLogPath returns the default audit log location.
func DefaultAuditLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "wicket", "audit.log")
}

// DefaultPIDPath returns the default PID file location.
func DefaultPIDPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "wicket", "wicket.pid")
}

// Config is the top-level configuration structure.
type Config struct {
	SocketPath      string                    `yaml:"socket_path"`
	CofferPath     string                    `yaml:"coffer_path"`
	IdleTimeout     Duration                  `yaml:"idle_timeout"`
	AuditLog        string                    `yaml:"audit_log"`
	PIDFile         string                    `yaml:"pid_file"`
	AllowedBinaries []string                  `yaml:"allowed_binaries"`
	Providers       map[string]ProviderConfig `yaml:"providers"`
}

// ProviderConfig holds the type-specific configuration for a single provider.
// Fields vary by type; unused fields for a given type are silently ignored.
type ProviderConfig struct {
	Type           string                    `yaml:"type"`             // "cloudflare", "github", "tailscale_oauth", "zoho_oauth", "passthrough"
	RootCredential string                    `yaml:"root_credential"` // coffer path for the root credential
	DefaultTTL     Duration                  `yaml:"default_ttl"`
	Scopes         map[string]ScopeConfig    `yaml:"scopes"`

	// GitHub-specific
	AppID          int64  `yaml:"app_id"`
	InstallationID int64  `yaml:"installation_id"`
	PrivateKey     string `yaml:"private_key"` // coffer path

	// Tailscale-specific
	ClientID     string `yaml:"client_id"`     // coffer path
	ClientSecret string `yaml:"client_secret"` // coffer path

	// Zoho-specific
	RefreshToken string `yaml:"refresh_token"` // coffer path
	Domain       string `yaml:"domain"`        // zoho.com, zoho.eu, etc.

	// Passthrough-specific
	Credential string `yaml:"credential"` // coffer path
}

// ScopeConfig holds the permissions and resource scoping for a single scope
// within a provider. Different provider types use different fields.
type ScopeConfig struct {
	// Cloudflare
	Permissions []string `yaml:"permissions"`
	ZoneIDs     []string `yaml:"zone_ids"`
	AccountIDs  []string `yaml:"account_ids"`

	// GitHub
	GHPermissions map[string]string `yaml:"gh_permissions"`
	Repositories  []string          `yaml:"repositories"`

	// Tailscale
	TailscaleScopes []string `yaml:"tailscale_scopes"`

	// Zoho
	ZohoScopes []string `yaml:"zoho_scopes"`
}

// Duration wraps time.Duration for YAML unmarshaling of human-readable
// durations like "15m", "4h", "0" (disabled).
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses duration strings. Accepts Go duration format ("15m",
// "4h") and the special value "0" which means disabled/no timeout.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		// Try as integer (seconds)
		var secs int64
		if err2 := value.Decode(&secs); err2 != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		d.Duration = time.Duration(secs) * time.Second
		return nil
	}

	if raw == "0" {
		d.Duration = 0
		return nil
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	d.Duration = parsed
	return nil
}

// MarshalYAML produces a human-readable duration string.
func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

// Load reads and parses a config file from the given path. If the path is
// empty, it uses the default config location.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot resolve home directory: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Apply defaults
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath()
	}
	if cfg.AuditLog == "" {
		cfg.AuditLog = DefaultAuditLogPath()
	}
	if cfg.PIDFile == "" {
		cfg.PIDFile = DefaultPIDPath()
	}

	// Expand ~ in paths
	cfg.SocketPath = expandHome(cfg.SocketPath)
	cfg.CofferPath = expandHome(cfg.CofferPath)
	cfg.AuditLog = expandHome(cfg.AuditLog)
	cfg.PIDFile = expandHome(cfg.PIDFile)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the config for logical errors.
func (c *Config) Validate() error {
	if c.CofferPath == "" {
		return fmt.Errorf("coffer_path is required")
	}

	if len(c.Providers) == 0 {
		return fmt.Errorf("at least one provider must be configured")
	}

	for name, p := range c.Providers {
		if p.Type == "" {
			return fmt.Errorf("provider %q: type is required", name)
		}

		switch p.Type {
		case "cloudflare":
			if p.RootCredential == "" {
				return fmt.Errorf("provider %q: root_credential is required for cloudflare type", name)
			}
		case "github":
			if p.PrivateKey == "" {
				return fmt.Errorf("provider %q: private_key is required for github type", name)
			}
			if p.AppID == 0 {
				return fmt.Errorf("provider %q: app_id is required for github type", name)
			}
			if p.InstallationID == 0 {
				return fmt.Errorf("provider %q: installation_id is required for github type", name)
			}
		case "tailscale_oauth":
			if p.ClientID == "" {
				return fmt.Errorf("provider %q: client_id is required for tailscale_oauth type", name)
			}
			if p.ClientSecret == "" {
				return fmt.Errorf("provider %q: client_secret is required for tailscale_oauth type", name)
			}
		case "zoho_oauth":
			if p.ClientID == "" {
				return fmt.Errorf("provider %q: client_id is required for zoho_oauth type", name)
			}
			if p.ClientSecret == "" {
				return fmt.Errorf("provider %q: client_secret is required for zoho_oauth type", name)
			}
			if p.RefreshToken == "" {
				return fmt.Errorf("provider %q: refresh_token is required for zoho_oauth type", name)
			}
		case "passthrough":
			if p.Credential == "" {
				return fmt.Errorf("provider %q: credential is required for passthrough type", name)
			}
		default:
			return fmt.Errorf("provider %q: unknown type %q", name, p.Type)
		}

		if len(p.Scopes) == 0 && p.Type != "passthrough" {
			return fmt.Errorf("provider %q: at least one scope is required", name)
		}
	}

	return nil
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
