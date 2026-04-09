package main

import (
	"strings"
	"testing"
)

func TestParseProviderScope(t *testing.T) {
	tests := []struct {
		input    string
		provider string
		scope    string
		wantErr  bool
	}{
		{"cloudflare/dns", "cloudflare", "dns", false},
		{"github/repos", "github", "repos", false},
		{"homeassistant/token", "homeassistant", "token", false},
		{"a/b", "a", "b", false},
		// Invalid formats
		{"nodivider", "", "", true},
		{"/noprovider", "", "", true},
		{"noscope/", "", "", true},
		{"", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parts := strings.SplitN(tt.input, "/", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				if !tt.wantErr {
					t.Errorf("parsing %q failed unexpectedly", tt.input)
				}
				return
			}

			if tt.wantErr {
				t.Errorf("parsing %q should have failed", tt.input)
				return
			}

			if parts[0] != tt.provider {
				t.Errorf("provider = %q, want %q", parts[0], tt.provider)
			}
			if parts[1] != tt.scope {
				t.Errorf("scope = %q, want %q", parts[1], tt.scope)
			}
		})
	}
}
