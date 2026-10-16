package coffer

import "testing"

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		stderr string
		want   bool
	}{
		{"coffer: error: Failed to decrypt 'k' from 'ai': error truncating tree: component ['k'] not found (from: x)", true},
		{"coffer: error: Failed to get the data key required to decrypt the SOPS file", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isNotFound(c.stderr); got != c.want {
			t.Errorf("isNotFound(%q) = %v, want %v", c.stderr, got, c.want)
		}
	}
}
