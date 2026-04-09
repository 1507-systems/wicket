// Package coffer provides an interface to the coffer vault for reading
// secrets. It shells out to the `coffer` CLI to decrypt values, keeping
// coffer as the single source of truth for vault operations.
package coffer

import (
	"fmt"
	"os/exec"
	"strings"
)

// Reader reads secrets from a coffer vault by shelling out to the coffer CLI.
type Reader struct {
	// VaultPath is the path to the coffer vault directory.
	VaultPath string
}

// NewReader creates a Reader pointing at the given vault directory.
func NewReader(vaultPath string) *Reader {
	return &Reader{VaultPath: vaultPath}
}

// Get retrieves a secret from the coffer vault. The path format is
// "<category>/<key>" (e.g., "cloudflare/meta-token"). This shells out
// to `coffer get <path>` and returns the decrypted value.
func (r *Reader) Get(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("coffer: empty path")
	}

	// Validate path format: must be category/key
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("coffer: invalid path %q (expected category/key format)", path)
	}

	cmd := exec.Command("coffer", "get", path)
	cmd.Dir = r.VaultPath

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("coffer get %q failed: %s (stderr: %s)", path, err, string(exitErr.Stderr))
		}
		return "", fmt.Errorf("coffer get %q failed: %w", path, err)
	}

	// Trim trailing newline that CLI tools typically append
	return strings.TrimSpace(string(output)), nil
}

// Set writes a secret back to the coffer vault. Used when a provider issues
// a new refresh token that must be persisted (e.g., Zoho OAuth rotation).
// Shells out to `coffer set <path> <value>`.
func (r *Reader) Set(path, value string) error {
	if path == "" {
		return fmt.Errorf("coffer: empty path for set")
	}
	if value == "" {
		return fmt.Errorf("coffer: empty value for set on path %q", path)
	}

	cmd := exec.Command("coffer", "set", path, value)
	cmd.Dir = r.VaultPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("coffer set %q failed: %w (output: %s)", path, err, string(output))
	}

	return nil
}
