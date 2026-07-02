package daemon

import (
	"os"
	"testing"
)

// shortSocketDir returns a temp dir with a path short enough for Unix socket
// binding. macOS caps sun_path at 104 bytes and t.TempDir() embeds the full
// test name, which overflows the limit for long test names and fails with
// "bind: invalid argument".
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wsock")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
