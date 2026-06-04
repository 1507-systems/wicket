package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryAllowed(t *testing.T) {
	cases := []struct {
		name    string
		exe     string
		allowed []string
		want    bool
	}{
		{"exact match", "/usr/bin/foo", []string{"/usr/bin/foo"}, true},
		{"match among many", "/usr/bin/foo", []string{"/bin/bar", "/usr/bin/foo"}, true},
		{"no match", "/usr/bin/foo", []string{"/usr/bin/bar"}, false},
		{"empty exe never matches", "", []string{"/usr/bin/foo"}, false},
		{"empty allowlist never matches via this helper", "/usr/bin/foo", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := binaryAllowed(tc.exe, tc.allowed); got != tc.want {
				t.Errorf("binaryAllowed(%q, %v) = %v, want %v", tc.exe, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestResolvePeerExecutableSelf(t *testing.T) {
	exe, err := resolvePeerExecutable(int32(os.Getpid()))
	if err != nil {
		t.Skipf("peer executable resolution unsupported here: %v", err)
	}
	if exe == "" {
		t.Fatal("resolvePeerExecutable returned empty path with no error")
	}
	if !filepath.IsAbs(exe) {
		t.Errorf("resolvePeerExecutable returned non-absolute path %q", exe)
	}
}

// dialAndAuth runs a Unix socket accept loop that authenticates the peer with
// the given allowlist and returns the result over channels.
func dialAndAuth(t *testing.T, allowed []string) (*PeerInfo, error) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create test socket: %v", err)
	}
	defer listener.Close()

	done := make(chan *PeerInfo, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		peer, err := AuthenticatePeerWithBinaries(conn, allowed)
		if err != nil {
			errCh <- err
			return
		}
		done <- peer
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer client.Close()

	select {
	case peer := <-done:
		return peer, nil
	case err := <-errCh:
		return nil, err
	}
}

func TestAuthenticatePeerWithBinariesEmptyAllowlistAllows(t *testing.T) {
	// Empty allowlist preserves historical behavior: any same-UID caller is
	// accepted.
	peer, err := dialAndAuth(t, nil)
	if err != nil {
		t.Fatalf("expected success with empty allowlist, got %v", err)
	}
	if peer.UID != uint32(os.Getuid()) {
		t.Errorf("peer.UID = %d, want %d", peer.UID, os.Getuid())
	}
}

func TestAuthenticatePeerWithBinariesEnforcement(t *testing.T) {
	// Determine our own resolved exe path; if unsupported, the enforcement
	// path fails closed, which we assert below.
	selfExe, resErr := resolvePeerExecutable(int32(os.Getpid()))

	t.Run("allowed binary passes", func(t *testing.T) {
		if resErr != nil {
			t.Skipf("peer executable resolution unsupported here: %v", resErr)
		}
		peer, err := dialAndAuth(t, []string{selfExe})
		if err != nil {
			t.Fatalf("expected allowlisted binary to pass, got %v", err)
		}
		if peer.Binary != selfExe {
			t.Errorf("peer.Binary = %q, want %q", peer.Binary, selfExe)
		}
	})

	t.Run("disallowed binary rejected", func(t *testing.T) {
		_, err := dialAndAuth(t, []string{"/nonexistent/not-this-binary"})
		if err == nil {
			t.Fatal("expected rejection for non-allowlisted binary, got nil")
		}
	})
}
