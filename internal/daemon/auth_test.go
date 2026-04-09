package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthenticatePeerSameUID(t *testing.T) {
	// Create a Unix socket pair for testing peer auth.
	// Both sides run as the same UID, so authentication should succeed.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create test socket: %v", err)
	}
	defer listener.Close()

	// Connect as client (same process, same UID)
	done := make(chan *PeerInfo, 1)
	errCh := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		peer, err := AuthenticatePeer(conn)
		if err != nil {
			errCh <- err
			return
		}
		done <- peer
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to connect to test socket: %v", err)
	}
	defer client.Close()

	select {
	case peer := <-done:
		myUID := uint32(os.Getuid())
		if peer.UID != myUID {
			t.Errorf("peer.UID = %d, want %d", peer.UID, myUID)
		}
		// PID should be set on both macOS and Linux
		if peer.PID <= 0 {
			t.Logf("warning: PID not available (got %d), this may be expected on some platforms", peer.PID)
		}
	case err := <-errCh:
		t.Fatalf("AuthenticatePeer() error: %v", err)
	}
}

func TestAuthenticatePeerNonUnixConn(t *testing.T) {
	// Create a TCP connection (not Unix socket) -- should fail
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create TCP listener: %v", err)
	}
	defer listener.Close()

	done := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		_, err = AuthenticatePeer(conn)
		done <- err
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer client.Close()

	err = <-done
	if err == nil {
		t.Fatal("expected error for non-Unix connection, got nil")
	}
}
