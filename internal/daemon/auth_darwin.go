//go:build darwin

package daemon

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// authenticatePeerOS extracts peer credentials on macOS using LOCAL_PEERCRED
// and LOCAL_PEERPID.
func authenticatePeerOS(conn net.Conn) (*PeerInfo, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a Unix socket")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw connection: %w", err)
	}

	var peer PeerInfo
	var credErr error

	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credErr = fmt.Errorf("GetsockoptXucred failed: %w", err)
			return
		}
		peer.UID = cred.Uid

		// Try to get the PID (macOS-specific, non-critical if it fails)
		pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if err == nil {
			peer.PID = int32(pid)
		}
	})

	if err != nil {
		return nil, fmt.Errorf("raw connection control failed: %w", err)
	}
	if credErr != nil {
		return nil, credErr
	}

	// Verify UID matches the daemon's own UID
	myUID := uint32(os.Getuid())
	if peer.UID != myUID {
		return nil, fmt.Errorf("UID mismatch: peer UID %d does not match daemon UID %d", peer.UID, myUID)
	}

	return &peer, nil
}
