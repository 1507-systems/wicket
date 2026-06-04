// Package daemon implements the wicket Unix socket server, connection
// handling, peer authentication, and daemon state management.
package daemon

import (
	"fmt"
	"net"
)

// PeerInfo contains the authenticated identity of a connecting process.
type PeerInfo struct {
	UID uint32
	GID uint32
	PID int32

	// Binary is the absolute path to the peer process's executable, when it
	// could be resolved from PID. Empty if resolution failed or is
	// unsupported on the platform.
	Binary string
}

// AuthenticatePeer extracts and verifies the identity of the connecting
// process using kernel-provided credentials. On Linux this uses SO_PEERCRED;
// on macOS it uses LOCAL_PEERCRED + LOCAL_PEERPID.
// Returns an error if the connecting UID does not match the daemon's UID.
func AuthenticatePeer(conn net.Conn) (*PeerInfo, error) {
	return authenticatePeerOS(conn)
}

// AuthenticatePeerWithBinaries authenticates the peer (UID match) and then,
// when allowedBinaries is non-empty, additionally enforces that the peer's
// executable path is on the allowlist. An empty allowedBinaries means the
// binary check is disabled (allow any same-UID caller), preserving the
// historical default behavior.
//
// The peer's resolved executable path is recorded in PeerInfo.Binary
// regardless of whether the allowlist is enforced, so it can be logged.
func AuthenticatePeerWithBinaries(conn net.Conn, allowedBinaries []string) (*PeerInfo, error) {
	peer, err := authenticatePeerOS(conn)
	if err != nil {
		return nil, err
	}

	// Best-effort: resolve the peer executable path for auditing. A failure
	// here is only fatal when the allowlist is being enforced (below).
	if peer.PID > 0 {
		if exe, perr := resolvePeerExecutable(peer.PID); perr == nil {
			peer.Binary = exe
		} else if len(allowedBinaries) > 0 {
			// Allowlist is active but we cannot identify the caller binary:
			// fail closed.
			return nil, fmt.Errorf("allowed_binaries enforced but peer executable could not be resolved: %w", perr)
		}
	} else if len(allowedBinaries) > 0 {
		return nil, fmt.Errorf("allowed_binaries enforced but peer PID is unavailable")
	}

	if len(allowedBinaries) > 0 {
		if !binaryAllowed(peer.Binary, allowedBinaries) {
			return nil, fmt.Errorf("peer executable %q is not in allowed_binaries", peer.Binary)
		}
	}

	return peer, nil
}

// binaryAllowed reports whether exe matches any entry in allowed. An entry
// matches when it equals the executable path exactly.
func binaryAllowed(exe string, allowed []string) bool {
	if exe == "" {
		return false
	}
	for _, a := range allowed {
		if a == exe {
			return true
		}
	}
	return false
}
