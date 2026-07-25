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

	// ParentBinary is set only when the allowlist admitted this call on the
	// strength of the PARENT process rather than the peer itself — i.e. the peer
	// was the wicket CLI and the real caller was one level up. Recorded so the
	// audit trail names the caller instead of the CLI shim.
	ParentBinary string
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
		// Check the peer AND its parent.
		//
		// Why the parent matters: the process that opens this socket is almost
		// always the `wicket` CLI itself, so a peer-only check makes any
		// allowlist of CALLERS (claude, a shell, curl-via-CLI) unsatisfiable —
		// the daemon rejects everything and the broker serves nobody. That is
		// exactly what happened on 2026-07-25: the enforcement shipped in #1,
		// the deployed binary was old enough to ignore it, and the first real
		// deploy attempt took the broker down.
		//
		// Checking both keeps two legitimate shapes working:
		//   - a program that connects DIRECTLY (peer is that program)
		//   - a program that execs the CLI (peer is wicket, parent is the caller)
		//
		// Only one level up, deliberately. Walking further would let any
		// allowlisted ancestor launder access for an arbitrary intermediate
		// process, which is the thing an allowlist is supposed to prevent.
		if !binaryAllowed(peer.Binary, allowedBinaries) {
			parentBinary, perr := resolveParentBinary(peer.PID)
			if perr != nil {
				return nil, fmt.Errorf("peer executable %q is not in allowed_binaries and its parent could not be resolved: %w", peer.Binary, perr)
			}
			if !binaryAllowed(parentBinary, allowedBinaries) {
				return nil, fmt.Errorf("neither peer executable %q nor its parent %q is in allowed_binaries", peer.Binary, parentBinary)
			}
			// Record what actually authorized the call, so the audit log shows
			// the caller rather than the CLI shim every time.
			peer.ParentBinary = parentBinary
		}
	}

	return peer, nil
}

// resolveParentBinary returns the executable path of pid's parent process.
func resolveParentBinary(pid int32) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("peer PID unavailable")
	}
	ppid, err := resolveParentPID(pid)
	if err != nil {
		return "", err
	}
	if ppid <= 0 {
		return "", fmt.Errorf("parent PID of %d is unavailable", pid)
	}
	return resolvePeerExecutable(ppid)
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
