// Package daemon implements the wicket Unix socket server, connection
// handling, peer authentication, and daemon state management.
package daemon

import "net"

// PeerInfo contains the authenticated identity of a connecting process.
type PeerInfo struct {
	UID uint32
	GID uint32
	PID int32
}

// AuthenticatePeer extracts and verifies the identity of the connecting
// process using kernel-provided credentials. On Linux this uses SO_PEERCRED;
// on macOS it uses LOCAL_PEERCRED + LOCAL_PEERPID.
// Returns an error if the connecting UID does not match the daemon's UID.
func AuthenticatePeer(conn net.Conn) (*PeerInfo, error) {
	return authenticatePeerOS(conn)
}
