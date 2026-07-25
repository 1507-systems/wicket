//go:build !linux && !(darwin && cgo)

package daemon

import "fmt"

// resolvePeerExecutable is unsupported on this platform/build configuration.
// Callers treat a non-nil error as "could not identify the peer binary",
// which fails closed when an allowed_binaries allowlist is configured.
func resolvePeerExecutable(pid int32) (string, error) {
	return "", fmt.Errorf("peer executable resolution unsupported on this platform")
}

// resolveParentPID is unsupported on this platform.
func resolveParentPID(pid int32) (int32, error) {
	return 0, fmt.Errorf("parent PID resolution unsupported on this platform")
}
