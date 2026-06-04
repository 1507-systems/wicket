//go:build linux

package daemon

import (
	"fmt"
	"os"
)

// resolvePeerExecutable returns the absolute path to the executable of the
// process identified by pid by reading /proc/<pid>/exe.
func resolvePeerExecutable(pid int32) (string, error) {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", fmt.Errorf("readlink /proc/%d/exe: %w", pid, err)
	}
	return exe, nil
}
