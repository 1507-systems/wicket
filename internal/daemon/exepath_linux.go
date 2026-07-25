//go:build linux

package daemon

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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

// resolveParentPID returns the parent PID of pid by reading the PPid field of
// /proc/<pid>/status. See the darwin implementation for why the parent matters.
func resolveParentPID(pid int32) (int32, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, fmt.Errorf("open /proc/%d/status: %w", pid, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
		ppid, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse PPid %q: %w", v, err)
		}
		return int32(ppid), nil
	}
	return 0, fmt.Errorf("PPid not found in /proc/%d/status", pid)
}
