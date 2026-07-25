//go:build darwin && cgo

package daemon

/*
#include <libproc.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// resolvePeerExecutable returns the absolute path to the executable of the
// process identified by pid, using libproc's proc_pidpath(2).
func resolvePeerExecutable(pid int32) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath(%d) failed", pid)
	}
	return string(buf[:n]), nil
}

// resolveParentPID returns the parent PID of the process identified by pid,
// using libproc's proc_pidinfo(2) with PROC_PIDTBSDINFO.
//
// Needed because the process that opens wicket's socket is always the `wicket`
// CLI itself. The meaningful identity for an allowlist decision is what INVOKED
// the CLI, so the allowlist check has to be able to look one level up.
func resolveParentPID(pid int32) (int32, error) {
	var info C.struct_proc_bsdinfo
	n := C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0, unsafe.Pointer(&info), C.int(C.sizeof_struct_proc_bsdinfo))
	if n <= 0 {
		return 0, fmt.Errorf("proc_pidinfo(%d, PROC_PIDTBSDINFO) failed", pid)
	}
	return int32(info.pbi_ppid), nil
}
