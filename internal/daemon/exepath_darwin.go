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
