// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package ws

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func pinGoroutineToCpu(cpuID int) error {

	// Lock goroutine to the current OS thread
	runtime.LockOSThread()

	var mask unix.CPUSet
	mask.Set(cpuID)

	pid := os.Getpid() // 0 = current thread
	if err := unix.SchedSetaffinity(pid, &mask); err != nil {
		return fmt.Errorf("failed to set affinity: %w", err)
	}

	return nil
}

// makeThreadTheNicest -
// on linux, a regular user can only increase the nice value (make the process less prioritized).
// To decrease the nice value (increase priority), root privileges or the CAP_SYS_NICE capability are required.
func makeThreadTheNicest(niceVal int) error {
	//Current process ID
	pid := os.Getpid()

	// Set the niceness for the current process
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, pid, niceVal); err != nil {
		return fmt.Errorf("error setting nice value: %w", err)
	}

	return nil
}
