// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// mpolinject package provides functions to enforce a Linux memory
// policy in any process in the system, assuming that it can be ptraced.
package mpolinject

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// maxWorkers is the maximum number of concurrent goroutines
	// (each pinned to an OS thread) used for ptrace-based syscall
	// injection. Ptrace workers are mostly blocked in wait4, not
	// CPU-bound, so this does not need to track NumCPU.
	maxWorkers = 8
)

const (
	// MPOL_PREFERRED means allocate memory from preferred node
	MPOL_PREFERRED = 1
	// MPOL_BIND means allocate memory only from specified nodes
	MPOL_BIND = 2
	// MPOL_INTERLEAVE means interleave allocations across nodes
	MPOL_INTERLEAVE = 3
	// MPOL_LOCAL means prefer local node
	MPOL_LOCAL = 4

	// MPOL_F_STATIC_NODES flag
	MPOL_F_STATIC_NODES = 1 << 15
	// MPOL_F_RELATIVE_NODES flag
	MPOL_F_RELATIVE_NODES = 1 << 14
)

// LogDebug prints debug messages to stderr with a consistent prefix,
// starting with epoch time (including milliseconds) for easier log
// correlation.
func LogDebug(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "%.06f DEBUG mpolinject: %s", float64(time.Now().UnixNano())/1e9, msg)
}

// SetMemoryPolicySingleThreadAttach injects set_mempolicy into the
// given PIDs serially using PTRACE_ATTACH. Kept as a benchmark
// reference for comparing against the PTRACE_SEIZE-based variants.
func SetMemoryPolicySingleThreadAttach(pids []int, preferredNodes []int) error {
	if len(pids) == 0 {
		return fmt.Errorf("no PIDs provided")
	}
	if len(preferredNodes) == 0 {
		return fmt.Errorf("no preferred nodes provided")
	}

	mask := makeNodeMask(preferredNodes)
	for _, pid := range pids {
		if err := injectSetMempolicyAttach(pid, preferredNodes, mask); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to set memory policy for PID %d: %v\n", pid, err)
		}
	}
	return nil
}

// SetMemoryPolicySingleThread injects set_mempolicy into the given
// PIDs serially using PTRACE_SEIZE + PTRACE_INTERRUPT.
func SetMemoryPolicySingleThread(pids []int, preferredNodes []int) error {
	if len(pids) == 0 {
		return fmt.Errorf("no PIDs provided")
	}
	if len(preferredNodes) == 0 {
		return fmt.Errorf("no preferred nodes provided")
	}

	mask := makeNodeMask(preferredNodes)
	for _, pid := range pids {
		if err := injectSetMempolicySeize(pid, preferredNodes, mask); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to set memory policy for PID %d: %v\n", pid, err)
		}
	}
	return nil
}

// SetMemoryPolicy injects set_mempolicy syscall into the given PIDs
// to prefer memory allocations from the specified NUMA nodes.
// PIDs are processed in parallel using a bounded worker pool.
func SetMemoryPolicy(pids []int, preferredNodes []int) error {
	if len(pids) == 0 {
		return fmt.Errorf("no PIDs provided")
	}
	if len(preferredNodes) == 0 {
		return fmt.Errorf("no preferred nodes provided")
	}

	// Create nodemask once — shared read-only across workers.
	nodemask := makeNodeMask(preferredNodes)

	type result struct {
		pid int
		err error
	}

	pidCh := make(chan int, len(pids))
	for _, pid := range pids {
		pidCh <- pid
	}
	close(pidCh)

	resultCh := make(chan result, len(pids))
	numWorkers := min(len(pids), maxWorkers)

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Ptrace state is per-OS-thread: attach, wait,
			// peek/poke, cont, and detach must all happen on
			// the same OS thread.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			for pid := range pidCh {
				err := injectSetMempolicySeize(pid, preferredNodes, nodemask)
				resultCh <- result{pid, err}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var lastErr error
	failCount := 0
	for r := range resultCh {
		if r.err != nil {
			lastErr = r.err
			fmt.Fprintf(os.Stderr, "Warning: failed to set memory policy for PID %d: %v\n", r.pid, r.err)
			failCount++
		}
	}

	if lastErr != nil {
		return fmt.Errorf("failed to set memory policy for %d out of %d PIDs, last error: %w", failCount, len(pids), lastErr)
	}

	return nil
}

// makeNodeMask creates a bitmask for the given NUMA nodes
func makeNodeMask(nodes []int) []uint64 {
	// Support up to 1024 nodes (16 * 64 bits)
	mask := make([]uint64, 16)

	for _, node := range nodes {
		if node < 0 || node >= 1024 {
			continue
		}
		wordIdx := node / 64
		bitIdx := node % 64
		mask[wordIdx] |= 1 << bitIdx
	}

	return mask
}

// injectSetMempolicyAttach injects set_mempolicy syscall into a
// running process using PTRACE_ATTACH. Kept as a benchmark reference.
func injectSetMempolicyAttach(pid int, preferredNodes []int, nodemask []uint64) error {
	LogDebug("ptrace attaching pid %d\n", pid)
	if err := unix.PtraceAttach(pid); err != nil {
		return fmt.Errorf("failed to attach to PID %d: %w", pid, err)
	}

	var ws unix.WaitStatus
	_, err := unix.Wait4(pid, &ws, 0, nil)
	if err != nil {
		unix.PtraceDetach(pid)
		return fmt.Errorf("failed to wait for PID %d: %w", pid, err)
	}

	defer unix.PtraceDetach(pid)

	return doSyscallInjection(pid, preferredNodes, nodemask)
}

// injectSetMempolicySeize injects set_mempolicy syscall into a running
// process using PTRACE_SEIZE + PTRACE_INTERRUPT. Unlike the
// PTRACE_ATTACH variant, PTRACE_SEIZE does not send SIGSTOP: it
// attaches instantly and then uses a kernel-level interrupt to stop
// the tracee, which avoids signal-delivery delays when the target is
// throttled by memory.high.
func injectSetMempolicySeize(pid int, preferredNodes []int, nodemask []uint64) error {
	LogDebug("ptrace seizing pid %d\n", pid)
	if err := unix.PtraceSeize(pid); err != nil {
		return fmt.Errorf("failed to seize PID %d: %w", pid, err)
	}

	// Interrupt the tracee to bring it into ptrace-stop.
	if err := unix.PtraceInterrupt(pid); err != nil {
		unix.PtraceDetach(pid)
		return fmt.Errorf("failed to interrupt PID %d: %w", pid, err)
	}

	// Wait for PTRACE_EVENT_STOP.
	var ws unix.WaitStatus
	_, err := unix.Wait4(pid, &ws, 0, nil)
	if err != nil {
		unix.PtraceDetach(pid)
		return fmt.Errorf("failed to wait for PID %d: %w", pid, err)
	}
	if !ws.Stopped() || ws.StopSignal() != unix.SIGTRAP || ws>>16 != unix.PTRACE_EVENT_STOP {
		unix.PtraceDetach(pid)
		return fmt.Errorf("unexpected wait status for PID %d after interrupt: 0x%x", pid, uint32(ws))
	}

	// Ensure we detach on exit.
	defer unix.PtraceDetach(pid)

	// From here on the injection is identical to the attach variant:
	// save state, write nodemask + syscall, execute, check result, restore.
	return doSyscallInjection(pid, preferredNodes, nodemask)
}

// doSyscallInjection performs the syscall injection on an already
// ptrace-stopped process. It saves registers and code at RIP, writes
// a set_mempolicy syscall, executes it, checks the result, and
// restores the original state.
func doSyscallInjection(pid int, preferredNodes []int, nodemask []uint64) error {
	// Get current registers.
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("failed to get registers for PID %d: %w", pid, err)
	}

	origRegs := regs

	// Save original instructions at RIP.
	var origCode [8]byte
	if _, err := unix.PtracePeekData(pid, uintptr(regs.Rip), origCode[:]); err != nil {
		return fmt.Errorf("failed to read original code for PID %d: %w", pid, err)
	}

	// Determine set_mempolicy mode.
	mode := MPOL_PREFERRED
	if len(preferredNodes) > 1 {
		mode = MPOL_INTERLEAVE
	}

	// Compute maxnode (rounded up to a multiple of 64).
	maxNodeID := 0
	for _, node := range preferredNodes {
		if node > maxNodeID {
			maxNodeID = node
		}
	}
	maxnode := uint64(((maxNodeID / 64) + 1) * 64)

	// Write the nodemask onto the tracee's stack.
	stackPtr := (regs.Rsp - 256) & ^uint64(7)
	numLongs := int((maxnode + 63) / 64)
	if numLongs == 0 {
		numLongs = 1
	}
	for i, word := range nodemask[:numLongs] {
		wordBytes := (*[8]byte)(unsafe.Pointer(&word))[:]
		if _, err := unix.PtracePokeData(pid, uintptr(stackPtr)+uintptr(i*8), wordBytes); err != nil {
			return fmt.Errorf("failed to write nodemask to PID %d: %w", pid, err)
		}
	}

	// Inject syscall instruction (0x0f 0x05) followed by int3 (0xcc).
	var syscallCode [8]byte
	syscallCode[0] = 0x0f
	syscallCode[1] = 0x05
	syscallCode[2] = 0xcc
	if _, err := unix.PtracePokeData(pid, uintptr(regs.Rip), syscallCode[:]); err != nil {
		return fmt.Errorf("failed to write syscall instruction for PID %d: %w", pid, err)
	}

	// Set up registers for set_mempolicy(mode, nodemask, maxnode).
	regs.Rax = 238 // __NR_set_mempolicy on x86_64
	regs.Rdi = uint64(mode)
	regs.Rsi = stackPtr
	regs.Rdx = maxnode

	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		return fmt.Errorf("failed to set registers for PID %d: %w", pid, err)
	}

	// Execute the injected syscall.
	if err := unix.PtraceCont(pid, 0); err != nil {
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		return fmt.Errorf("failed to continue execution for PID %d: %w", pid, err)
	}

	// Wait for the int3 trap.
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("failed to wait for syscall completion for PID %d: %w", pid, err)
	}

	// Check syscall return value.
	var resultRegs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &resultRegs); err != nil {
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		return fmt.Errorf("failed to get result registers for PID %d: %w", pid, err)
	}
	if resultRegs.Rax > uint64(0xfffffffffffff000) {
		errno := syscall.Errno(uint64(0) - resultRegs.Rax)
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		unix.PtraceSetRegs(pid, &origRegs)
		return fmt.Errorf("set_mempolicy failed for PID %d: %v", pid, errno)
	}

	// Restore original instructions and registers.
	if _, err := unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:]); err != nil {
		return fmt.Errorf("failed to restore original code for PID %d: %w", pid, err)
	}
	if err := unix.PtraceSetRegs(pid, &origRegs); err != nil {
		return fmt.Errorf("failed to restore registers for PID %d: %w", pid, err)
	}

	LogDebug("ptrace injection restored pid %d\n", pid)
	return nil
}

// GetCurrentMemoryPolicy retrieves the current memory policy of a process
func GetCurrentMemoryPolicy(pid int) (int, []int, error) {
	// This would require reading /proc/<pid>/numa_maps or using process_vm_readv
	// For now, we'll return a simple implementation

	numaPath := fmt.Sprintf("/proc/%d/numa_maps", pid)
	if _, err := os.Stat(numaPath); err != nil {
		return 0, nil, fmt.Errorf("cannot access numa_maps for PID %d: %w", pid, err)
	}

	// Parse numa_maps to determine current policy
	// This is a simplified implementation
	return MPOL_LOCAL, nil, nil
}

// ValidateNumaNodes checks if the specified NUMA nodes exist on the system
func ValidateNumaNodes(nodes []int) error {
	// Read available NUMA nodes from /sys/devices/system/node/
	nodeDir := "/sys/devices/system/node"
	entries, err := os.ReadDir(nodeDir)
	if err != nil {
		return fmt.Errorf("failed to read NUMA node directory: %w", err)
	}

	availableNodes := make(map[int]bool)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) > 4 && name[:4] == "node" {
			var nodeID int
			if _, err := fmt.Sscanf(name, "node%d", &nodeID); err == nil {
				availableNodes[nodeID] = true
			}
		}
	}

	for _, node := range nodes {
		if !availableNodes[node] {
			return fmt.Errorf("NUMA node %d does not exist on this system", node)
		}
	}

	return nil
}
