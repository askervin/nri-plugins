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
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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

// SetMemoryPolicy injects set_mempolicy syscall into the given PIDs
// to prefer memory allocations from the specified NUMA nodes
func SetMemoryPolicy(pids []int, preferredNodes []int) error {
	if len(pids) == 0 {
		return fmt.Errorf("no PIDs provided")
	}
	if len(preferredNodes) == 0 {
		return fmt.Errorf("no preferred nodes provided")
	}

	// Create nodemask for the preferred nodes
	nodemask := makeNodeMask(preferredNodes)

	var lastErr error
	successCount := 0

	for _, pid := range pids {
		if err := injectSetMempolicy(pid, preferredNodes, nodemask); err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "Warning: failed to set memory policy for PID %d: %v\n", pid, err)
		} else {
			successCount++
		}
	}

	if successCount == 0 && lastErr != nil {
		return fmt.Errorf("failed to set memory policy for all PIDs: %w", lastErr)
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

// injectSetMempolicy injects set_mempolicy syscall into a running process
func injectSetMempolicy(pid int, preferredNodes []int, nodemask []uint64) error {
	LogDebug("ptrace attaching pid %d\n", pid)
	// Attach to the process using ptrace
	if err := unix.PtraceAttach(pid); err != nil {
		return fmt.Errorf("failed to attach to PID %d: %w", pid, err)
	}

	// Wait for the process to stop
	var ws unix.WaitStatus
	_, err := unix.Wait4(pid, &ws, 0, nil)
	if err != nil {
		unix.PtraceDetach(pid)
		return fmt.Errorf("failed to wait for PID %d: %w", pid, err)
	}

	// Ensure we detach on exit
	defer unix.PtraceDetach(pid)

	// Get current registers
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("failed to get registers for PID %d: %w", pid, err)
	}

	// Save original registers and instruction pointer
	origRegs := regs

	// Save original instructions at RIP
	var origCode [8]byte
	_, err = unix.PtracePeekData(pid, uintptr(regs.Rip), origCode[:])
	if err != nil {
		return fmt.Errorf("failed to read original code for PID %d: %w", pid, err)
	}

	// Prepare syscall arguments for set_mempolicy
	// syscall: set_mempolicy(mode, nodemask, maxnode)
	// Note: maxnode must be aligned to sizeof(unsigned long) boundary
	mode := MPOL_PREFERRED
	if len(preferredNodes) > 1 {
		// Use MPOL_INTERLEAVE for multiple nodes
		mode = MPOL_INTERLEAVE
	}
	// Don't use MPOL_F_STATIC_NODES for now - test without it first

	// maxnode should be a multiple of bits in unsigned long (64 bits on x86_64)
	// Round up to next multiple of 64
	maxNodeID := 0
	for _, node := range preferredNodes {
		if node > maxNodeID {
			maxNodeID = node
		}
	}
	// Round up to next multiple of 64
	maxnode := uint64(((maxNodeID / 64) + 1) * 64)

	// We need to write the nodemask to the process memory
	// Find a safe location (we'll use the stack)
	stackPtr := regs.Rsp - 256 // Use space below current stack pointer for safety

	// Align stack pointer to 8-byte boundary
	stackPtr = stackPtr & ^uint64(7)

	// Calculate how many unsigned longs we need for the nodemask
	// Round up maxnode to nearest multiple of 64, then divide by 64
	numLongs := int((maxnode + 63) / 64)
	if numLongs == 0 {
		numLongs = 1
	}

	// Only use the number of words we actually need
	nodemaskToWrite := nodemask[:numLongs]

	// Write nodemask to process memory
	for i, word := range nodemaskToWrite {
		wordBytes := (*[8]byte)(unsafe.Pointer(&word))[:]
		if _, err := unix.PtracePokeData(pid, uintptr(stackPtr)+uintptr(i*8), wordBytes); err != nil {
			return fmt.Errorf("failed to write nodemask to PID %d: %w", pid, err)
		}
	}

	// Inject syscall instruction (0x0f 0x05) followed by int3 trap (0xcc)
	// This creates: syscall; int3
	var syscallCode [8]byte
	syscallCode[0] = 0x0f // syscall instruction byte 1
	syscallCode[1] = 0x05 // syscall instruction byte 2
	syscallCode[2] = 0xcc // int3 (trap) to stop after syscall

	// Write syscall instruction at current RIP
	if _, err := unix.PtracePokeData(pid, uintptr(regs.Rip), syscallCode[:]); err != nil {
		return fmt.Errorf("failed to write syscall instruction for PID %d: %w", pid, err)
	}

	// Set up registers for set_mempolicy syscall
	// x86_64 syscall convention: syscall number in RAX, args in RDI, RSI, RDX, R10, R8, R9
	regs.Rax = 238 // __NR_set_mempolicy on x86_64
	regs.Rdi = uint64(mode)
	regs.Rsi = stackPtr
	regs.Rdx = maxnode

	// Set the modified registers
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		// Restore original code before returning
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		return fmt.Errorf("failed to set registers for PID %d: %w", pid, err)
	}

	// Continue execution - this will execute the syscall instruction
	if err := unix.PtraceCont(pid, 0); err != nil {
		// Restore original code before returning
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		return fmt.Errorf("failed to continue execution for PID %d: %w", pid, err)
	}

	// Wait for the int3 trap after syscall completes
	_, err = unix.Wait4(pid, &ws, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to wait for syscall completion for PID %d: %w", pid, err)
	}

	// Get the result registers
	var resultRegs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &resultRegs); err != nil {
		// Restore original code before returning
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		return fmt.Errorf("failed to get result registers for PID %d: %w", pid, err)
	}

	// Check return value (in RAX)
	// Syscall returns negative errno on error
	// In x86_64, kernel returns -errno as a large unsigned value
	if resultRegs.Rax > uint64(0xfffffffffffff000) { // Check for error range
		errno := syscall.Errno(uint64(0) - resultRegs.Rax) // Convert to positive errno
		// Restore state before returning error
		unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:])
		unix.PtraceSetRegs(pid, &origRegs)
		return fmt.Errorf("set_mempolicy failed for PID %d: %v", pid, errno)
	}

	// Restore original instructions
	if _, err := unix.PtracePokeData(pid, uintptr(origRegs.Rip), origCode[:]); err != nil {
		return fmt.Errorf("failed to restore original code for PID %d: %w", pid, err)
	}

	// Restore original registers
	if err := unix.PtraceSetRegs(pid, &origRegs); err != nil {
		return fmt.Errorf("failed to restore registers for PID %d: %w", pid, err)
	}

	LogDebug("ptrace restored pid %d\n", pid)
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
