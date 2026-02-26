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

// cgmemnotify package implements a watcher that listens (epoll) to
// cgroup memory.events and reports when memory usage grows above or
// below given limits. If available, it immediately updates limits to
// next levels in order to cause minimal delay in cgroup processes
// waiting for their requested memory pages.
package cgmemnotify

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Notification represents a ladder crossing notification
type Notification struct {
	LadderIndex     int    // New ladder index
	OldLadderIndex  int    // Old ladder index
	MemoryCurrentKB uint64 // Current memory usage
}

// CgroupWatcher watches a cgroup for memory usage changes
type CgroupWatcher struct {
	CgroupPath         string
	ladders            MemoryLadders
	currentLadder      int // Current ladder position (index into ladders)
	eventFd            int
	memoryEventsFd     int
	mu                 sync.RWMutex
	stopCh             chan struct{}
	notifyCh           chan Notification
	pollInterval       time.Duration
	lastHighEventCount uint64
	memoryHighBytes    uint64 // Expected memory.high limit in bytes
	memoryCurrent      uint64 // Previously recorded memory.current in bytes
}

// LogDebug prints debug messages to stderr with a consistent prefix,
// starting with epoch time (including milliseconds) for easier log
// correlation.
func LogDebug(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "%.06f DEBUG cgmemnotify: %s", float64(time.Now().UnixNano())/1e9, msg)
}

// LogError prints debug messages to stderr with a consistent prefix,
// starting with epoch time (including milliseconds) for easier log
// correlation.
func LogError(args ...interface{}) {
	msg := fmt.Sprintln(args...)
	fmt.Fprintf(os.Stderr, "%.06f ERROR cgmemnotify: %s", float64(time.Now().UnixNano())/1e6, msg)
}

// NewCgroupWatcher creates a new cgroup watcher for the given cgroup path
func NewCgroupWatcher(cgroupPath string, ml *MemoryLadders) (*CgroupWatcher, error) {
	// Validate cgroup path exists
	if _, err := os.Stat(cgroupPath); err != nil {
		return nil, fmt.Errorf("cgroup path does not exist: %w", err)
	}

	if ml == nil || len(*ml) == 0 {
		return nil, fmt.Errorf("memory ladders cannot be empty")
	}

	watcher := &CgroupWatcher{
		CgroupPath:     cgroupPath,
		ladders:        *ml,
		currentLadder:  0, // Start at the first ladder
		eventFd:        -1,
		memoryEventsFd: -1,
		stopCh:         make(chan struct{}),
		notifyCh:       make(chan Notification, 10),
		pollInterval:   100 * time.Millisecond, // Default poll interval
	}

	return watcher, nil
}

// SetConfig reconfigures the watcher with new memory ladders
func (w *CgroupWatcher) SetConfig(ml *MemoryLadders) error {
	if ml == nil || len(*ml) == 0 {
		return fmt.Errorf("memory ladders cannot be empty")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.ladders = *ml
	// Reset to first ladder
	w.currentLadder = 0

	// Update memory.high based on new configuration
	return w.setupMemoryHigh()
}

// setupMemoryHigh sets memory.high based on the current ladder's high watermark
func (w *CgroupWatcher) setupMemoryHigh() error {
	var value []byte
	memoryHighPath := filepath.Join(w.CgroupPath, "memory.high")

	// If we're on the last ladder or it has no high watermark, set to "max"
	if w.currentLadder >= len(w.ladders) || w.ladders[w.currentLadder].HighWatermarkKB == 0 {
		w.memoryHighBytes = 0 // No limit
		value = []byte("max\n")
	} else {
		// Set memory.high to current ladder's high watermark
		w.memoryHighBytes = w.ladders[w.currentLadder].HighWatermarkKB * 1024
		value = []byte(fmt.Sprintf("%d\n", w.memoryHighBytes))
	}
	if err := os.WriteFile(memoryHighPath, value, 0644); err != nil {
		LogDebug("%s: writing %q failed: %v\n", memoryHighPath, string(value), err)
		return err
	}
	LogDebug("%s: wrote %q\n", memoryHighPath, string(value))
	return nil
}

// Start begins watching the cgroup for memory changes
func (w *CgroupWatcher) Start() error {
	// Set memory.high based on current ladder
	if err := w.setupMemoryHigh(); err != nil {
		return fmt.Errorf("failed to setup memory.high: %w", err)
	}

	// Try to use memory.events for notifications (cgroup v2)
	eventsPath := filepath.Join(w.CgroupPath, "memory.events")
	if _, err := os.Stat(eventsPath); err == nil {
		if err := w.setupEventFd(); err != nil {
			// Fall back to polling if eventfd setup fails
			LogError("Warning: eventfd setup failed, falling back to polling: %v\n", err)
			go w.pollLoop()
		} else {
			go w.eventLoop()
		}
	} else {
		// Fall back to polling
		go w.pollLoop()
	}

	return nil
}

// setupEventFd sets up eventfd for efficient cgroup event notifications
// This creates two file descriptors:
//  1. eventFd: Used for signaling stop requests to the event loop
//  2. memoryEventsFd: Monitors memory.events file for kernel notifications
func (w *CgroupWatcher) setupEventFd() error {
	// Create an eventfd for internal signaling (e.g., stop requests)
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("failed to create eventfd: %w", err)
	}
	w.eventFd = efd

	// Open memory.events file which the kernel updates on memory events
	// This file is monitored via epoll for efficient event-driven notifications
	eventsPath := filepath.Join(w.CgroupPath, "memory.events")
	fd, err := unix.Open(eventsPath, unix.O_RDONLY, 0)
	if err != nil {
		unix.Close(w.eventFd)
		return fmt.Errorf("failed to open memory.events: %w", err)
	}
	w.memoryEventsFd = fd

	return nil
}

// eventLoop waits for cgroup events using eventfd and epoll
func (w *CgroupWatcher) eventLoop() {
	defer func() {
		if w.eventFd >= 0 {
			unix.Close(w.eventFd)
		}
		if w.memoryEventsFd >= 0 {
			unix.Close(w.memoryEventsFd)
		}
	}()

	// Create epoll instance
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		LogError("Failed to create epoll: %v\n", err)
		// Fall back to polling
		w.pollLoop()
		return
	}
	defer unix.Close(epfd)

	// Register memory.events file descriptor with epoll
	event := &unix.EpollEvent{
		Events: unix.EPOLLPRI,
		Fd:     int32(w.memoryEventsFd),
	}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, w.memoryEventsFd, event); err != nil {
		LogError("Failed to register memory.events with epoll: %v\n", err)
		// Fall back to polling
		w.pollLoop()
		return
	}

	// Register eventfd with epoll for stop signal
	stopEvent := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(w.eventFd),
	}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, w.eventFd, &stopEvent); err != nil {
		LogError("Failed to register eventfd with epoll: %v\n", err)
		// Continue without eventfd - will use timeout for stop check
	}

	// Start a goroutine to signal eventfd when stop is requested
	go func() {
		<-w.stopCh
		// Write to eventfd to wake up EpollWait
		buf := make([]byte, 8)
		buf[0] = 1
		unix.Write(w.eventFd, buf)
	}()

	events := make([]unix.EpollEvent, 10)

	// Do initial check
	w.checkMemoryStatus()

	for {
		// Wait for events with 1 second timeout
		// Timeout allows periodic checks even if no events occur
		n, err := unix.EpollWait(epfd, events, 1000) // 1000ms timeout

		if err != nil {
			if err == unix.EINTR {
				// Interrupted by signal, continue
				continue
			}
			LogError("EpollWait error: %v\n", err)
			time.Sleep(w.pollInterval)
			continue
		}

		// Check if stop was requested
		select {
		case <-w.stopCh:
			return
		default:
		}

		highEvents := 0
		for i := 0; i < n; i++ {
			// Events occurred - check which ones
			if events[i].Fd == int32(w.memoryEventsFd) {
				// Memory event. Must read whole file from pos 0 to the end
				// to clear the event and allow future notifications.
				_, err := unix.Seek(w.memoryEventsFd, 0, unix.SEEK_SET)
				if err != nil {
					LogError("Failed to seek memory.events: %v, stop eventloop\n", err)
					return
				}
				buf := make([]byte, 4096)
				nread, err := unix.Read(w.memoryEventsFd, buf)
				if err != nil {
					LogError("Failed to read memory.events: %v, stop eventloop\n", err)
					return
				}
				// Parse the content we just read
				content := string(buf[:nread])
				if w.checkMemoryHighFromContent(content) {
					highEvents++
				}
			} else if events[i].Fd == int32(w.eventFd) {
				// Stop signal received via eventfd
				return
			}
		}
		// There are real high events, or it is time for a periodic check (timeout)
		if highEvents > 0 || n == 0 {
			w.checkMemoryStatus()
		}
	}
}

// pollLoop continuously polls memory status
func (w *CgroupWatcher) pollLoop() {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.checkMemoryStatus()
		}
	}
}

// checkMemoryHighFromContent parses memory.events content for "high" counter
// and validates by comparing memory.current against the expected limit
func (w *CgroupWatcher) checkMemoryHighFromContent(content string) bool {
	// Parse memory.events to find "high" counter
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "high" {
			continue
		}
		highEventCount, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		newHighReached := highEventCount > w.lastHighEventCount
		if w.lastHighEventCount == 0 {
			// First time seeing the counter. Possibly
			// watching this cgroup memory.events was just
			// started. Report memory.high only if
			// memory.current is already above threshold
			newHighReached = w.checkMemoryCurrentAboveHigh()
		}
		w.lastHighEventCount = highEventCount
		return newHighReached
	}
	return false
}

// checkMemoryCurrentAboveHigh validates that memory.current has actually reached memory.high
func (w *CgroupWatcher) checkMemoryCurrentAboveHigh() bool {
	// If no limit is set.
	if w.memoryHighBytes == 0 {
		return false
	}

	// Read memory.current
	memoryCurrentPath := filepath.Join(w.CgroupPath, "memory.current")
	data, err := os.ReadFile(memoryCurrentPath)
	if err != nil {
		return false
	}

	currentBytes, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return false
	}

	// Only consider it a valid memory.high event if memory.current >= memory.high
	// Allow some tolerance (95% of limit) to account for timing
	threshold := w.memoryHighBytes * 95 / 100
	return currentBytes >= threshold
}

// checkMemoryStatus reads current memory usage and checks for ladder crossings
func (w *CgroupWatcher) checkMemoryStatus() {
	if len(w.ladders) == 0 {
		// No ladders, nothing to report.
		return
	}
	// Read memory.current
	memoryCurrentPath := filepath.Join(w.CgroupPath, "memory.current")
	data, err := os.ReadFile(memoryCurrentPath)
	if err != nil {
		return
	}

	currentBytes, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return
	}
	currentKB := currentBytes / 1024

	w.mu.Lock()
	defer w.mu.Unlock()

	oldLadder := w.currentLadder

	// Find the correct ladder for current memory usage
	// Start from the lowest ladder and find the first one where:
	// 1. currentKB is above the LowWatermarkKB
	// 2. currentKB has not exceeded the HighWatermarkKB (or it's the last ladder with no limit)
	newLadder := 0
	for i := 0; i < len(w.ladders); i++ {
		meetsLow := currentKB >= w.ladders[i].LowWatermarkKB
		belowHigh := (w.ladders[i].HighWatermarkKB == 0 || currentKB < w.ladders[i].HighWatermarkKB)

		if meetsLow && belowHigh {
			newLadder = i
			break
		}

		// Special case: if we're on the last ladder and exceeded its limit, stay on it
		if i == len(w.ladders)-1 {
			newLadder = i
			break
		}
	}

	// If ladder changed, update and notify
	if newLadder != oldLadder {
		LogDebug("ladder change from %d to %d memory.current from %d to %d\n", w.currentLadder, newLadder, w.memoryCurrent, currentBytes)
		w.currentLadder = newLadder
		w.setupMemoryHigh() // Update memory.high for new ladder
		w.sendNotification(newLadder, oldLadder, currentKB)
	}
	w.memoryCurrent = currentBytes
}

// sendNotification sends a ladder crossing notification
func (w *CgroupWatcher) sendNotification(ladderIndex int, oldLadder int, currentKB uint64) {
	notification := Notification{
		LadderIndex:     ladderIndex,
		OldLadderIndex:  oldLadder,
		MemoryCurrentKB: currentKB,
	}

	select {
	case w.notifyCh <- notification:
	default:
		// Channel full, skip this notification
	}
}

// GetCurrentLadder returns the current ladder index
func (w *CgroupWatcher) GetCurrentLadder() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.currentLadder
}

// Notifications returns a channel for receiving ladder crossing notifications
func (w *CgroupWatcher) Notifications() <-chan Notification {
	return w.notifyCh
}

// Stop stops the watcher
func (w *CgroupWatcher) Stop() {
	close(w.stopCh)
}

// RemoveMemoryHigh sets memory.high to "max", removing the throttling limit
func (w *CgroupWatcher) RemoveMemoryHigh() error {
	memoryHighPath := filepath.Join(w.CgroupPath, "memory.high")
	w.mu.Lock()
	w.memoryHighBytes = 0
	w.mu.Unlock()
	return os.WriteFile(memoryHighPath, []byte("max\n"), 0644)
}

// GetPIDs returns all PIDs in the cgroup
func GetPIDs(cgroupPath string) ([]int, error) {
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	data, err := os.ReadFile(procsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cgroup.procs: %w", err)
	}

	var pids []int
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}

	return pids, scanner.Err()
}

// SetMemoryPressure configures memory pressure notifications (optional advanced feature)
func (w *CgroupWatcher) SetMemoryPressure(threshold uint64) error {
	// This could use memory.pressure or PSI (Pressure Stall Information)
	// For now, we rely on polling/events
	pressurePath := filepath.Join(w.CgroupPath, "memory.pressure")
	if _, err := os.Stat(pressurePath); err != nil {
		return fmt.Errorf("memory.pressure not available: %w", err)
	}

	// Configure pressure threshold using eventfd
	// This is a placeholder for actual PSI configuration
	_ = threshold
	return nil
}

// Helper function to get cgroup path for a PID
func GetCgroupPath(pid int) (string, error) {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", fmt.Errorf("failed to read cgroup file: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: hierarchy-ID:controller-list:cgroup-path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			// For cgroup v2, hierarchy-ID is 0 and controller-list is empty
			if parts[0] == "0" && parts[1] == "" {
				return filepath.Join("/sys/fs/cgroup", parts[2]), nil
			}
		}
	}

	return "", fmt.Errorf("cgroup v2 not found for PID %d", pid)
}

// LinuxMemoryCategory represents a memory category from memory.numa_stat as a bit flag
type LinuxMemoryCategory uint64

const (
	LmcAnon LinuxMemoryCategory = 1 << iota
	LmcFile
	LmcKernel_stack
	LmcPagetables
	LmcSec_pagetables
	LmcShmem
	LmcFile_mapped
	LmcFile_dirty
	LmcFile_writeback
	LmcSwapcached
	LmcAnon_thp
	LmcFile_thp
	LmcShmem_thp
	LmcInactive_anon
	LmcActive_anon
	LmcInactive_file
	LmcActive_file
	LmcUnevictable
	LmcSlab_reclaimable
	LmcSlab_unreclaimable
	LmcSlab
	LmcWorkingset_refault_anon
	LmcWorkingset_refault_file
	LmcWorkingset_activate_anon
	LmcWorkingset_activate_file
	LmcWorkingset_restore_anon
	LmcWorkingset_restore_file
	LmcWorkingset_nodereclaim
)

var lmcNames = map[LinuxMemoryCategory]string{
	LmcAnon:                     "anon",
	LmcFile:                     "file",
	LmcKernel_stack:             "kernel_stack",
	LmcPagetables:               "pagetables",
	LmcSec_pagetables:           "sec_pagetables",
	LmcShmem:                    "shmem",
	LmcFile_mapped:              "file_mapped",
	LmcFile_dirty:               "file_dirty",
	LmcFile_writeback:           "file_writeback",
	LmcSwapcached:               "swapcached",
	LmcAnon_thp:                 "anon_thp",
	LmcFile_thp:                 "file_thp",
	LmcShmem_thp:                "shmem_thp",
	LmcInactive_anon:            "inactive_anon",
	LmcActive_anon:              "active_anon",
	LmcInactive_file:            "inactive_file",
	LmcActive_file:              "active_file",
	LmcUnevictable:              "unevictable",
	LmcSlab_reclaimable:         "slab_reclaimable",
	LmcSlab_unreclaimable:       "slab_unreclaimable",
	LmcSlab:                     "slab",
	LmcWorkingset_refault_anon:  "workingset_refault_anon",
	LmcWorkingset_refault_file:  "workingset_refault_file",
	LmcWorkingset_activate_anon: "workingset_activate_anon",
	LmcWorkingset_activate_file: "workingset_activate_file",
	LmcWorkingset_restore_anon:  "workingset_restore_anon",
	LmcWorkingset_restore_file:  "workingset_restore_file",
	LmcWorkingset_nodereclaim:   "workingset_nodereclaim",
}

// NumaStat returns per-NUMA node memory usage in bytes for the cgroup.
// It reads allowed nodes from cpuset.mems.effective and memory usage from memory.numa_stat.
// The categories parameter is a bitmask of LinuxMemoryCategory flags to count.
// If categories is 0, returns nil, nil (no categories requested).
// Returns a map where keys are NUMA node IDs and values are memory usage in bytes.
func (w *CgroupWatcher) NumaStat(categories LinuxMemoryCategory) (map[int]uint64, error) {
	// If no categories specified, return nil
	if categories == 0 {
		return nil, nil
	}

	// Build set of category names to look for
	categoryNames := make(map[string]bool)
	for cat, name := range lmcNames {
		if categories&cat != 0 {
			categoryNames[name] = true
		}
	}

	// Read memory.numa_stat
	numaStatPath := filepath.Join(w.CgroupPath, "memory.numa_stat")
	file, err := os.Open(numaStatPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open memory.numa_stat: %w", err)
	}
	defer file.Close()

	// Parse memory.numa_stat
	// Format: <category> N<node>=<bytes> N<node>=<bytes> ...
	result := make(map[int]uint64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		category := parts[0]
		if !categoryNames[category] {
			continue
		}

		// Parse node values: N0=1234 N1=5678 ...
		for _, part := range parts[1:] {
			if !strings.HasPrefix(part, "N") {
				continue
			}

			nodeValue := strings.SplitN(part[1:], "=", 2)
			if len(nodeValue) != 2 {
				continue
			}

			nodeID, err := strconv.Atoi(nodeValue[0])
			if err != nil {
				continue
			}

			bytes, err := strconv.ParseUint(nodeValue[1], 10, 64)
			if err != nil {
				continue
			}

			result[nodeID] += bytes
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading memory.numa_stat: %w", err)
	}

	return result, nil
}

// parseCpusetList parses a cpuset list format (e.g., "0-2,5,7-9") into a slice of integers
func parseCpusetList(s string) []int {
	var result []int
	if s == "" {
		return result
	}

	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range: "0-2"
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
		} else {
			// Single value
			val, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			result = append(result, val)
		}
	}

	return result
}

// Utility: Check if running with sufficient privileges
func CheckPrivileges() error {
	if syscall.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	return nil
}
