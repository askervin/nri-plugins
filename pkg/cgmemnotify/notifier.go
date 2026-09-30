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

// Package cgmemnotify reports when the memory usage of a cgroup v2
// leaves configured bounds. The upper bound is enforced by writing
// it to memory.high, so the kernel throttles the cgroup at the bound
// and increments the "high" counter in memory.events. The lower
// bound is checked against memory.current on every wakeup.
//
// The package has no goroutines. A Notifier is driven by one
// goroutine that calls SetBounds, Wait and Close. Interrupt wakes a
// blocked Wait and may be called from any goroutine.
package cgmemnotify

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Bounds are memory.current thresholds in bytes.
type Bounds struct {
	// Lower is the usage below which LowerCrossed is reported. Zero
	// disables the lower bound.
	Lower int64
	// Upper is written to memory.high. UpperCrossed is reported when
	// the kernel has throttled the cgroup at this limit. Zero removes
	// the limit.
	Upper int64
}

// Crossing tells which bound an Event reports.
type Crossing int

const (
	// NoCrossing is returned when Wait timed out.
	NoCrossing Crossing = iota
	// LowerCrossed means memory.current is below Bounds.Lower.
	LowerCrossed
	// UpperCrossed means the kernel has throttled the cgroup at
	// Bounds.Upper since the last SetBounds.
	UpperCrossed
)

// String returns the name of the crossing.
func (c Crossing) String() string {
	switch c {
	case NoCrossing:
		return "none"
	case LowerCrossed:
		return "lower"
	case UpperCrossed:
		return "upper"
	}
	return "Crossing(" + strconv.Itoa(int(c)) + ")"
}

// Event is the result of a Wait that was not interrupted.
type Event struct {
	Crossing      Crossing
	MemoryCurrent int64
}

// ErrInterrupted is returned by Wait when Interrupt was called.
var ErrInterrupted = errors.New("wait interrupted")

// Notifier watches the memory usage of one cgroup.
type Notifier struct {
	cgroupPath string
	eventsFd   int
	wakeFd     int
	bounds     Bounds
	highCount  int64
}

// New returns a Notifier for the cgroup with no bounds set. The
// cgroup must be a cgroup v2 directory with the memory controller
// enabled.
func New(cgroupPath string) (*Notifier, error) {
	if _, err := os.Stat(filepath.Join(cgroupPath, "memory.high")); err != nil {
		return nil, fmt.Errorf("cgroup v2 memory controller not available: %w", err)
	}
	eventsFd, err := unix.Open(filepath.Join(cgroupPath, "memory.events"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open memory.events: %w", err)
	}
	wakeFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(eventsFd)
		return nil, fmt.Errorf("create eventfd: %w", err)
	}
	n := &Notifier{
		cgroupPath: cgroupPath,
		eventsFd:   eventsFd,
		wakeFd:     wakeFd,
	}
	if n.highCount, err = n.readHighCount(); err != nil {
		_ = n.Close()
		return nil, err
	}
	return n, nil
}

// SetBounds writes Upper to memory.high and arms both bounds.
func (n *Notifier) SetBounds(b Bounds) error {
	value := "max\n"
	if b.Upper > 0 {
		value = strconv.FormatInt(b.Upper, 10) + "\n"
	}
	if err := os.WriteFile(filepath.Join(n.cgroupPath, "memory.high"), []byte(value), 0644); err != nil {
		return fmt.Errorf("write memory.high: %w", err)
	}
	highCount, err := n.readHighCount()
	if err != nil {
		return err
	}
	n.highCount = highCount
	n.bounds = b
	return nil
}

// Wait returns the next event: a bound crossing, or NoCrossing when
// timeout expires first. A negative timeout waits without a limit.
// Wait returns ErrInterrupted when Interrupt was called. A crossing is
// reported by every Wait until SetBounds is called.
func (n *Notifier) Wait(timeout time.Duration) (Event, error) {
	timeoutMs := -1
	if timeout >= 0 {
		timeoutMs = int(timeout / time.Millisecond)
	}
	fds := []unix.PollFd{
		{Fd: int32(n.eventsFd), Events: unix.POLLPRI},
		{Fd: int32(n.wakeFd), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(fds, timeoutMs)
		if err == nil {
			break
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return Event{}, fmt.Errorf("poll: %w", err)
	}
	if fds[1].Revents != 0 {
		var buf [8]byte
		_, _ = unix.Read(n.wakeFd, buf[:])
		return Event{}, ErrInterrupted
	}

	// Reading memory.events also clears its pending change, so poll
	// reports only changes after this read.
	highCount, err := n.readHighCount()
	if err != nil {
		return Event{}, err
	}
	current, err := MemoryCurrent(n.cgroupPath)
	if err != nil {
		return Event{}, err
	}
	event := Event{MemoryCurrent: current}
	switch {
	case highCount > n.highCount:
		event.Crossing = UpperCrossed
	case n.bounds.Lower > 0 && current < n.bounds.Lower:
		event.Crossing = LowerCrossed
	}
	return event, nil
}

// Interrupt wakes up a blocked Wait.
func (n *Notifier) Interrupt() error {
	var buf [8]byte
	binary.NativeEndian.PutUint64(buf[:], 1)
	if _, err := unix.Write(n.wakeFd, buf[:]); err != nil {
		return fmt.Errorf("write eventfd: %w", err)
	}
	return nil
}

// Close releases the file descriptors of the notifier. memory.high
// is left as it is.
func (n *Notifier) Close() error {
	var errs []error
	if n.eventsFd >= 0 {
		errs = append(errs, unix.Close(n.eventsFd))
		n.eventsFd = -1
	}
	if n.wakeFd >= 0 {
		errs = append(errs, unix.Close(n.wakeFd))
		n.wakeFd = -1
	}
	return errors.Join(errs...)
}

// readHighCount returns the "high" counter of memory.events.
func (n *Notifier) readHighCount() (int64, error) {
	if _, err := unix.Seek(n.eventsFd, 0, unix.SEEK_SET); err != nil {
		return 0, fmt.Errorf("seek memory.events: %w", err)
	}
	buf := make([]byte, 4096)
	nread, err := unix.Read(n.eventsFd, buf)
	if err != nil {
		return 0, fmt.Errorf("read memory.events: %w", err)
	}
	events, err := parseMemoryEvents(bytes.NewReader(buf[:nread]))
	if err != nil {
		return 0, fmt.Errorf("memory.events: %w", err)
	}
	highCount, ok := events["high"]
	if !ok {
		return 0, errors.New("memory.events has no high counter")
	}
	return highCount, nil
}
