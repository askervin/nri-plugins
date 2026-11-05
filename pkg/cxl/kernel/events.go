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

package kernel

import (
	"bufio"
	"encoding/json"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containers/nri-plugins/pkg/udev"
)

// Changes is a broadcast of changes: every Changed channel taken before a
// Notify is closed by it. The zero value is ready to use; it takes no lock.
type Changes struct {
	ch atomic.Pointer[chan struct{}]
}

// Changed returns a channel that is closed at the next Notify.
func (c *Changes) Changed() <-chan struct{} {
	for {
		if p := c.ch.Load(); p != nil {
			return *p
		}
		ch := make(chan struct{})
		if c.ch.CompareAndSwap(nil, &ch) {
			return ch
		}
	}
}

// Notify closes the channels of Changed taken before it.
func (c *Changes) Notify() {
	ch := make(chan struct{})
	if old := c.ch.Swap(&ch); old != nil {
		close(*old)
	}
}

// UdevEvents watches the uevents of the kernel objects of this package:
// NUMA nodes (add, remove), memory blocks, CXL devices, dax devices and nd
// devices. Every event wakes the waits of the Kernels that have it as their
// Events. The events of the NUMA nodes, memory blocks and CXL devices, and
// every fake event of the FIFO, also feed a debounced notification
// (Stable): one signal after the events of a hotplug sequence (CXL device
// bind -> region creation -> memory onlining -> NUMA node appearance) have
// been quiet for the stable duration.
type UdevEvents struct {
	monitor        *udev.Monitor
	stableDuration time.Duration
	rawEvents      chan *udev.Event
	fakeEvents     chan *udev.Event
	stable         chan struct{}
	stopCh         chan struct{}
	changes        Changes
	// Logf logs the start of the watch and its problems (nil: nothing).
	Logf func(format string, args ...any)
}

var _ Events = &UdevEvents{}

// stableSubsystems are the subsystems whose events feed Stable.
var stableSubsystems = map[string]bool{"node": true, "memory": true, "cxl": true}

// NewUdevEvents returns a watcher of the uevents of the kernel objects,
// whose Stable signals after stableDuration of quiet (0: at every event).
func NewUdevEvents(stableDuration time.Duration) (*UdevEvents, error) {
	m, err := udev.NewMonitor(
		udev.WithFilters(
			map[string]string{udev.PropertySubsystem: "node", udev.PropertyAction: "add"},
			map[string]string{udev.PropertySubsystem: "node", udev.PropertyAction: "remove"},
			map[string]string{udev.PropertySubsystem: "memory"},
			map[string]string{udev.PropertySubsystem: "cxl"},
			map[string]string{udev.PropertySubsystem: "dax"},
			map[string]string{udev.PropertySubsystem: "nd"},
		),
	)
	if err != nil {
		return nil, err
	}
	return &UdevEvents{
		monitor:        m,
		stableDuration: stableDuration,
		rawEvents:      make(chan *udev.Event, 64),
		fakeEvents:     make(chan *udev.Event, 64),
		stable:         make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
	}, nil
}

func (w *UdevEvents) logf(format string, args ...any) {
	if w.Logf != nil {
		w.Logf(format, args...)
	}
}

// Start starts the watch. With a fifoPath it also reads JSON-encoded fake
// events from that named pipe (created if it does not exist), one object of
// event properties per line.
func (w *UdevEvents) Start(fifoPath string) error {
	w.monitor.Start(w.rawEvents)
	go w.dispatch()
	if fifoPath != "" {
		if err := ensureFifo(fifoPath); err != nil {
			return err
		}
		go w.fifoReader(fifoPath)
		w.logf("udev events: reading fake events from FIFO %s", fifoPath)
	}
	w.logf("udev events: started (stableDuration=%v)", w.stableDuration)
	return nil
}

// Stop stops the watch.
func (w *UdevEvents) Stop() {
	close(w.stopCh)
	w.monitor.Stop() //nolint:errcheck
}

// Changed returns a channel that is closed at the next event.
func (w *UdevEvents) Changed() <-chan struct{} {
	return w.changes.Changed()
}

// Stable returns a channel that receives a signal each time the events of
// NUMA nodes, memory blocks and CXL devices have been quiet for the stable
// duration.
func (w *UdevEvents) Stable() <-chan struct{} {
	return w.stable
}

// signalStable sends the stable signal unless one is pending.
func (w *UdevEvents) signalStable() {
	select {
	case w.stable <- struct{}{}:
	default:
	}
}

// dispatch wakes the waits at every event and debounces the stable signal.
func (w *UdevEvents) dispatch() {
	var timer *time.Timer
	var timerCh <-chan time.Time
	debounce := func() {
		if w.stableDuration == 0 {
			w.signalStable()
			return
		}
		if timer == nil {
			timer = time.NewTimer(w.stableDuration)
			timerCh = timer.C
		} else {
			timer.Reset(w.stableDuration)
		}
	}
	for {
		select {
		case evt, ok := <-w.rawEvents:
			if !ok {
				if timer != nil {
					timer.Stop()
				}
				return
			}
			w.changes.Notify()
			if stableSubsystems[evt.Subsystem] {
				debounce()
			}
		case <-w.fakeEvents:
			w.changes.Notify()
			debounce()
		case <-timerCh:
			w.signalStable()
			timer = nil
			timerCh = nil
		case <-w.stopCh:
			if timer != nil {
				timer.Stop()
			}
			return
		}
	}
}

// fifoReader reads JSON-encoded udev events from a named pipe, one JSON
// object per line, opening it again after each writer.
func (w *UdevEvents) fifoReader(fifoPath string) {
	for {
		select {
		case <-w.stopCh:
			return
		default:
		}
		// the open blocks until a writer opens the other end
		f, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
		if err != nil {
			select {
			case <-w.stopCh:
				return
			default:
			}
			w.logf("udev events: failed to open FIFO %s: %v", fifoPath, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			select {
			case <-w.stopCh:
				_ = f.Close()
				return
			default:
			}
			line := scanner.Text()
			if line == "" {
				continue
			}
			evt, err := parseFifoEvent(line)
			if err != nil {
				w.logf("udev events: ignoring malformed FIFO event: %v", err)
				continue
			}
			select {
			case w.fakeEvents <- evt:
			case <-w.stopCh:
				_ = f.Close()
				return
			}
		}
		_ = f.Close()
	}
}

// parseFifoEvent returns the udev event of a JSON line of its properties.
func parseFifoEvent(line string) (*udev.Event, error) {
	props := map[string]string{}
	if err := json.Unmarshal([]byte(line), &props); err != nil {
		return nil, err
	}
	return &udev.Event{
		Action:     props[udev.PropertyAction],
		Subsystem:  props[udev.PropertySubsystem],
		Devpath:    props[udev.PropertyDevpath],
		Seqnum:     props[udev.PropertySeqnum],
		Properties: props,
	}, nil
}

// ensureFifo creates a named pipe at path unless one exists.
func ensureFifo(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.Mode()&os.ModeNamedPipe != 0 {
			return nil
		}
		return os.ErrExist
	}
	if !os.IsNotExist(err) {
		return err
	}
	return syscall.Mkfifo(path, 0o666)
}
