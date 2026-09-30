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

// Package cgmpolmgr steers the memory allocations of a cgroup v2
// across NUMA nodes along a Plan.
//
// A Plan is a sequence of waypoints, each giving a target memory
// usage per node. Plan.NextStep tells on which nodes the next
// allocations should land and how many bytes may be allocated before
// the route is re-evaluated. Policy builds a Plan from a user-facing
// description of how DRAM and CXL quotas are consumed.
//
// A Manager applies the steps to a cgroup with two mechanisms. The
// nodes of every step are added to cpuset.mems of the cgroup, which
// confines all allocations of the cgroup to the nodes used so far.
// Nodes are only added, so memory is never migrated. The nodes of
// the current step are set as the memory policy of every thread in
// the cgroup with mpolinject. The step size is enforced with
// memory.high through cgmemnotify: the kernel throttles the cgroup
// when the step has been allocated, the manager computes the next
// step, updates the policy and raises memory.high again.
package cgmpolmgr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/pkg/cgmemnotify"
	logger "github.com/containers/nri-plugins/pkg/log"
	"github.com/containers/nri-plugins/pkg/mpolinject"
)

// Logger is the logging interface used by a Manager. The Logger of
// pkg/log implements it.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

var log Logger = logger.NewLogger("cgmpolmgr")

// waitTimeout is the interval at which the lower memory bound is
// checked when no memory.high event arrives.
const waitTimeout = time.Second

// numaUsageCategories are the memory.numa_stat categories that count
// as usage steered by the plan.
var numaUsageCategories = []string{"anon", "shmem"}

// Manager steers the memory allocations of one cgroup along a plan.
type Manager struct {
	cgroupPath string
	name       string
	plan       *Plan
	log        Logger
	notifier   *cgmemnotify.Notifier
	// allowed are the nodes written to cpuset.mems so far.
	allowed map[int]bool
	// stop is closed by Stop, done is closed when the steering
	// goroutine has exited.
	stop     chan struct{}
	done     chan struct{}
	started  bool
	stopOnce sync.Once
}

// Option configures a Manager.
type Option func(*Manager)

// WithName sets the name of the manager in log messages. The default
// is the base name of the cgroup path.
func WithName(name string) Option {
	return func(m *Manager) {
		m.name = name
	}
}

// WithLogger sets the logger of the manager. The default is the
// "cgmpolmgr" logger of pkg/log.
func WithLogger(l Logger) Option {
	return func(m *Manager) {
		m.log = l
	}
}

// New returns a Manager for the cgroup and the plan. Nothing is
// written to the cgroup before Start. The plan must not be modified
// after this call.
func New(cgroupPath string, plan *Plan, opts ...Option) (*Manager, error) {
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("invalid plan: %w", err)
	}
	info, err := os.Stat(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("cgroup: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("cgroup %s is not a directory", cgroupPath)
	}
	m := &Manager{
		cgroupPath: cgroupPath,
		name:       filepath.Base(cgroupPath),
		plan:       plan,
		log:        log,
		allowed:    make(map[int]bool),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// Start applies the first step of the plan to the cgroup and starts
// the goroutine that applies the following steps.
func (m *Manager) Start() error {
	if m.started {
		return errors.New("manager already started")
	}
	usage, err := m.numaUsage()
	if err != nil {
		return err
	}
	// Nodes that already hold memory stay allowed, so that writing
	// cpuset.mems never migrates memory.
	for node, bytes := range usage {
		if bytes > 0 {
			m.allowed[node] = true
		}
	}

	m.notifier, err = cgmemnotify.New(m.cgroupPath)
	if err != nil {
		return err
	}
	m.log.Infof("%s: start steering %s: %s", m.name, m.cgroupPath, m.plan)
	if err := m.step(usage); err != nil {
		_ = m.notifier.SetBounds(cgmemnotify.Bounds{})
		_ = m.notifier.Close()
		m.notifier = nil
		return err
	}
	m.started = true
	go m.loop()
	return nil
}

// Stop stops steering, removes memory.high from the cgroup and waits
// for the steering goroutine to exit. cpuset.mems and the memory
// policies of the threads are left as they are.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stop)
		if !m.started {
			return
		}
		if err := m.notifier.Interrupt(); err != nil {
			m.log.Errorf("%s: interrupt failed: %v", m.name, err)
		}
		<-m.done
	})
}

// loop applies a step whenever the memory usage of the cgroup
// crosses a bound, until Stop is called.
func (m *Manager) loop() {
	defer close(m.done)
	defer m.closeNotifier()
	defer m.release()
	for {
		event, err := m.notifier.Wait(waitTimeout)
		select {
		case <-m.stop:
			return
		default:
		}
		if errors.Is(err, cgmemnotify.ErrInterrupted) {
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			m.log.Infof("%s: cgroup %s is gone, stop steering", m.name, m.cgroupPath)
			return
		}
		if err != nil {
			m.log.Errorf("%s: wait failed: %v", m.name, err)
			select {
			case <-m.stop:
				return
			case <-time.After(waitTimeout):
			}
			continue
		}
		if event.Crossing == cgmemnotify.NoCrossing {
			continue
		}
		m.log.Debugf("%s: %s bound crossed, memory.current=%d", m.name, event.Crossing, event.MemoryCurrent)
		usage, err := m.numaUsage()
		if err != nil {
			m.log.Errorf("%s: %v", m.name, err)
			continue
		}
		if err := m.step(usage); err != nil {
			m.log.Errorf("%s: step failed: %v", m.name, err)
		}
	}
}

// closeNotifier closes the notifier of the manager.
func (m *Manager) closeNotifier() {
	if err := m.notifier.Close(); err != nil {
		m.log.Errorf("%s: closing notifier failed: %v", m.name, err)
	}
}

// release removes memory.high from the cgroup.
func (m *Manager) release() {
	err := m.notifier.SetBounds(cgmemnotify.Bounds{})
	switch {
	case errors.Is(err, os.ErrNotExist):
		m.log.Debugf("%s: cgroup is gone, memory.high not removed", m.name)
	case err != nil:
		m.log.Errorf("%s: removing memory.high failed: %v", m.name, err)
	}
	m.log.Infof("%s: stopped steering %s", m.name, m.cgroupPath)
}

// numaUsage returns the steered memory usage per node of the cgroup.
func (m *Manager) numaUsage() (NodeMem, error) {
	usage, err := cgmemnotify.NumaUsage(m.cgroupPath, numaUsageCategories...)
	if err != nil {
		return nil, fmt.Errorf("reading NUMA usage: %w", err)
	}
	return NodeMem(usage), nil
}

// step applies the next step of the plan for the usage: allows the
// step nodes in cpuset.mems, sets the memory policy of the threads
// in the cgroup and sets the memory bounds for the next step.
func (m *Manager) step(usage NodeMem) error {
	step, err := m.plan.NextStep(usage)
	if err != nil {
		return err
	}
	if len(step.Nodes) == 0 {
		m.log.Debugf("%s: step: usage=%s nothing left to steer, removing memory.high", m.name, usage)
		return m.notifier.SetBounds(cgmemnotify.Bounds{})
	}

	if err := m.allowNodes(step.Nodes); err != nil {
		return err
	}

	pids, err := cgmemnotify.Procs(m.cgroupPath)
	if err != nil {
		return fmt.Errorf("reading processes: %w", err)
	}
	if len(pids) > 0 {
		mode := mpolinject.Preferred
		if len(step.Nodes) > 1 {
			mode = mpolinject.Interleave
		}
		// Bounds are set even if some threads could not be
		// updated, otherwise the cgroup would stay throttled.
		if err := mpolinject.SetMemoryPolicy(pids, mode, step.Nodes); err != nil {
			m.log.Warnf("%s: setting memory policy failed: %v", m.name, err)
		}
	}

	current, err := cgmemnotify.MemoryCurrent(m.cgroupPath)
	if err != nil {
		return fmt.Errorf("reading memory.current: %w", err)
	}
	bounds := cgmemnotify.Bounds{Upper: current + step.Bytes}
	if current > step.Bytes {
		bounds.Lower = current - step.Bytes
	}
	if err := m.notifier.SetBounds(bounds); err != nil {
		return err
	}
	m.log.Debugf("%s: step: usage=%s nodes=%v bytes=%d procs=%d cpuset.mems=%s lower=%d upper=%d",
		m.name, usage, step.Nodes, step.Bytes, len(pids), m.allowedNodes(), bounds.Lower, bounds.Upper)
	return nil
}

// allowNodes adds the nodes to cpuset.mems of the cgroup if they are
// not allowed yet.
func (m *Manager) allowNodes(nodes []int) error {
	added := false
	for _, node := range nodes {
		if !m.allowed[node] {
			m.allowed[node] = true
			added = true
		}
	}
	if !added {
		return nil
	}
	mems := m.allowedNodes().String()
	if err := os.WriteFile(filepath.Join(m.cgroupPath, "cpuset.mems"), []byte(mems+"\n"), 0644); err != nil {
		return fmt.Errorf("write cpuset.mems %q: %w", mems, err)
	}
	m.log.Debugf("%s: cpuset.mems=%s", m.name, mems)
	return nil
}

// allowedNodes returns the nodes allowed in cpuset.mems so far.
func (m *Manager) allowedNodes() cpuset.CPUSet {
	nodes := make([]int, 0, len(m.allowed))
	for node := range m.allowed {
		nodes = append(nodes, node)
	}
	sort.Ints(nodes)
	return cpuset.New(nodes...)
}
