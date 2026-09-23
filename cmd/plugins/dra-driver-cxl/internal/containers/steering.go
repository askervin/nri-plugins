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

package containers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/containerd/nri/pkg/api"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
)

// The steering of the memory of containers by pkg/cgmpolmgr: a manager of
// the plugin writes the cpuset.mems, the thread memory policies and
// memory.high of a steered container directly, never through NRI. The
// Steered records of the store name the containers whose cgroup a manager
// writes: a record is committed before the manager writes the cgroup, and
// removed when the manager has stopped. So the records of a process that
// was killed, or that exited on the loss of NRI, name the containers whose
// memory.high its managers left, and the next process releases exactly
// those, whatever their settings say now (the configuration may have
// changed across the restart), and leaves the memory.high of the others
// alone.

// steeredCommitWait bounds a commit of the Steered records.
const steeredCommitWait = 5 * time.Second

// startManager starts a steering manager: its first step writes the
// cgroup (a variable for tests).
var startManager = (*cgmpolmgr.Manager).Start

// klogLogger writes cgmpolmgr log messages with klog.
type klogLogger struct{}

func (klogLogger) Debugf(format string, args ...any) { klog.V(4).Infof(format, args...) }
func (klogLogger) Infof(format string, args ...any)  { klog.Infof(format, args...) }
func (klogLogger) Warnf(format string, args ...any)  { klog.Warningf(format, args...) }
func (klogLogger) Errorf(format string, args ...any) { klog.Errorf(format, args...) }

// startSteering starts steering the memory of a container whose task the
// runtime has created along its plan, recorded in the store before the
// manager writes its cgroup. A container whose steering does not start is
// managed as a container that is not steered (notSteered).
func (p *Plugin) startSteering(c *Container, ctr *api.Container, plan *cgmpolmgr.Plan) {
	name := c.name()
	dir, err := resolveContainerCgroupDir(ctr)
	if err != nil {
		klog.Errorf("NRI StartContainer: ctr=%s id=%s: failed to resolve cgroup directory: %v", name, c.ID, err)
		p.notSteered(c, false)
		return
	}
	klog.V(3).Infof("NRI StartContainer: ctr=%s id=%s pid=%d cgroupsPath=%s", name, c.ID, ctr.GetPid(), dir)
	mgr, err := cgmpolmgr.New(dir, plan,
		cgmpolmgr.WithName(name),
		cgmpolmgr.WithLogger(klogLogger{}),
		cgmpolmgr.WithSysRoot(filepath.Join(p.opts.SysRoot, "/sys")))
	if err != nil {
		klog.Warningf("NRI StartContainer: ctr=%s: failed to create memory steering manager: %v", name, err)
		p.notSteered(c, false)
		return
	}
	p.addSteered(c.ID, dir)
	if err := startManager(mgr); err != nil {
		klog.Warningf("NRI StartContainer: ctr=%s: failed to start memory steering: %v", name, err)
		p.notSteered(c, true)
		return
	}
	p.mu.Lock()
	if p.ctrs[c.ID] != c {
		p.mu.Unlock()
		p.stopManager(c.ID, name, mgr)
		return
	}
	c.manager = mgr
	p.mu.Unlock()
	klog.V(3).Infof("NRI StartContainer: ctr=%s: started memory steering (cgroup=%s)", name, dir)
}

// notSteered manages a started container whose steering did not start
// like a container that is not steered (fenced with allowed-mems): no
// manager of this process steers it, so it is fenced and may be lent to.
// Its repair pass runs at its PostStartContainer. A failed Start of a
// manager (added: its Steered record was committed) has removed memory.high
// again, so the container leaves the Steered records.
func (p *Plugin) notSteered(c *Container, added bool) {
	if added {
		p.removeSteered(c.ID)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctrs[c.ID] != c || c.manager != nil {
		return
	}
	p.manage(c, c.unsteered, TriggerStart)
	klog.Warningf("NRI StartContainer: ctr=%s id=%s: not steered, memory %s", c.name(), c.ID, c.Management.text())
}

// stopManagers stops the managers of containers that left the table and
// removes their Steered records.
func (p *Plugin) stopManagers(gone []*Container) {
	for _, c := range gone {
		p.mu.Lock()
		mgr := c.manager
		c.manager, c.Plan = nil, nil
		p.mu.Unlock()
		if mgr != nil {
			p.stopManager(c.ID, c.name(), mgr)
		}
	}
}

// stopManager stops the manager of the container id, which sets its
// memory.high to max, and then removes its Steered record.
func (p *Plugin) stopManager(id, name string, mgr *cgmpolmgr.Manager) {
	mgr.Stop()
	p.removeSteered(id)
	klog.V(3).Infof("NRI: stopped memory steering for ctr=%s", name)
}

// releaseSteering sets memory.high of a container to max, as the Stop of
// a manager does, if a Steered record says that a manager of a previous
// process steered it, whatever its settings say now (steers: they steer
// it): the manager of a killed plugin left the memory.high of its last
// step, which nothing raises any more. The memory.high of a container that
// no manager steered (created while the plugin was down, or one that is not
// steered) is left alone: it may be someone else's (MemoryQoS). Without
// records (legacy) the containers that their settings steer are released,
// as a started one may have had a manager. Its cpuset.mems and memory
// policies are left as they are. Called with mu held.
func (p *Plugin) releaseSteering(c *Container, steers bool) {
	dir, recorded := p.steeredDir(c.ID)
	switch {
	case p.legacy && steers && !c.started():
		klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s", c.name(), c.ID, c.Management.text())
		return
	case p.legacy && steers:
		dir = c.CgroupDir
	case !recorded:
		if steers {
			klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high left alone: no manager steered it",
				c.name(), c.ID, c.Management.text())
		}
		return
	case dir == "":
		dir = c.CgroupDir
	}
	release(c, dir)
}

// release sets memory.high of the cgroup dir of a container to max.
func release(c *Container, dir string) {
	memory := c.Management.text()
	if dir == "" {
		klog.Warningf("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high not checked: no cgroup directory",
			c.name(), c.ID, memory)
		return
	}
	was, err := cgmpolmgr.Release(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; no memory.high: %v",
			c.name(), c.ID, memory, err)
	case err != nil:
		klog.Warningf("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; removing memory.high failed: %v",
			c.name(), c.ID, memory, err)
	case was != "":
		klog.Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high %s removed (max)",
			c.name(), c.ID, memory, was)
	default:
		klog.V(3).Infof("NRI Synchronize: ctr=%s id=%s: steering not restarted, memory %s; memory.high max",
			c.name(), c.ID, memory)
	}
}

// steeredDir returns the cgroup directory of the Steered record of the
// container id, and whether the store has one.
func (p *Plugin) steeredDir(id string) (string, bool) {
	for _, s := range p.opts.Store.Snapshot().Steered {
		if s.Container == id {
			return s.CgroupDir, true
		}
	}
	return "", false
}

// addSteered commits the Steered record of the container id whose cgroup
// dir a manager writes.
func (p *Plugin) addSteered(id, dir string) {
	p.commitSteered(func(records []state.Steered) []state.Steered {
		records = slices.DeleteFunc(records, func(s state.Steered) bool { return s.Container == id })
		return append(records, state.Steered{Container: id, CgroupDir: dir})
	})
}

// removeSteered commits the removal of the Steered records of the
// containers ids; the store writes nothing when it has none of them.
func (p *Plugin) removeSteered(ids ...string) {
	p.commitSteered(func(records []state.Steered) []state.Steered {
		return slices.DeleteFunc(records, func(s state.Steered) bool { return slices.Contains(ids, s.Container) })
	})
}

// syncSteered commits the Steered records of the containers keep only (the
// managers of this process): from now on the records are the plugin's.
func (p *Plugin) syncSteered(keep []string) {
	p.commitSteered(func(records []state.Steered) []state.Steered {
		return slices.DeleteFunc(records, func(s state.Steered) bool { return !slices.Contains(keep, s.Container) })
	})
	p.mu.Lock()
	p.legacy = false
	p.mu.Unlock()
}

// commitSteered commits the change of the Steered records durably, waiting
// at most steeredCommitWait; an error is logged.
func (p *Plugin) commitSteered(change func([]state.Steered) []state.Steered) {
	ctx, cancel := context.WithTimeout(context.Background(), steeredCommitWait)
	defer cancel()
	err := p.opts.Store.Commit(ctx, store.Durable, func(doc *store.Document) error {
		doc.Steered = change(slices.Clone(doc.Steered))
		return nil
	})
	if err != nil {
		klog.Warningf("NRI: steering record: %v", err)
	}
}
