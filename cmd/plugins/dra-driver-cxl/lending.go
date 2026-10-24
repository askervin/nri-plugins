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

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/klog/v2"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// Lending of companion claims, shared by the pool driver and the
// cxl.nri.io driver: a companion claim carries the label
// cxl.nri.io/lease=<id> of a lease of the broker, whose running
// container borrows the memory of the claim's devices (docs/memory/cxl/leases.md).

// lentDevice is one prepared device of a companion claim, as the lease
// broker needs it.
type lentDevice struct {
	Driver    string // DRA driver that prepared the device
	Source    string // api.SourcePool or api.SourceLocal
	Request   string
	Device    string
	Pool      string
	Serial    uint64
	Shared    bool
	Size      uint64 // bytes the lease gets: the slice size or the device size
	Mode      string // api.ModeNUMA, api.ModeDax, api.ModeBlock or api.ModeFs
	ReadOnly  bool
	Node      int    // numa: NUMA node of the memory, else -1
	DaxDevice string // dax: /dev/daxX.Y
	// BlockDevice is the host path of the block device of a block or fs
	// device, /dev/pmemK.
	BlockDevice string
	Access      string // fs: api.AccessDirect or api.AccessCached
	NodeMount   string // fs: the host path of the node mount of the device
}

// leaseHooks is what a driver tells the lease broker about companion
// claims. The hooks are called with the driver's lock held and must not
// call back into the driver.
type leaseHooks interface {
	// OnLending checks that the claim is the companion of the lease,
	// marks the lease Lending and returns the lend of the lease's
	// container (without nodes). An error fails the Prepare.
	OnLending(id string, claim *resourceapi.ResourceClaim) (*lendRecord, error)
	// OnPrepared marks the lease Ready with the prepared devices.
	OnPrepared(id string, devs []lentDevice)
	// OnLendFailed records a lend error (kubelet retries the Prepare).
	OnLendFailed(id string, err error)
	// OnReleasing is called when the companion claim is unprepared.
	OnReleasing(id string)
}

// lendRecord is the lend of a prepared companion claim, persisted with the
// claim so that Unprepare can revoke it after a plugin restart.
type lendRecord struct {
	Lease     string `json:"lease"`
	Pod       podRef `json:"pod"`
	Container string `json:"container"`
	Nodes     []int  `json:"nodes,omitempty"` // lent NUMA nodes
	// FsDir is the host directory of the mounts of the fs leases of the
	// lease claim, "" for other leases and for a lease claim without it.
	FsDir string `json:"fsDir,omitempty"`
	// Name is the mount point of an fs lease in FsDir.
	Name string `json:"name,omitempty"`
	// Mounts are the host paths of the binds of the node mounts of the
	// fs devices in FsDir.
	Mounts []string `json:"mounts,omitempty"`
}

// companionLender lends the companion claims of one driver to running
// containers. A nil or zero companionLender has lending disabled.
type companionLender struct {
	driver string
	mu     sync.Mutex
	nodes  nodeLender // nil: NRI not connected
	hooks  leaseHooks // nil: lending disabled
}

// newCompanionLender returns a companionLender for the companion claims of
// driver, with lending disabled until set is called.
func newCompanionLender(driver string) *companionLender {
	return &companionLender{driver: driver}
}

// set enables lending: nodes lends NUMA nodes (nil when NRI is not
// connected, then companion claims fail), hooks is the lease broker (nil
// disables lending).
func (c *companionLender) set(nodes nodeLender, hooks leaseHooks) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes = nodes
	c.hooks = hooks
}

// get returns the node lender and the hooks.
func (c *companionLender) get() (nodeLender, leaseHooks) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nodes, c.hooks
}

// leaseOf returns the lease id of a companion claim (its label
// device.LeaseLabel), "" for other claims.
func leaseOf(claim *resourceapi.ResourceClaim) string {
	return claim.Labels[device.LeaseLabel]
}

// check checks that a companion claim can be lent, before any device is
// touched, marks its lease Lending and returns the lend of the lease's
// container.
func (c *companionLender) check(id string, claim *resourceapi.ResourceClaim) (*lendRecord, error) {
	nodes, hooks := c.get()
	if hooks == nil {
		return nil, fmt.Errorf("lease %s: lending to running containers is disabled (--leases=false)", id)
	}
	if nodes == nil {
		return nil, fmt.Errorf("lease %s: %w", id, errLendingUnavailable)
	}
	return hooks.OnLending(id, claim)
}

// lend lends the NUMA nodes of the numa devices of a companion claim to
// the container of the lend, held by its lease, and records them in rec.
// Dax and block devices are passed as an fd by the broker. On error rec lists the
// nodes lent so far.
func (c *companionLender) lend(ctx context.Context, rec *lendRecord, devs []lentDevice) error {
	nodes, _ := c.get()
	for _, d := range devs {
		if d.Mode != api.ModeNUMA || d.Node < 0 {
			continue
		}
		if nodes == nil {
			return fmt.Errorf("lease %s: %w", rec.Lease, errLendingUnavailable)
		}
		rec.Nodes = append(rec.Nodes, d.Node)
		if err := nodes.LendNode(ctx, rec.Pod.UID, rec.Container, d.Node, rec.Lease); err != nil {
			return fmt.Errorf("lease %s: lending node %d to %s/%s/%s: %w", rec.Lease, d.Node, rec.Pod.Namespace, rec.Pod.Name, rec.Container, err)
		}
		klog.Infof("%s: lease %s: lent node %d to %s/%s/%s", c.driver, rec.Lease, d.Node, rec.Pod.Namespace, rec.Pod.Name, rec.Container)
	}
	return nil
}

// revoke revokes the lent nodes of a lend for its lease: a node that
// another lease of the container holds stays lent. Without NRI the nodes
// cannot be revoked: the release then migrates the pages anyway, but the
// stale node stays in the container's cpuset.mems.
func (c *companionLender) revoke(ctx context.Context, rec *lendRecord, claimName string) error {
	if rec == nil || len(rec.Nodes) == 0 {
		return nil
	}
	nodes, _ := c.get()
	if nodes == nil {
		klog.Warningf("%s: claim %s: lease %s: %v, cannot revoke nodes %v from %s/%s/%s",
			c.name(), claimName, rec.Lease, errLendingUnavailable, rec.Nodes, rec.Pod.Namespace, rec.Pod.Name, rec.Container)
		return nil
	}
	var errs []error
	for _, n := range rec.Nodes {
		if err := nodes.RevokeNode(ctx, rec.Pod.UID, rec.Container, n, rec.Lease); err != nil {
			errs = append(errs, fmt.Errorf("lease %s: revoking node %d from %s/%s/%s: %w", rec.Lease, n, rec.Pod.Namespace, rec.Pod.Name, rec.Container, err))
		}
	}
	return errors.Join(errs...)
}

// prepared tells the broker that the companion claim of a lease is
// prepared and lent.
func (c *companionLender) prepared(id string, devs []lentDevice) {
	if _, hooks := c.get(); hooks != nil {
		hooks.OnPrepared(id, devs)
	}
}

// reprepared tells the broker again that a stored companion claim is
// prepared and lent, as kubelet asks to prepare a prepared claim again
// after a plugin restart.
func (c *companionLender) reprepared(rec *lendRecord, claim *resourceapi.ResourceClaim, devs []lentDevice) {
	_, hooks := c.get()
	if hooks == nil || rec == nil {
		return
	}
	if _, err := hooks.OnLending(rec.Lease, claim); err == nil {
		hooks.OnPrepared(rec.Lease, devs)
	}
}

// failed tells the broker that lending the companion claim of a lease
// failed.
func (c *companionLender) failed(id string, err error) {
	if _, hooks := c.get(); hooks != nil {
		hooks.OnLendFailed(id, err)
	}
}

// releasing tells the broker that the companion claim of a lease is
// being unprepared.
func (c *companionLender) releasing(id string) {
	if _, hooks := c.get(); hooks != nil {
		hooks.OnReleasing(id)
	}
}

// name returns the driver name for logs.
func (c *companionLender) name() string {
	if c == nil {
		return ""
	}
	return c.driver
}

// resolveResults returns the MemoryConfig of each allocation result of a
// claim for driver by result index; of selects the results of the driver.
// Returns an error with the request of the first result whose
// configuration is invalid.
func resolveResults(claim *resourceapi.ResourceClaim, driver string, of func(r *resourceapi.DeviceRequestAllocationResult) bool) (map[int]*config.Resolved, error) {
	out := map[int]*config.Resolved{}
	for n := range claim.Status.Allocation.Devices.Results {
		r := &claim.Status.Allocation.Devices.Results[n]
		if !of(r) {
			continue
		}
		res, err := config.Resolve(claim, driver, r.Request)
		if err != nil {
			return nil, fmt.Errorf("request %s: %w", r.Request, err)
		}
		out[n] = res
	}
	return out, nil
}

// consumedShares returns the shares that an allocation result of the
// shared device with the serial consumed, and an error if it consumed less
// than one share or has no shares in its consumed capacity.
func consumedShares(serial uint64, r *resourceapi.DeviceRequestAllocationResult) (int64, error) {
	q, ok := r.ConsumedCapacity[device.CapacityShares]
	if !ok || q.Cmp(*resource.NewQuantity(1, resource.DecimalSI)) < 0 {
		got := ""
		if ok {
			got = q.String()
		}
		return 0, fmt.Errorf("device %s: consumed %s %q is less than 1: request %s: 1 (a share) or no %s (exclusive)",
			api.FormatSerial(serial), device.CapacityShares, got, device.CapacityShares, device.CapacityShares)
	}
	return q.Value(), nil
}

// shareUse returns how an allocation result that consumed shares of a
// device of total shares uses it: "exclusive" when it consumed all of
// them, else "1 share" or "<n> shares".
func shareUse(shares, total int64) string {
	switch {
	case shares >= total:
		return "exclusive"
	case shares == 1:
		return "1 share"
	}
	return fmt.Sprintf("%d shares", shares)
}

// daxDeviceNode returns the CDI device node of a devdax device. A
// read-only node has permissions "r": the runtime turns that into a
// device cgroup rule that refuses opens for writing, whatever the
// container's capabilities.
func daxDeviceNode(path string, major, minor int, readOnly bool) *cdiSpecs.DeviceNode {
	node := &cdiSpecs.DeviceNode{
		Path:  path,
		Type:  "c",
		Major: int64(major),
		Minor: int64(minor),
	}
	if readOnly {
		node.Permissions = "r"
	}
	return node
}

// envKeys counts the memories of each base env key in one claim.
type envKeys map[string]int

// next returns the env key of the next memory with the base key: the
// base key for the first one, then "<base>_<n>" (api.Nth).
func (k envKeys) next(base string) string {
	k[base]++
	return api.Nth(base, k[base])
}
