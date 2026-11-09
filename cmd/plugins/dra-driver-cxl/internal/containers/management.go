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
	"fmt"
	"slices"

	"k8s.io/klog/v2"
	"k8s.io/utils/cpuset"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/pkg/cgmpolmgr"
	cxlapi "github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// LocalResults are the prepared claims of cxl.nri.io.
type LocalResults interface {
	// PreparedResult returns the claim name and the prepared device of
	// the allocation result n of a prepared claim, and false if there is
	// none.
	PreparedResult(uid string, n int) (string, dra.DeviceInfo, bool)
}

// PoolResults are the prepared claims of the pool driver.
type PoolResults interface {
	// ClaimResults returns the prepared allocation results of a claim.
	ClaimResults(uid string) []dra.PoolResult
}

// resultRef is an allocation result of a claim: the claim UID and the
// index of the result in the allocation of the claim.
type resultRef struct {
	uid string
	n   int
}

// result is a prepared allocation result of either driver that a container
// uses.
type result struct {
	// pool: a device of the pool driver.
	pool bool
	// deviceType is the device type of a result of cxl.nri.io.
	deviceType string
	mode       string
	nodes      []int
	// bytes is the memory of the result.
	bytes    int64
	settings config.ResultSettings
}

// numaCXL tells whether the result has CXL memory in mode numa: a numa
// slice of a local memdev, a region or a pool device in mode numa.
func (r *result) numaCXL() bool {
	return r.mode == cxlapi.ModeNUMA && (r.pool || r.deviceType == device.DeviceTypeMemdev || r.deviceType == device.DeviceTypeRegion)
}

// decision is the management of the memory of a container that the
// plugin decides from its results.
type decision struct {
	management Management
	// eff are the effective container settings.
	eff *config.Effective
	// claimed are the NUMA nodes of the CXL numa memory of the results.
	claimed cpuset.CPUSet
	// plan is the steering plan of a steered container, if built.
	plan *cgmpolmgr.Plan
	// policy is the memory use order of the plan.
	policy string
	// mem is the memory to steer.
	mem cgmpolmgr.MemoryTypes
	// capacityOnly: the results have DRAM or region memory that is not
	// steered.
	capacityOnly bool
}

// extractResults returns the unique allocation results of the markers
// CXL_CLAIM_<uid>_<n> in an environment: kubelet does not deduplicate CDI
// device IDs.
func extractResults(env []string) []resultRef {
	seen := make(map[resultRef]bool)
	var refs []resultRef
	for _, e := range env {
		uid, n, ok := dra.ResultFromEnvVar(e)
		if ref := (resultRef{uid: uid, n: n}); ok && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	return refs
}

// results returns the prepared allocation results of both drivers that refs
// refer to; results that are not prepared are left out.
func (p *Plugin) results(ctrName string, refs []resultRef) []result {
	var out []result
	for _, ref := range refs {
		if r, ok := p.localResult(ctrName, ref); ok {
			out = append(out, r)
			continue
		}
		if r, ok := p.poolResult(ctrName, ref); ok {
			out = append(out, r)
			continue
		}
		klog.V(5).Infof("NRI CreateContainer: ctr=%s claim=%s result %d: not prepared (driver may have restarted)", ctrName, ref.uid, ref.n)
	}
	return out
}

// localResult returns the prepared result ref of cxl.nri.io, and false if
// there is none.
func (p *Plugin) localResult(ctrName string, ref resultRef) (result, bool) {
	if p.opts.Local == nil {
		return result{}, false
	}
	claim, d, ok := p.opts.Local.PreparedResult(ref.uid, ref.n)
	if !ok {
		return result{}, false
	}
	klog.V(5).Infof("NRI CreateContainer: ctr=%s claim=%s (%s) result %d: name=%s type=%s mode=%s sysfs=%s numa=%v affinities=%v total=%s consumed=%s request=%s",
		ctrName, ref.uid, claim, ref.n,
		d.DeviceName, d.DeviceType, d.Mode, d.SysfsPath, d.NUMANodes, d.NodeAffinities,
		formatBytes(d.TotalBytes), formatBytes(uint64(d.ConsumedBytes)), d.RequestName)
	return result{deviceType: d.DeviceType, mode: d.Mode, nodes: nonNegative(d.NUMANodes), bytes: d.ConsumedBytes,
		settings: d.ResultSettings}, true
}

// poolResult returns the prepared result ref of the pool driver, and false
// if there is none.
func (p *Plugin) poolResult(ctrName string, ref resultRef) (result, bool) {
	if p.opts.Pool == nil {
		return result{}, false
	}
	results := p.opts.Pool.ClaimResults(ref.uid)
	i := slices.IndexFunc(results, func(r dra.PoolResult) bool { return r.Index == ref.n })
	if i < 0 {
		return result{}, false
	}
	r := results[i]
	klog.V(5).Infof("NRI CreateContainer: ctr=%s claim=%s result %d: pool device mode=%s node=%d size=%s request=%s",
		ctrName, ref.uid, ref.n, r.Mode, r.Node, formatBytes(r.Size), r.Request)
	out := result{pool: true, mode: r.Mode, bytes: int64(r.Size), settings: r.Settings}
	if r.Node >= 0 {
		out.nodes = []int{r.Node}
	}
	return out, true
}

// decide returns the management of the memory of a container that uses
// the results, with the steering plan of a steered container if plan is
// set. A container is steered when its effective steering policy is not
// none and its results have DRAM or CXL numa memory; otherwise it is
// fenced when its effective fencing is allowed-mems, else none. Returns an
// error if the container settings of the results conflict or are invalid,
// or the steering plan cannot be built.
func (p *Plugin) decide(ctrName string, results []result, plan bool) (*decision, error) {
	settings := make([]config.ResultSettings, 0, len(results))
	for _, r := range results {
		settings = append(settings, r.settings)
	}
	eff, err := config.Combine(settings, p.opts.Defaults)
	if err != nil {
		return nil, fmt.Errorf("container %s: %w", ctrName, err)
	}
	d := &decision{management: ManagementNone, eff: eff, claimed: claimedNodes(results), mem: steeredMemory(results)}
	if pol, ok := eff.Container.Steering.CgmPolicy(d.mem); ok {
		d.management, d.policy = ManagementSteered, pol.MemoryUseOrder
		if plan {
			if d.plan, err = pol.Plan(d.mem); err != nil {
				return nil, fmt.Errorf("NRI CreateContainer: ctr=%s: failed to build memory steering plan: %w", ctrName, err)
			}
		}
		return d, nil
	}
	d.management = unsteered(eff)
	for _, r := range results {
		if r.deviceType == device.DeviceTypeDRAM || (r.deviceType == device.DeviceTypeRegion && r.mode == cxlapi.ModeNUMA) {
			d.capacityOnly = true
		}
	}
	return d, nil
}

// unsteered returns the management of the memory of a container that is
// not steered: fenced when its effective fencing is allowed-mems, else
// none.
func unsteered(eff *config.Effective) Management {
	if eff.Container.Fencing == config.FencingAllowedMems {
		return ManagementFenced
	}
	return ManagementNone
}

// defaultManagement returns the management of the memory of a container
// that uses no allocation results.
func (p *Plugin) defaultManagement() Management {
	eff, err := config.Combine(nil, p.opts.Defaults)
	if err != nil {
		return ManagementNone
	}
	return unsteered(eff)
}

// logDecision logs the management of the memory of a new container.
//   - hasResults: the container uses allocation results
func logDecision(ctrName string, d *decision, hasResults bool) {
	klog.V(3).Infof("NRI CreateContainer: ctr=%s: memory %s (steering %s, fencing %s)",
		ctrName, d.management.text(), d.eff.PolicyText(), fencingText(d.eff))
	switch {
	case d.management == ManagementSteered && d.plan != nil:
		klog.V(5).Infof("NRI CreateContainer: ctr=%s: prepared memory steering (order=%s, dramNodes=%v, cxlNodes=%v, %s)",
			ctrName, d.policy, d.mem.DRAMNodes, d.mem.CXLNodes, d.plan)
	case d.management == ManagementSteered:
	case d.eff.Steers() && hasResults:
		klog.V(3).Infof("NRI CreateContainer: ctr=%s: steering policy %s: no numa memory to steer", ctrName, d.eff.Container.Steering.Policy)
	}
	if d.capacityOnly {
		klog.V(3).Infof("NRI CreateContainer: ctr=%s: dram and region memory is not steered: the claims reserve capacity only", ctrName)
	}
}

// text returns the management as the log lines name it: steered, fenced
// or none.
func (m Management) text() string {
	switch m {
	case ManagementSteered:
		return "steered"
	case ManagementFenced:
		return "fenced"
	case ManagementNone:
		return "none"
	}
	return string(m)
}

// fencingText returns the effective fencing and its origin, such as
// "allowed-mems (default)" or "none (node default)".
func fencingText(eff *config.Effective) string {
	switch origin := eff.Origins[config.FieldFencing]; origin {
	case config.OriginDefault, "":
		return eff.Container.Fencing + " (" + config.OriginDefault + ")"
	case config.OriginNodeDefault:
		return eff.Container.Fencing + " (" + config.OriginNodeDefault + ")"
	default:
		return eff.Container.Fencing + " from " + origin
	}
}

// claimedNodes returns the NUMA nodes of the CXL numa memory of the
// results.
func claimedNodes(results []result) cpuset.CPUSet {
	nodes := cpuset.New()
	for i := range results {
		if results[i].numaCXL() {
			nodes = nodes.Union(cpuset.New(results[i].nodes...))
		}
	}
	return nodes
}

// steeredMemory returns the memory types and quotas of the results: DRAM
// of dram devices, CXL of numa slices of local memdevs, regions and pool
// devices in mode numa.
func steeredMemory(results []result) cgmpolmgr.MemoryTypes {
	dram, cxl := cpuset.New(), cpuset.New()
	var mem cgmpolmgr.MemoryTypes
	for i := range results {
		r := &results[i]
		switch {
		case r.deviceType == device.DeviceTypeDRAM:
			dram = dram.Union(cpuset.New(r.nodes...))
			mem.DRAMQuota += r.bytes
		case r.numaCXL():
			cxl = cxl.Union(cpuset.New(r.nodes...))
			mem.CXLQuota += r.bytes
		}
	}
	mem.DRAMNodes, mem.CXLNodes = dram.List(), cxl.List()
	return mem
}

// nonNegative returns the nodes that are not negative.
func nonNegative(nodes []int) []int {
	out := make([]int, 0, len(nodes))
	for _, n := range nodes {
		if n >= 0 {
			out = append(out, n)
		}
	}
	return out
}

// formatBytes formats a byte count as a human-readable string using
// binary units (KiB, MiB, GiB).
func formatBytes(bytes uint64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
	)
	switch {
	case bytes >= gib:
		return fmt.Sprintf("%.1fGiB", float64(bytes)/float64(gib))
	case bytes >= mib:
		return fmt.Sprintf("%.1fMiB", float64(bytes)/float64(mib))
	case bytes >= kib:
		return fmt.Sprintf("%.1fKiB", float64(bytes)/float64(kib))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
