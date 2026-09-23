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

package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"sigs.k8s.io/yaml"
	cdiapi "tags.cncf.io/container-device-interface/pkg/cdi"
	cdiSpecs "tags.cncf.io/container-device-interface/specs-go"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/dra"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/store"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
	"github.com/containers/nri-plugins/pkg/cxl/kernel/fake"
)

const (
	// frontNode and frontNS are the node and the namespace of the claims,
	// frontPool the DRA pool of the pool devices.
	frontNode = "node1"
	frontNS   = "demo"
	frontPool = "fake-cxl-pool"
	// the requester of the leases of companion claims
	frontPod    = "borrower"
	frontPodUID = "pod-uid-1"
	frontCtr    = "app"
)

// The core model (engine.RunCoreModel) with kubelet's requests through both
// DRA drivers of the process over the engine and the store: the real
// Preparation steps, the CDI specs checked against the records at every
// step, companion claims lent through fakes of the lease broker and of NRI,
// and the process stopped at every commit of the store. The flags of
// TestCoreModel plan and replay a run.
func TestFrontModel(t *testing.T) {
	engine.RunCoreModel(t, func(f *fake.Fake, dir string) engine.CoreFront { return newFrontEnd(t, f, dir) })
}

// frontEnd runs the requests of the core model as kubelet does, through the
// plugins of cxl.nri.io and of the pool driver of the process; the fakes of
// the lease broker and of NRI outlive a restart, NRI's lends not a reboot.
type frontEnd struct {
	t   *testing.T
	f   *fake.Fake
	dir string
	// mountsDirs and leaseFsRoot are the directories of the node mounts and
	// of the lease binds of the engine.
	mountsDirs  map[state.Source]string
	leaseFsRoot string
	bootID      string

	st    *store.Store
	local *dra.Plugin
	pool  *dra.Plugin
	nodes *frontNodes
	hooks *frontHooks
}

// newFrontEnd returns the front-end of the node of the fake kernel f with
// its files in dir.
func newFrontEnd(t *testing.T, f *fake.Fake, dir string) *frontEnd {
	fe := &frontEnd{t: t, f: f, dir: dir, bootID: f.BootID()}
	fe.nodes = &frontNodes{}
	fe.hooks = &frontHooks{fe: fe}
	if err := os.MkdirAll(fe.cdiDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	return fe
}

// cdiDir returns the directory of the CDI specs.
func (fe *frontEnd) cdiDir() string {
	return filepath.Join(fe.dir, "cdi")
}

// TuneStore sets the pool driver and the roots of the device paths of the
// store.
func (fe *frontEnd) TuneStore(o *store.Options) {
	o.PoolDir, o.PoolDriver = filepath.Join(fe.dir, device.PoolDriverName), device.PoolDriverName
	o.SysRoot, o.DevRoot = fe.f.SysRoot(), fe.f.DevRoot()
}

// TuneEngine sets the revoke of the lends of companion grants of the engine
// and notes its directories.
func (fe *frontEnd) TuneEngine(o *engine.Options) {
	o.Revoke = fe.revoke
	fe.mountsDirs, fe.leaseFsRoot = o.MountsDirs, o.LeaseFsRoot
}

// Started starts both plugins over the store and the engine of a start, as
// the process does after the recovery rec: the lenders set, the CDI specs
// written from the records, the local devices published. NRI's lends do not
// outlive a reboot.
func (fe *frontEnd) Started(st *store.Store, e *engine.Engine, rec *engine.Recovered) error {
	if b := fe.f.BootID(); b != fe.bootID {
		fe.bootID = b
		fe.nodes.clear()
	}
	ctx := context.Background()
	cache, err := cdiapi.NewCache(cdiapi.WithSpecDirs(fe.cdiDir()), cdiapi.WithAutoRefresh(false))
	if err != nil {
		return err
	}
	cfg := dra.PublishConfig{ManageMemdevs: true, SharedDevices: []string{api.FormatSerial(frontSerialS)}}
	pub, err := dra.NewPublisher(dra.PublishOptions{Config: cfg, NodeName: frontNode, Scan: fe.scan, Store: st, Probes: e.Probes,
		BlockSize: fe.f.Kernel().BlockSize})
	if err != nil {
		return err
	}
	local := dra.LocalRules(fe.mountsDirs[state.SourceLocal])
	pool := dra.PoolRules(device.PoolDriverName, fe.mountsDirs[state.SourcePool], store.FileName)
	fe.st = st
	fe.local, err = dra.New(dra.Options{Rules: local, Store: st, Engine: e, NodeName: frontNode, BootID: fe.f.BootID(),
		DevRoot: fe.f.DevRoot(), CDI: cache, Publisher: pub, Local: dra.LocalConfig{Managed: true,
			UsableSize: func(string, uint64) uint64 { return 0 }, Coherent: func(string, uint64) bool { return false }}})
	if err != nil {
		return err
	}
	fe.pool, err = dra.New(dra.Options{Rules: pool, Store: st, Engine: e, NodeName: frontNode, BootID: fe.f.BootID(),
		DevRoot: fe.f.DevRoot(), CDI: cache, Publisher: pub})
	if err != nil {
		return err
	}
	for _, p := range []*dra.Plugin{fe.local, fe.pool} {
		p.Lender().Set(fe.nodes, fe.hooks)
		p.Recovered(rec, store.FileName)
		if err := p.WriteCDI(); err != nil {
			return err
		}
	}
	return pub.ScanWith(ctx, cfg, nil)
}

// frontSerialS is the serial of the local memdev that the core model
// configures shared (engine's serialS).
const frontSerialS = 0x51

// scan returns the local memdevs of the node as a scan of the publisher
// finds them: the sliced, the shared and the persistent one, ready.
func (fe *frontEnd) scan(context.Context) (*kernel.Snapshot, error) {
	snap := &kernel.Snapshot{}
	for _, m := range []struct {
		serial    uint64
		ram, pmem uint64
	}{{0x11, 1 << 30, 0}, {frontSerialS, 1 << 30, 0}, {0x91, 0, 1 << 30}} {
		snap.Memdevs = append(snap.Memdevs, kernel.MemdevInfo{Name: fe.f.Memdev(m.serial), Serial: m.serial, State: kernel.MemdevReady,
			RamSize: m.ram, PmemSize: m.pmem})
	}
	return snap, nil
}

// plugin returns the plugin of the source.
func (fe *frontEnd) plugin(source state.Source) *dra.Plugin {
	if source == state.SourcePool {
		return fe.pool
	}
	return fe.local
}

// Prepare runs kubelet's Prepare of the claim uid of a slot.
func (fe *frontEnd) Prepare(sl engine.CoreSlot, uid string) error {
	claim := fe.claim(sl, uid)
	res, err := fe.plugin(sl.Source).PrepareResourceClaims(context.Background(), []*resourcev1.ResourceClaim{claim})
	if err != nil {
		return err
	}
	return res[claim.UID].Err
}

// Unprepare runs kubelet's Unprepare of the claim uid of a slot.
func (fe *frontEnd) Unprepare(sl engine.CoreSlot, uid string) error {
	res, err := fe.plugin(sl.Source).UnprepareResourceClaims(context.Background(), []kubeletplugin.NamespacedObject{{UID: types.UID(uid)}})
	if err != nil {
		return err
	}
	return res[types.UID(uid)]
}

// leaseOf returns the lease of the companion claim uid.
func leaseOf(uid string) string {
	return "lease-" + uid
}

// claim returns the claim uid of a slot as the scheduler allocated it: a
// pool device with the status data of its controller, or a local memdev of
// the node with the size (sliced) or the shares it consumed; the
// MemoryConfig of the slot's mode; a companion claim of its lease.
func (fe *frontEnd) claim(sl engine.CoreSlot, uid string) *resourcev1.ResourceClaim {
	c := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Name: "claim-" + uid, Namespace: frontNS},
		Status:     resourcev1.ResourceClaimStatus{Allocation: &resourcev1.AllocationResult{}},
	}
	r := resourcev1.DeviceRequestAllocationResult{Request: "mem", Driver: device.DriverName, Pool: frontNode, Device: dra.MemdevDeviceName(sl.Serial)}
	shares := func(n int64) map[resourcev1.QualifiedName]resource.Quantity {
		return map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: *resource.NewQuantity(n, resource.DecimalSI)}
	}
	switch {
	case sl.Source == state.SourcePool:
		r.Driver, r.Pool, r.Device = device.PoolDriverName, frontPool, "pooled-"+sl.ID
		data := fmt.Sprintf(`{"serial":"%s","shared":%v,"size":268435456,"persistent":%v}`, api.FormatSerial(sl.Serial),
			sl.Kind == state.KindShared, sl.Kind == state.KindPersistent)
		if sl.Kind == state.KindShared {
			r.ConsumedCapacity = shares(1)
		}
		c.Status.Devices = []resourcev1.AllocatedDeviceStatus{{Driver: r.Driver, Pool: r.Pool, Device: r.Device,
			Data: &runtime.RawExtension{Raw: []byte(data)}}}
	case sl.Kind == state.KindExclusive:
		r.ConsumedCapacity = map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: *resource.NewQuantity(256<<20, resource.BinarySI)}
	case sl.Kind == state.KindPersistent && !sl.ReadOnly:
		r.ConsumedCapacity = shares(device.SharesUnlimited)
	default:
		r.ConsumedCapacity = shares(1)
	}
	c.Status.Allocation.Devices.Results = []resourcev1.DeviceRequestAllocationResult{r}
	dev := map[string]any{"mode": string(sl.Mode)}
	if sl.Mode == state.ModeFs || sl.Mode == state.ModeBlock {
		dev["readOnly"] = sl.ReadOnly
	}
	params, _ := json.Marshal(map[string]any{"apiVersion": "cxl.nri.io/v1alpha1", "kind": "MemoryConfig", "device": dev})
	c.Status.Allocation.Devices.Config = []resourcev1.DeviceAllocationConfiguration{{
		Source: resourcev1.AllocationConfigSourceClaim,
		DeviceConfiguration: resourcev1.DeviceConfiguration{Opaque: &resourcev1.OpaqueDeviceConfiguration{
			Driver: r.Driver, Parameters: runtime.RawExtension{Raw: params},
		}},
	}}
	if sl.Lease {
		id := leaseOf(uid)
		c.Name = "cxl-lease-" + id
		c.Labels = map[string]string{device.LeaseLabel: id}
		controller := true
		c.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: frontPod, UID: frontPodUID, Controller: &controller}}
	}
	return c
}

// revoke revokes the NUMA node that a grant of a companion claim lends,
// through the lender of the driver of the grant's source, as the engine's
// Revoke of the process does.
func (fe *frontEnd) revoke(ctx context.Context, ref state.GrantRef, gl state.GrantLend) error {
	r := &fe.st.Snapshot().Records
	p := fe.pool
	if g := r.Grant(ref); g != nil && g.Asked.Source == state.SourceLocal {
		p = fe.local
	}
	return p.Lender().RevokeGrant(ctx, gl, ref.Claim)
}

// Check returns the violations of the CDI specs, the lends and the lease
// binds against the records and the kernel now (6.2, 6.3, 5.3, O6): the
// spec of each driver has the devices of the results of its PREPARED
// claims that are not companions (cxl.nri.io: UNPREPARING ones too, D-88),
// each naming the dax device, the block device or the node mount that the
// records and the kernel have; a NUMA node is lent only for a grant that
// records the lend, and every prepared numa companion's node is lent; a
// lease bind is mounted only for a grant that records it, and every
// prepared fs companion's bind is mounted.
func (fe *frontEnd) Check() []string {
	doc := fe.st.Snapshot()
	snap, err := fe.f.Kernel().Observe(context.Background())
	if err != nil {
		return []string{"observe: " + err.Error()}
	}
	var out []string
	for _, p := range []*dra.Plugin{fe.local, fe.pool} {
		out = append(out, fe.checkCDI(doc, snap, p.Rules())...)
	}
	return append(out, fe.checkLends(doc, snap)...)
}

// checkCDI returns the violations of the CDI spec of the driver of rules.
func (fe *frontEnd) checkCDI(doc *store.Document, snap *kernel.Snapshot, rules dra.SourceRules) []string {
	var out []string
	devs := map[string]*cdiSpecs.Device{}
	spec, err := fe.cdiSpec(rules.CDISpecName)
	if err != nil {
		return []string{err.Error()}
	}
	if spec != nil {
		for i := range spec.Devices {
			devs[spec.Devices[i].Name] = &spec.Devices[i]
		}
	}
	r := &doc.Records
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Driver != rules.Name {
			continue
		}
		for _, res := range prep.Results {
			name := dra.ClaimCDIDeviceName(prep.UID, res.Index)
			d := devs[name]
			delete(devs, name)
			switch {
			case prep.Lease == "" && prep.State == state.PreparationPrepared:
				if d == nil {
					out = append(out, fmt.Sprintf("%s: no CDI device %s of PREPARED claim %s", rules.Name, name, prep.UID))
					continue
				}
				out = append(out, fe.checkCDIDevice(r, snap, d, prep, &res)...)
			case d != nil && (prep.Lease != "" || prep.State != state.PreparationUnpreparing || !rules.CDIUnpreparing):
				out = append(out, fmt.Sprintf("%s: CDI device %s of %s claim %s (lease %q)", rules.Name, name, prep.State, prep.UID, prep.Lease))
			}
		}
	}
	for name := range devs {
		out = append(out, fmt.Sprintf("%s: CDI device %s of no claim", rules.Name, name))
	}
	return out
}

// checkCDIDevice returns the violations of the CDI device d of the result
// res of a PREPARED claim: its marker, and the device node or the mount of
// what the grant got, as the records and the kernel have it.
func (fe *frontEnd) checkCDIDevice(r *state.Records, snap *kernel.Snapshot, d *cdiSpecs.Device, prep *state.Preparation,
	res *state.Result) []string {
	var out []string
	bad := func(format string, args ...any) {
		out = append(out, fmt.Sprintf("CDI device %s: ", d.Name)+fmt.Sprintf(format, args...))
	}
	if marker := state.ResultEnvVarName(prep.UID, res.Index) + "=1"; !slices.Contains(d.ContainerEdits.Env, marker) {
		bad("no %s in %v", marker, d.ContainerEdits.Env)
	}
	if res.Grant == nil {
		return out
	}
	g := r.Grant(*res.Grant)
	if g == nil {
		bad("no grant %s", *res.Grant)
		return out
	}
	nodes, mounts := d.ContainerEdits.DeviceNodes, d.ContainerEdits.Mounts
	switch g.Asked.Mode {
	case state.ModeDax:
		path := filepath.Join(fe.f.DevRoot(), g.Got.Dax)
		var kd *kernel.DaxDeviceInfo
		for i := range snap.DaxDevices {
			if snap.DaxDevices[i].Name == g.Got.Dax {
				kd = &snap.DaxDevices[i]
			}
		}
		switch {
		case kd == nil:
			bad("the kernel has no dax device %q of grant %s", g.Got.Dax, g.Ref)
		case len(nodes) != 1 || nodes[0].Path != path || nodes[0].Major != int64(kd.Major) || nodes[0].Minor != int64(kd.Minor) ||
			(nodes[0].Permissions == "r") != g.Asked.ReadOnly:
			bad("device nodes %s, the kernel has %s %d:%d (read-only %v)", nodeList(nodes), path, kd.Major, kd.Minor, g.Asked.ReadOnly)
		}
	case state.ModeBlock:
		bd := g.Got.BlockDevice
		var kb *kernel.BlockDevice
		for i := range snap.Devices {
			if bd != nil && filepath.Base(snap.Devices[i].Path) == filepath.Base(bd.Name) {
				kb = &snap.Devices[i]
			}
		}
		switch {
		case kb == nil:
			bad("the kernel has no block device of grant %s (%+v)", g.Ref, bd)
		case len(nodes) != 1 || nodes[0].Path != bd.Name || nodes[0].Major != int64(kb.Major) || nodes[0].Minor != int64(kb.Minor) ||
			(nodes[0].Permissions == "r") != g.Asked.ReadOnly:
			bad("device nodes %s, the kernel has %s %d:%d (read-only %v)", nodeList(nodes), kb.Path, kb.Major, kb.Minor, g.Asked.ReadOnly)
		}
	case state.ModeFs:
		m := r.MountOf(g)
		switch {
		case m == nil:
			bad("grant %s has no node mount", g.Ref)
		case !slices.ContainsFunc(snap.Mounts, func(mi kernel.MountInfo) bool { return mi.Target == m.Path }):
			bad("the kernel has no node mount %s", m.Path)
		case len(mounts) != 1 || mounts[0].HostPath != m.Path || slices.Contains(mounts[0].Options, "ro") != g.Asked.ReadOnly:
			bad("mounts %+v, the node mount %s (read-only %v)", mounts, m.Path, g.Asked.ReadOnly)
		}
	default:
		if len(nodes)+len(mounts) > 0 {
			bad("device nodes %s, mounts %+v of mode %s", nodeList(nodes), mounts, g.Asked.Mode)
		}
	}
	return out
}

// nodeList returns the device nodes as text.
func nodeList(nodes []*cdiSpecs.DeviceNode) string {
	var out []string
	for _, n := range nodes {
		out = append(out, fmt.Sprintf("%s %d:%d %q", n.Path, n.Major, n.Minor, n.Permissions))
	}
	return "[" + strings.Join(out, " ") + "]"
}

// cdiSpec returns the CDI spec of the name on disk, nil if there is none.
func (fe *frontEnd) cdiSpec(name string) (*cdiSpecs.Spec, error) {
	m, _ := filepath.Glob(filepath.Join(fe.cdiDir(), name+".*"))
	if len(m) == 0 {
		return nil, nil
	}
	data, err := os.ReadFile(m[0])
	if err != nil {
		return nil, err
	}
	spec := &cdiSpecs.Spec{}
	if err := yaml.Unmarshal(data, spec); err != nil {
		return nil, fmt.Errorf("CDI spec %s: %w", m[0], err)
	}
	return spec, nil
}

// checkLends returns the violations of the lends of NRI and of the lease
// binds of the kernel against the grants of the companion claims.
func (fe *frontEnd) checkLends(doc *store.Document, snap *kernel.Snapshot) []string {
	r := &doc.Records
	var out []string
	recorded := map[string]bool{}
	binds := map[string]bool{}
	for i := range r.Grants {
		g := &r.Grants[i]
		if l := g.Got.Lend; l != nil && l.NumaNode != nil {
			recorded[fmt.Sprintf("%d %s", *l.NumaNode, l.Lease)] = true
		}
		if b := g.Got.Bind; b != nil && b.State != state.BindAbsent {
			binds[b.Target] = true
		}
	}
	lent := fe.nodes.lends()
	for _, l := range lent {
		if !recorded[l] {
			out = append(out, fmt.Sprintf("NRI lends node and lease %s that no grant records", l))
		}
	}
	mounted := map[string]bool{}
	for _, mi := range snap.Mounts {
		if strings.HasPrefix(mi.Target, fe.leaseFsRoot+"/") {
			mounted[mi.Target] = true
			if !binds[mi.Target] {
				out = append(out, fmt.Sprintf("lease bind %s that no grant records", mi.Target))
			}
		}
	}
	for i := range r.Preparations {
		prep := &r.Preparations[i]
		if prep.Lease == "" || prep.State != state.PreparationPrepared {
			continue
		}
		for _, res := range prep.Results {
			g := r.Grant(*res.Grant)
			switch {
			case g == nil:
			case g.Asked.Mode == state.ModeNUMA && g.Got.NumaNode != nil &&
				!slices.Contains(lent, fmt.Sprintf("%d %s", *g.Got.NumaNode, prep.Lease)):
				out = append(out, fmt.Sprintf("node %d of PREPARED companion %s is not lent (lent %v)", *g.Got.NumaNode, prep.UID, lent))
			case g.Asked.Mode == state.ModeFs && (g.Got.Bind == nil || !mounted[g.Got.Bind.Target]):
				out = append(out, fmt.Sprintf("the lease bind of PREPARED companion %s is not mounted (%+v)", prep.UID, g.Got.Bind))
			}
		}
	}
	return out
}

// frontNodes is NRI's lender of NUMA nodes to the containers of leases.
type frontNodes struct {
	mu   sync.Mutex
	lent map[string]bool // "<node> <holder>"
}

// LendNode lends a node to the container on behalf of holder.
func (n *frontNodes) LendNode(_ context.Context, _, _ string, node int, holder string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.lent == nil {
		n.lent = map[string]bool{}
	}
	n.lent[fmt.Sprintf("%d %s", node, holder)] = true
	return nil
}

// RevokeNode drops holder of the node.
func (n *frontNodes) RevokeNode(_ context.Context, _, _ string, node int, holder string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.lent, fmt.Sprintf("%d %s", node, holder))
	return nil
}

// lends returns the lent nodes and their holders, sorted.
func (n *frontNodes) lends() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for l := range n.lent {
		out = append(out, l)
	}
	slices.Sort(out)
	return out
}

// clear forgets every lend: the containers are gone.
func (n *frontNodes) clear() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lent = nil
}

// frontHooks is the lease broker of the companion claims: every lease is
// the requester's and lends; an fs lease binds into its lease claim's
// directory.
type frontHooks struct {
	fe *frontEnd
}

// OnLending returns the lend of the lease's container.
func (h *frontHooks) OnLending(id string, _ *resourcev1.ResourceClaim) (*lend.Lend, error) {
	return &lend.Lend{Lease: id, Pod: state.PodRef{Namespace: frontNS, Name: frontPod, UID: frontPodUID}, Container: frontCtr,
		FsDir: filepath.Join(h.fe.leaseFsRoot, "lc-"+id), Name: "data"}, nil
}

// OnPrepared is told the prepared companion.
func (h *frontHooks) OnPrepared(string, state.Source, []state.DeviceInfo) {}

// OnLendFailed is told a failed lend.
func (h *frontHooks) OnLendFailed(string, error) {}

// OnReleasing is told the Unprepare of a companion.
func (h *frontHooks) OnReleasing(string) {}
