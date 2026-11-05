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

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/kernel"
)

// The persistent chain of a grant of mode block or fs: the pmem region of
// the memdev -> its nd region -> the fsdax namespace (map mem) -> its pfn ->
// the block device /dev/pmemK -> its read-only flag -> the superblock of
// its filesystem -> one node mount per memdev and access that the grants of
// the node share (<mounts dir of the source>/<serial hex>-<access>). The
// state of a superblock (read-write while a grant of the memdev writes) and
// the read-only flags of the block devices are derived from the grants of
// the memdev, never stored apart from them.

const (
	// fsMountFlags are the flags of the node mounts of read-only
	// filesystem types (mount(2)).
	fsMountFlags = syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV
	// daxAlways is the super option of a DAX mount.
	daxAlways = "dax=always"
	// maxUnbinds bounds the unmounts of one lease bind (stacked mounts).
	maxUnbinds = 8
)

// use is a grant of mode block or fs of a persistent memdev, as the rules of
// one node see it.
type use struct {
	ref    state.GrantRef
	source state.Source
	serial state.Serial
	mode   state.Mode
	// readOnly is the effective read-only setting: a use with readOnly
	// false writes the device.
	readOnly bool
	// access and fsType are those of the node mount of mode fs.
	access string
	fsType string
	// blockDevice is the block device as prepared, nodeMount and loop the
	// node mount of mode fs and the loop device of a cached one.
	blockDevice string
	nodeMount   string
	loop        string
}

// writer tells whether the use writes the device.
func (u *use) writer() bool {
	return !u.readOnly
}

// useOf returns a grant as a use.
func useOf(g *state.Grant) use {
	u := use{ref: g.Ref, source: g.Asked.Source, serial: g.Serial, mode: g.Asked.Mode, readOnly: g.Asked.ReadOnly,
		access: string(g.Got.Mount), fsType: g.Got.FsType, nodeMount: g.Got.MountPath, loop: g.Got.Loop}
	if g.Got.BlockDevice != nil {
		u.blockDevice = g.Got.BlockDevice.Name
	}
	return u
}

// prepared tells whether a grant counts as a use of its device on the
// node: realised, or realised before a start that did not verify it.
func prepared(g *state.Grant) bool {
	return g.State == state.GrantRealised || g.State == state.GrantUnrestored
}

// usesOf returns the uses of the memdev with the serial by the prepared
// grants other than except.
func usesOf(r *state.Records, serial state.Serial, except ...state.GrantRef) []use {
	var out []use
	for i := range r.Grants {
		g := &r.Grants[i]
		if g.Serial != serial || !prepared(g) || slices.Contains(except, g.Ref) ||
			(g.Asked.Mode != state.ModeBlock && g.Asked.Mode != state.ModeFs) {
			continue
		}
		out = append(out, useOf(g))
	}
	return out
}

// firstWriter returns the first use that writes, nil if none does.
func firstWriter(uses []use) *use {
	for i := range uses {
		if uses[i].writer() {
			return &uses[i]
		}
	}
	return nil
}

// fsAccesses returns the accesses of the uses of mode fs, sorted.
func fsAccesses(uses []use) []string {
	var out []string
	for _, u := range uses {
		if u.mode == state.ModeFs && !slices.Contains(out, u.access) {
			out = append(out, u.access)
		}
	}
	slices.Sort(out)
	return out
}

// nodeMounts returns the node mounts of the uses, sorted.
func nodeMounts(uses []use) []string {
	var out []string
	for _, u := range uses {
		if u.nodeMount != "" && !slices.Contains(out, u.nodeMount) {
			out = append(out, u.nodeMount)
		}
	}
	slices.Sort(out)
	return out
}

// blockDeviceOf returns the first block device of the uses, "" if none.
func blockDeviceOf(uses []use) string {
	for _, u := range uses {
		if u.blockDevice != "" {
			return u.blockDevice
		}
	}
	return ""
}

// roWord returns "read-only" or "read-write".
func roWord(readOnly bool) string {
	if readOnly {
		return "read-only"
	}
	return "read-write"
}

// devRoot returns the directory of the device nodes.
func (e *Engine) devRoot() string {
	if e.k.DevRoot != "" {
		return e.k.DevRoot
	}
	return "/dev"
}

// loopOf returns the loop device that a mount is of, "" if none.
func (e *Engine) loopOf(mi *kernel.MountInfo) string {
	if strings.HasPrefix(mi.Source, e.devRoot()+"/loop") {
		return mi.Source
	}
	return ""
}

// nodeMountPath returns the node mount of the memdev with the serial and
// the access for a source: <mounts dir>/<serial hex>-<access>.
func (e *Engine) nodeMountPath(source state.Source, serial state.Serial, access string) string {
	return filepath.Join(e.opts.MountsDirs[source], fmt.Sprintf("%x-%s", uint64(serial), access))
}

// realisePersistent realises a grant of mode block or fs: the pmem region
// of the memdev with its nd region, the fsdax namespace (which only a
// writable block grant creates), then the use of the device next to the
// other uses on the node, and the lease bind of a companion grant.
func (e *Engine) realisePersistent(ctx context.Context, req *GrantRequest, memdev string) error {
	region, ns, err := e.pmemChain(ctx, req, memdev)
	if err != nil {
		return err
	}
	dev := &state.BlockDevice{Name: ns.BlockDevice, Dev: state.DevNumbers{Major: ns.Major, Minor: ns.Minor}}
	others := usesOf(e.records(), req.Serial, req.Ref)
	u, err := e.prepareUse(ctx, req, ns.BlockDevice, others)
	if err != nil {
		return err
	}
	got := state.Got{Region: state.RegionRef(region), Namespace: ns.Name, BlockDevice: dev, Size: ns.Size,
		Mount: state.Access(u.access), MountPath: u.nodeMount, Loop: u.loop, FsType: u.fsType}
	if err := e.recordUse(ctx, req, region, u, u.writer() || firstWriter(others) != nil); err != nil {
		return err
	}
	if err := e.bindCompanion(ctx, req, u, &got); err != nil {
		return err
	}
	return e.realised(ctx, req, got)
}

// pmemChain returns the pmem region of the memdev of a grant and its fsdax
// namespace: the region made or reused, its nd region and namespaces waited
// for, the namespace made for a writable block grant; the region's Pmem
// and the grant's namespace and block device recorded.
func (e *Engine) pmemChain(ctx context.Context, req *GrantRequest, memdev string) (string, *kernel.Namespace, error) {
	ok, err := e.k.Persistent(memdev)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", nil, fmt.Errorf("device %s: %s has no persistent memory", serialText(req.Serial), memdev)
	}
	wctx, cancel := context.WithTimeout(ctx, e.opts.Timeouts.Settle)
	defer cancel()
	if reg := ownRegion(e.records(), req.Serial, state.RegionRam); reg != nil {
		return "", nil, fmt.Errorf("%s: %s is not a region of persistent memory", memdev, reg.Ref())
	}
	region, err := e.ensureRegion(wctx, req, memdev, state.RegionPmem, 0)
	if err != nil {
		return "", nil, err
	}
	var nd string
	var nss []kernel.Namespace
	if err := e.waiting(req.Serial, state.TriggerPrepare, func() error {
		var err error
		if nd, err = e.k.WaitNdRegion(wctx, region); err != nil {
			return err
		}
		nss, err = e.k.Namespaces(wctx, nd)
		return err
	}); err != nil {
		return "", nil, err
	}
	ns, err := e.pmemNamespace(wctx, req, nd, nss)
	if err != nil {
		return "", nil, err
	}
	dev := &state.BlockDevice{Name: ns.BlockDevice, Dev: state.DevNumbers{Major: ns.Major, Minor: ns.Minor}}
	return region, ns, e.commit(ctx, func(r *state.Records) error {
		reg := r.Region(state.RegionRef(region))
		reg.Pmem = &state.Pmem{NdRegion: nd, Namespace: ns.Name, BlockDevice: dev}
		g := r.Grant(req.Ref)
		g.Got.Region, g.Got.Namespace, g.Got.BlockDevice = state.RegionRef(region), ns.Name, dev
		if !reg.SetUp {
			return state.Apply(&state.RegionSetUpTable, &reg.SetUp, true, state.TriggerPrepare)
		}
		return nil
	})
}

// bindCompanion binds the lease of a companion grant of mode fs at its
// target and sets what got records of the bind and the lend.
func (e *Engine) bindCompanion(ctx context.Context, req *GrantRequest, u use, got *state.Got) error {
	if req.BindTarget == "" || req.Asked.Mode != state.ModeFs {
		return nil
	}
	if err := e.bindGrant(ctx, req, u); err != nil {
		return err
	}
	got.Bind = &state.Bind{Target: req.BindTarget, State: state.BindAbsent}
	if err := state.Apply(&state.BindTable, &got.Bind.State, state.BindBound, state.TriggerPrepare); err != nil {
		return err
	}
	if req.Lend != nil {
		lend := *req.Lend
		got.Lend = &lend
	}
	return nil
}

// pmemNamespace returns the fsdax namespace (map mem) of the nd region for
// a grant: the existing one, else a new one for a writable block grant,
// whose intent names the nd region first (ndctl under the engine lock, the
// wait for its block device outside it); every other grant needs one that
// a writer made.
func (e *Engine) pmemNamespace(ctx context.Context, req *GrantRequest, nd string, nss []kernel.Namespace) (*kernel.Namespace, error) {
	if ns := kernel.FsdaxNamespace(nss); ns != nil {
		return ns, nil
	}
	if req.Asked.Mode == state.ModeFs || req.Asked.ReadOnly {
		return nil, fmt.Errorf("device %s: no fsdax namespace in %s: has a writer written the device?", serialText(req.Serial), nd)
	}
	existing := ""
	if len(nss) > 0 {
		existing = nss[0].Name
	}
	if err := e.commit(ctx, func(r *state.Records) error {
		r.Grant(req.Ref).Intent.NdRegion = nd
		return nil
	}); err != nil {
		return nil, err
	}
	var name string
	if err := e.locked(func() error {
		var err error
		name, err = e.k.StartFsdaxNamespace(ctx, nd, existing)
		return err
	}); err != nil {
		return nil, err
	}
	var ns *kernel.Namespace
	err := e.waiting(req.Serial, state.TriggerPrepare, func() error {
		var err error
		ns, err = e.k.WaitFsdaxNamespace(ctx, nd, name)
		return err
	})
	return ns, err
}

// prepareUse returns the use of a grant of the block device dev prepared
// next to others, the other uses of the device on the node: mode block
// gets the read-only flag of the block device, mode fs the node mount of
// its type and access, mounted, reused or made read-write. On error nothing
// of the device changed but what cannot be undone, which is logged.
func (e *Engine) prepareUse(ctx context.Context, req *GrantRequest, dev string, others []use) (use, error) {
	u := use{ref: req.Ref, source: req.Asked.Source, serial: req.Serial, mode: req.Asked.Mode, readOnly: req.Asked.ReadOnly, blockDevice: dev}
	s := serialText(req.Serial)
	blockWriter := slices.ContainsFunc(others, func(o use) bool { return o.mode == state.ModeBlock && o.writer() })
	if blockWriter || (req.Asked.Mode == state.ModeBlock && !req.Asked.ReadOnly && len(others) > 0) {
		return u, fmt.Errorf("device %s: mode block read-write needs the device alone on this node", s)
	}
	if req.Asked.Mode != state.ModeFs {
		if u.writer() {
			// others is empty: every superblock of the device is foreign
			if err := e.checkUnexplained(req.Serial, dev, nil); err != nil {
				return u, err
			}
		}
		writer := u.writer() || firstWriter(others) != nil
		return u, e.setReadOnly(req.Asked.Source, req.Serial, dev, !writer)
	}
	return e.prepareFs(ctx, req, u, others)
}

// prepareFs prepares the use u of mode fs (prepareUse): the type of the
// filesystem, the rules of the type and of one node, then the node mount of
// the access mounted, reused, made read-write or read-only.
func (e *Engine) prepareFs(ctx context.Context, req *GrantRequest, u use, others []use) (use, error) {
	source, serial, dev := req.Asked.Source, req.Serial, u.blockDevice
	sig := &signature{e: e, serial: serialText(serial), dev: dev}
	typ, err := e.fsTypeOf(req, dev, sig)
	if err != nil {
		return u, err
	}
	access, err := e.checkFsType(req, typ, sig)
	if err != nil {
		return u, err
	}
	if err := checkNodeRules(req, access, others); err != nil {
		return u, err
	}
	writer := u.writer() || firstWriter(others) != nil
	mnt := e.nodeMountPath(source, serial, access)
	if err := e.commit(ctx, func(r *state.Records) error {
		r.Grant(req.Ref).Intent.MountPath = mnt
		return nil
	}); err != nil {
		return u, err
	}
	loop, err := e.nodeMount(req, &u, typ, access, mnt, writer, others, sig)
	if err != nil {
		return u, err
	}
	u.access, u.fsType, u.nodeMount, u.loop = access, typ, mnt, loop
	return u, nil
}

// signature reads the signature of a block device once, when a rule needs
// it.
type signature struct {
	e           *Engine
	serial, dev string
	sig         *kernel.FsSignature
}

// get returns the signature of the block device.
func (s *signature) get() (*kernel.FsSignature, error) {
	if s.sig == nil {
		sg, err := s.e.k.ReadFsSignature(s.dev)
		if err != nil {
			return nil, fmt.Errorf("device %s: reading %s: %w", s.serial, s.dev, err)
		}
		s.sig = &sg
	}
	return s.sig, nil
}

// fsTypeOf returns the type of the filesystem of the block device dev of a
// grant: that of a node mount of the device, else of its signature.
func (e *Engine) fsTypeOf(req *GrantRequest, dev string, sig *signature) (string, error) {
	var mounted *kernel.MountInfo
	for _, a := range []string{api.AccessDirect, api.AccessCached} {
		mi, err := e.k.Mounted(e.nodeMountPath(req.Asked.Source, req.Serial, a))
		if err != nil {
			return "", err
		}
		if mi == nil || mounted != nil {
			continue
		}
		if ok, err := e.isDeviceMount(mi, dev, a); err != nil {
			return "", err
		} else if ok {
			mounted = mi
		}
	}
	if mounted != nil {
		if req.Asked.FsType != "" && req.Asked.FsType != mounted.FsType {
			return "", fmt.Errorf("device %s: %s has a filesystem of type %s, not %s", sig.serial, dev, mounted.FsType, req.Asked.FsType)
		}
		return mounted.FsType, nil
	}
	sg, err := sig.get()
	if err != nil {
		return "", err
	}
	return fsType(*sg, sig.serial, dev, req.Asked.FsType)
}

// checkFsType returns the access of a grant of the filesystem type (the
// asked one, else direct for a DAX type, cached for the others), or an
// error if the node does not allow the type, the type mounts no block
// device, a read-only type is asked read-write, a type without DAX is asked
// direct, or a writer on several hosts has no cluster filesystem on
// coherent memory.
func (e *Engine) checkFsType(req *GrantRequest, typ string, sig *signature) (string, error) {
	fail := func(format string, args ...any) (string, error) {
		return "", fmt.Errorf("device "+sig.serial+": "+format, args...)
	}
	allowed := strings.Join(e.opts.FsTypes, ", ")
	if allowed == "" {
		allowed = "none"
	}
	switch {
	case !slices.Contains(e.opts.FsTypes, typ):
		return fail("filesystem type %s is not allowed on this node (fsTypes: %s)", typ, allowed)
	case e.nodevType(req.Asked.Source, typ):
		return fail("filesystem type %s does not mount a block device", typ)
	case !req.Asked.ReadOnly && config.FsTypeReadOnly(typ):
		return fail("%s is a read-only filesystem: set readOnly: true", typ)
	case req.Asked.Access == state.AccessDirect && !config.FsTypeDAX(typ):
		return fail("%s has no DAX: use access cached", typ)
	}
	access := string(req.Asked.Access)
	if access == "" {
		access = api.AccessCached
		if config.FsTypeDAX(typ) {
			access = api.AccessDirect
		}
	}
	if !req.Asked.ReadOnly && !req.SingleHost {
		if err := checkCluster(req, typ, sig); err != nil {
			return "", err
		}
	}
	return access, nil
}

// checkCluster returns an error unless a writer of the type on several
// hosts has a cluster filesystem on coherent memory.
func checkCluster(req *GrantRequest, typ string, sig *signature) error {
	sg, err := sig.get()
	if err != nil {
		return err
	}
	ok, why := cluster(*sg, typ)
	if ok && !req.Facts.Coherent {
		ok, why = false, "the device is not coherent between hosts"
	}
	if !ok {
		return fmt.Errorf("device %s: read-write on several hosts needs a cluster filesystem on coherent memory: %s", sig.serial, why)
	}
	return nil
}

// checkNodeRules returns an error if a grant of the access breaks the rules
// of one node next to the other uses of the device: one access with a
// writer, a writer only with one access.
func checkNodeRules(req *GrantRequest, access string, others []use) error {
	s := serialText(req.Serial)
	other := firstWriter(others)
	accesses := fsAccesses(others)
	switch {
	case other != nil && other.access != access:
		return fmt.Errorf("device %s: it is mounted read-write with access %s on this node: access %s would mount it a second time",
			s, other.access, access)
	case !req.Asked.ReadOnly && len(accesses) == 2:
		return fmt.Errorf("device %s: it is mounted with access %s and %s on this node: a read-write claim needs one access only",
			s, api.AccessDirect, api.AccessCached)
	case !req.Asked.ReadOnly && len(accesses) == 1 && accesses[0] != access:
		return fmt.Errorf("device %s: it is mounted with access %s only on this node: a read-write claim with access %s would mount it a second time",
			s, accesses[0], access)
	}
	return nil
}

// nodeMount returns the loop device of the node mount mnt of a use after it
// mounted it, or checked and reused the mount there: made read-write for a
// use that writes, read-only when no use writes (a read-write superblock
// that a failed release left).
func (e *Engine) nodeMount(req *GrantRequest, u *use, typ, access, mnt string, writer bool, others []use, sig *signature) (string, error) {
	source, serial, dev := req.Asked.Source, req.Serial, u.blockDevice
	mi, err := e.k.Mounted(mnt)
	if err != nil {
		return "", err
	}
	if mi == nil {
		return e.mountFresh(source, serial, dev, access, typ, mnt, writer, nodeMounts(others), sig)
	}
	loop, err := e.checkNodeMount(serial, dev, access, typ, mi)
	if err != nil {
		return "", err
	}
	switch {
	case u.writer() && mi.SuperReadOnly() && !config.FsTypeUpgradable(typ):
		return "", fmt.Errorf("device %s: %s is mounted read-only on this node and cannot be remounted read-write: a read-write claim waits until the read-only claims of the node are gone",
			sig.serial, typ)
	case u.writer() && mi.SuperReadOnly():
		if err := e.upgrade(source, serial, dev, loop, mnt, append(nodeMounts(others), mnt)); err != nil {
			return "", err
		}
	case !writer && !mi.SuperReadOnly():
		// a rw superblock without a writer (a release that failed)
		if err := e.downgrade(source, serial, dev, loop, mnt); err != nil {
			e.errorf(source, "%v", err)
		}
	}
	return loop, nil
}

// mountFresh mounts the node mount mnt that is not mounted (mountNode),
// refusing an ext4 that needs recovery when no use writes.
func (e *Engine) mountFresh(source state.Source, serial state.Serial, dev, access, typ, mnt string, writer bool, explained []string, sig *signature) (string, error) {
	if !writer && typ == config.FsTypeExt4 {
		sg, err := sig.get()
		if err != nil {
			return "", err
		}
		if sg.Ext4NeedsRecovery {
			return "", errNeedsRecovery(sig.serial, typ, dev)
		}
	}
	return e.mountNode(source, serial, dev, access, typ, mnt, writer, explained)
}

// errNeedsRecovery returns the error of a filesystem that a read-only
// mount cannot recover.
func errNeedsRecovery(serial, fsType, dev string) error {
	return fmt.Errorf("device %s: %s on %s needs recovery (it was not unmounted cleanly): a read-only mount cannot recover it, a read-write claim on one node does",
		serial, fsType, dev)
}

// nodevType tells whether the kernel lists the filesystem type as one
// without a block device.
func (e *Engine) nodevType(source state.Source, fsType string) bool {
	data, err := os.ReadFile(e.opts.Filesystems)
	if err != nil {
		klog.V(3).Infof("%s: %v", e.driver(source), err)
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "nodev" && f[1] == fsType {
			return true
		}
	}
	return false
}

// recordUse records the node mount of a use of mode fs in its region: a
// new mount (ABSENT -> MOUNTED_RO or MOUNTED_RW), the grant a user of an
// existing one, read-write iff writer (a use of the device writes).
func (e *Engine) recordUse(ctx context.Context, req *GrantRequest, region string, u use, writer bool) error {
	if u.nodeMount == "" {
		return nil
	}
	return e.commit(ctx, func(r *state.Records) error {
		reg := r.Region(state.RegionRef(region))
		m := reg.Mount(state.Access(u.access))
		if m == nil {
			reg.Mounts = append(reg.Mounts, state.Mount{Access: state.Access(u.access), Path: u.nodeMount, State: state.MountAbsent})
			m = &reg.Mounts[len(reg.Mounts)-1]
		}
		want := state.MountedRO
		if writer {
			want = state.MountedRW
		}
		if err := state.Apply(&state.MountTable, &m.State, want, state.TriggerPrepare); err != nil {
			return err
		}
		m.Path, m.Loop, m.FsType, m.Writer = u.nodeMount, u.loop, u.fsType, writer
		m.Users = addRef(m.Users, req.Ref)
		g := r.Grant(req.Ref)
		g.Got.Mount, g.Got.MountPath, g.Got.Loop, g.Got.FsType = state.Access(u.access), u.nodeMount, u.loop, u.fsType
		return nil
	})
}

// mountNode returns the loop device of a cached node mount after it
// mounted the filesystem of the type on the block device dev at the node
// mount mnt for the access: read-write for a writer, else read-only on a
// read-only block device; access direct on the block device, cached on a
// direct-I/O loop device over it. Read-only types are mounted with
// mount(2) on a read-only loop device. A writable type is not mounted
// while the device has a superblock that the node mounts explained do not
// have.
func (e *Engine) mountNode(source state.Source, serial state.Serial, dev, access, fsType, mnt string, writer bool, explained []string) (string, error) {
	readOnlyType := config.FsTypeReadOnly(fsType)
	if !readOnlyType {
		if err := e.checkUnexplained(serial, dev, explained); err != nil {
			return "", err
		}
	}
	ro := !writer || readOnlyType
	data := config.FsMountData(fsType, access, ro)
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return "", err
	}
	if err := e.setReadOnly(source, serial, dev, ro); err != nil {
		e.removeMountDir(source, mnt)
		return "", err
	}
	src := dev
	var loop kernel.Loop
	if access == api.AccessCached {
		l, err := e.attachCachedLoop(source, serial, dev, mnt, readOnlyType, ro)
		if err != nil {
			return "", err
		}
		loop, src = l, l.Path()
	}
	if err := e.mountFs(source, serial, dev, src, fsType, mnt, ro, data, loop); err != nil {
		return "", err
	}
	if access == api.AccessDirect && config.FsTypeDAX(fsType) {
		if err := e.verifyNodeDax(source, serial, dev, fsType, mnt); err != nil {
			return "", err
		}
	}
	what := fsType + ", " + map[bool]string{true: "ro", false: "rw"}[ro]
	if len(data) > 0 {
		what += ", " + strings.Join(data, ",")
	}
	e.logf(source, "device %s: mounted %s at %s (%s)", serialText(serial), src, mnt, what)
	if loop != nil {
		return loop.Path(), nil
	}
	return "", nil
}

// mountFs mounts the filesystem of the type on src (the block device dev,
// or the loop device loop over it) at mnt: mount(2) for a read-only type,
// the new mount API read-only (ro) or read-write for the others. On an
// error the loop device is detached and the directory removed; then the
// mount keeps the autoclear loop device.
func (e *Engine) mountFs(source state.Source, serial state.Serial, dev, src, fsType, mnt string, ro bool, data []string, loop kernel.Loop) error {
	s := serialText(serial)
	err := e.locked(func() error {
		if config.FsTypeReadOnly(fsType) {
			return e.k.Mount(src, mnt, fsType, fsMountFlags, strings.Join(data, ","))
		}
		return e.k.FsMount(src, mnt, fsType, !ro, data)
	})
	if err != nil {
		if loop != nil {
			e.detachLoop(source, serial, loop)
		}
		e.removeMountDir(source, mnt)
		if ro && errors.Is(err, syscall.EROFS) {
			return errNeedsRecovery(s, fsType, dev)
		}
		return fmt.Errorf("device %s: %s has no %s filesystem: %w", s, dev, fsType, err)
	}
	if loop != nil {
		if err := loop.Release(false); err != nil {
			e.warnf(source, "device %s: closing %s: %v", s, loop.Path(), err)
		}
	}
	return nil
}

// attachCachedLoop returns a new direct-I/O loop device over the block
// device dev for a cached node mount at mnt, read-only for a read-only type,
// else with the read-only flag ro; on an error nothing of it is left.
func (e *Engine) attachCachedLoop(source state.Source, serial state.Serial, dev, mnt string, readOnlyType, ro bool) (kernel.Loop, error) {
	var l kernel.Loop
	err := e.locked(func() error {
		var err error
		l, err = e.k.AttachLoop(dev, !readOnlyType)
		return err
	})
	if err != nil {
		e.removeMountDir(source, mnt)
		return nil, fmt.Errorf("device %s: a loop device over %s: %w", serialText(serial), dev, err)
	}
	if !readOnlyType {
		if err := e.setReadOnly(source, serial, l.Path(), ro); err != nil {
			e.detachLoop(source, serial, l)
			e.removeMountDir(source, mnt)
			return nil, err
		}
	}
	return l, nil
}

// verifyNodeDax returns an error, after it unmounted the node mount mnt
// again, when the mount of the DAX type is without dax=always: another
// mount of the block device on the node has the superblock, and its
// options win.
func (e *Engine) verifyNodeDax(source state.Source, serial state.Serial, dev, fsType, mnt string) error {
	s := serialText(serial)
	mi, err := e.k.Mounted(mnt)
	if err == nil && (mi == nil || !mi.HasSuperOpt(daxAlways)) {
		err = fmt.Errorf("device %s: %s on %s was mounted without DAX", s, fsType, dev)
	}
	if err == nil {
		return nil
	}
	if uerr := e.locked(func() error { return e.k.Unmount(mnt) }); uerr != nil {
		e.errorf(source, "device %s: unmounting %s: %v", s, mnt, uerr)
	} else {
		e.removeMountDir(source, mnt)
	}
	return err
}

// detachLoop detaches a loop device that no mount uses.
func (e *Engine) detachLoop(source state.Source, serial state.Serial, loop kernel.Loop) {
	if err := e.locked(func() error { return loop.Release(true) }); err != nil {
		e.errorf(source, "device %s: detaching %s: %v", serialText(serial), loop.Path(), err)
	}
}

// upgrade makes the read-only superblock of the node mount mnt read-write:
// the block device, then the loop device of a cached mount, then the
// superblock. On error both are read-only again. It refuses while the
// device has a superblock that the node mounts explained do not have.
func (e *Engine) upgrade(source state.Source, serial state.Serial, dev, loop, mnt string, explained []string) error {
	s := serialText(serial)
	if err := e.checkUnexplained(serial, dev, explained); err != nil {
		return err
	}
	fail := func(err error) error {
		if loop != "" {
			if rerr := e.setReadOnly(source, serial, loop, true); rerr != nil {
				e.errorf(source, "%v", rerr)
			}
		}
		if rerr := e.setReadOnly(source, serial, dev, true); rerr != nil {
			e.errorf(source, "%v", rerr)
		}
		return fmt.Errorf("device %s: remounting %s read-write: %w", s, mnt, err)
	}
	if err := e.setReadOnly(source, serial, dev, false); err != nil {
		return fail(err)
	}
	if loop != "" {
		if err := e.setReadOnly(source, serial, loop, false); err != nil {
			return fail(err)
		}
	}
	if err := e.locked(func() error { return e.k.Reconfigure(mnt, true) }); err != nil {
		return fail(err)
	}
	e.logf(source, "device %s: remounted %s read-write", s, mnt)
	return nil
}

// downgrade makes the read-write superblock of the node mount mnt
// read-only: its data written, the superblock, then the loop device of a
// cached mount, then the block device.
func (e *Engine) downgrade(source state.Source, serial state.Serial, dev, loop, mnt string) error {
	s := serialText(serial)
	if err := e.locked(func() error { return e.k.Syncfs(mnt) }); err != nil {
		return fmt.Errorf("device %s: remounting %s read-only: %w", s, mnt, err)
	}
	if err := e.locked(func() error { return e.k.Reconfigure(mnt, false) }); err != nil {
		return fmt.Errorf("device %s: remounting %s read-only: %w", s, mnt, err)
	}
	e.logf(source, "device %s: remounted %s read-only", s, mnt)
	if loop != "" {
		if err := e.setReadOnly(source, serial, loop, true); err != nil {
			return err
		}
	}
	return e.setReadOnly(source, serial, dev, true)
}

// setReadOnly sets the read-only flag of the block device dev of the
// memdev with the serial, when it differs, and logs the change. A block
// device is never made read-only while a read-write superblock is on it,
// or on a loop device over it. A block device that is gone is not an error.
func (e *Engine) setReadOnly(source state.Source, serial state.Serial, dev string, readOnly bool) error {
	if dev == "" {
		return nil
	}
	s := serialText(serial)
	changed := false
	if err := e.locked(func() error {
		var err error
		changed, err = e.k.SetBlockDeviceReadOnly(dev, readOnly)
		return err
	}); err != nil {
		return fmt.Errorf("device %s: %w", s, err)
	}
	if changed {
		e.logf(source, "device %s: %s %s", s, dev, roWord(readOnly))
	}
	return nil
}

// checkUnexplained returns an error if the block device dev of the memdev
// with the serial, or a loop device over it, has a superblock anywhere on
// the node that is not that of one of the node mounts explained (the node
// mounts of the uses of the device), or if its superblocks cannot be read.
func (e *Engine) checkUnexplained(serial state.Serial, dev string, explained []string) error {
	s := serialText(serial)
	sbs, err := e.k.Superblocks(dev)
	if err != nil {
		return fmt.Errorf("device %s: the superblocks of %s: %w", s, dev, err)
	}
	known := map[string]bool{}
	for _, mnt := range explained {
		mi, err := e.k.Mounted(mnt)
		if err != nil {
			return err
		}
		if mi != nil {
			known[mi.Source] = true
		}
	}
	for _, sb := range sbs {
		if !known[sb.Device] {
			return fmt.Errorf("device %s: %s has a superblock that no claim of this node explains (%s mounted %s in %s): it is not used until that mount is gone",
				s, dev, sb.Source, map[bool]string{true: "ro", false: "rw"}[sb.ReadOnly], sb.Where)
		}
	}
	return nil
}

// isDeviceMount tells whether a mount is one of the block device dev for
// the access: of dev itself (direct), of a loop device over it (cached).
func (e *Engine) isDeviceMount(mi *kernel.MountInfo, dev, access string) (bool, error) {
	if access != api.AccessCached {
		return mi.Source == dev, nil
	}
	if e.loopOf(mi) == "" {
		return false, nil
	}
	backing, err := e.k.LoopBackingFile(mi.Source)
	if err != nil {
		return false, err
	}
	return kernel.SameDevice(backing, dev), nil
}

// checkNodeMount returns the loop device of an existing cached node mount,
// or an error if the mount at the node mount is not the filesystem of the
// type ("": any) of the block device for the access: on the block device
// (direct, with dax=always for the DAX types), on a loop device over it
// (cached).
func (e *Engine) checkNodeMount(serial state.Serial, dev, access, fsType string, mi *kernel.MountInfo) (string, error) {
	s := serialText(serial)
	ok, err := e.isDeviceMount(mi, dev, access)
	if err != nil {
		return "", err
	}
	if !ok {
		want := dev
		if access == api.AccessCached {
			want = "a loop device over " + dev
		}
		return "", fmt.Errorf("device %s: %s is a %s mount of %s, not of %s", s, mi.Target, mi.FsType, mi.Source, want)
	}
	if fsType != "" && mi.FsType != fsType {
		return "", fmt.Errorf("device %s: %s is a %s mount of %s, not %s", s, mi.Target, mi.FsType, mi.Source, fsType)
	}
	if access == api.AccessCached {
		return mi.Source, nil
	}
	if config.FsTypeDAX(mi.FsType) && !mi.HasSuperOpt(daxAlways) {
		return "", fmt.Errorf("device %s: %s on %s was mounted without DAX", s, mi.FsType, dev)
	}
	return "", nil
}

// removeMountDir removes the directory of a mount that is not mounted.
func (e *Engine) removeMountDir(source state.Source, mnt string) {
	if err := os.Remove(mnt); err != nil && !errors.Is(err, os.ErrNotExist) {
		e.warnf(source, "removing %s: %v", mnt, err)
	}
}

// unmountNode unmounts a node mount if it is mounted, never detaching it,
// and removes its directory. A busy mount is an error.
func (e *Engine) unmountNode(source state.Source, serial state.Serial, mnt string) error {
	mi, err := e.k.Mounted(mnt)
	if err != nil {
		return err
	}
	if mi != nil {
		if err := e.locked(func() error { return e.k.Unmount(mnt) }); err != nil {
			return fmt.Errorf("device %s: unmounting %s: %w", serialText(serial), mnt, err)
		}
		e.logf(source, "device %s: unmounted %s", serialText(serial), mnt)
	}
	e.removeMountDir(source, mnt)
	return nil
}

// releaseUses releases the uses gone of the memdev with the serial while
// the uses remaining stay: the node mounts that no remaining use has are
// unmounted, the superblock of a node mount whose remaining uses have no
// writer is made read-only, and so are the block devices when no writer
// remains (the block device of the remaining uses only when it is the one
// of the region now). An error (a busy unmount or downgrade) stops it.
func (e *Engine) releaseUses(source state.Source, serial state.Serial, gone, remaining []use) error {
	used := nodeMounts(remaining)
	for _, mnt := range nodeMounts(gone) {
		if slices.Contains(used, mnt) {
			continue
		}
		if err := e.unmountNode(source, serial, mnt); err != nil {
			return err
		}
	}
	if len(remaining) == 0 || firstWriter(remaining) != nil {
		return nil
	}
	// the recorded block device may be another device's now
	dev := e.verified(source, serial, blockDeviceOf(remaining))
	var loops []string
	for _, mnt := range used {
		mi, err := e.k.Mounted(mnt)
		if err != nil || mi == nil {
			continue
		}
		loop := e.loopOf(mi)
		if loop != "" {
			loops = append(loops, loop)
		}
		if !mi.SuperReadOnly() {
			if err := e.downgrade(source, serial, dev, loop, mnt); err != nil {
				return err
			}
		}
	}
	for _, loop := range loops {
		if err := e.setReadOnly(source, serial, loop, true); err != nil {
			return err
		}
	}
	return e.setReadOnly(source, serial, dev, true)
}

// verified returns dev when it is the block device of the fsdax namespace
// of the region of the memdev with the serial now as recorded, else ""
// (logged).
func (e *Engine) verified(source state.Source, serial state.Serial, dev string) string {
	if dev == "" {
		return dev
	}
	if err := e.checkUseBlockDevice(serial, dev); err != nil {
		e.warnf(source, "device %s: not changing the read-only flag of %s: %v", serialText(serial), dev, err)
		return ""
	}
	return dev
}

// waitNoHolder waits until the deadline until nothing holds the block
// device of a persistent memdev: no mount, no loop device, no exclusive
// open, outside the engine lock with the memdev Busy.
//
// This check is what keeps a region with a live superblock from being
// released, and it must stay: an umount succeeds while a bind of the same
// superblock exists elsewhere, and an rmdir of a directory that is a mount
// point in another mount namespace succeeds and detaches those mounts
// lazily, so a lease bind can be gone from the driver's view and still hold
// the device.
func (e *Engine) waitNoHolder(ctx context.Context, source state.Source, serial state.Serial, dev string, deadline time.Time, trigger state.Trigger) error {
	s := serialText(serial)
	return e.waiting(serial, trigger, func() error {
		for {
			holder, err := e.k.Holder(dev)
			if err != nil {
				return err
			}
			if holder == "" {
				return nil
			}
			if !time.Now().Before(deadline) {
				e.warnf(source, "device %s: %s is held: %s", s, dev, holder)
				return fmt.Errorf("device %s: %s is still in use", s, dev)
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("device %s: %s is still in use: %w", s, dev, ctx.Err())
			case <-time.After(holderPoll):
			}
		}
	})
}

// checkUseBlockDevice returns an error if blockDev is not the block device
// of the fsdax namespace of the region of the memdev with the serial now,
// as a prepared grant recorded it.
func (e *Engine) checkUseBlockDevice(serial state.Serial, blockDev string) error {
	r := e.records()
	for i := range r.Grants {
		g := &r.Grants[i]
		if g.Serial == serial && g.Got.BlockDevice != nil && g.Got.BlockDevice.Name == blockDev {
			return e.checkBlockDevice(g)
		}
	}
	return fmt.Errorf("device %s: no prepared device has %s", serialText(serial), blockDev)
}

// checkBlockDevice returns an error if the block device of a grant is not
// the one of the fsdax namespace of the region of its memdev now: its
// name, numbers and namespace must be those that the Prepare recorded.
func (e *Engine) checkBlockDevice(g *state.Grant) error {
	s := serialText(g.Serial)
	nss, nd, err := e.regionNamespaces(g.Serial)
	if err != nil {
		return fmt.Errorf("device %s: %w", s, err)
	}
	cur := kernel.FsdaxNamespace(nss)
	bd := g.Got.BlockDevice
	switch {
	case cur == nil:
		return fmt.Errorf("device %s: no fsdax namespace in %s", s, nd)
	case bd == nil || cur.BlockDevice != bd.Name || cur.Name != g.Got.Namespace || cur.Major != bd.Dev.Major || cur.Minor != bd.Dev.Minor:
		var name string
		var major, minor int
		if bd != nil {
			name, major, minor = bd.Name, bd.Dev.Major, bd.Dev.Minor
		}
		return fmt.Errorf("device %s: its fsdax namespace is %s with %s (%d:%d), not %s with %s (%d:%d) as prepared",
			s, cur.Name, cur.BlockDevice, cur.Major, cur.Minor, g.Got.Namespace, name, major, minor)
	}
	return nil
}

// regionNamespaces returns the namespaces of the nd region of the region of
// the memdev with the serial and the nd region, waiting at most
// Timeouts.Restore for them to settle.
func (e *Engine) regionNamespaces(serial state.Serial) ([]kernel.Namespace, string, error) {
	memdev, err := e.k.FindMemdev(uint64(serial))
	if err != nil {
		return nil, "", err
	}
	regions := e.k.Regions(memdev)
	if len(regions) == 0 {
		return nil, "", fmt.Errorf("%s has no region", memdev)
	}
	nd, err := e.k.NdRegionOf(regions[0])
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.opts.Timeouts.Restore)
	defer cancel()
	nss, err := e.k.Namespaces(ctx, nd)
	return nss, nd, err
}

// currentBlockDevice returns the block device of the fsdax namespace of the
// region of the memdev with the serial, else of another namespace of it
// with a block device, "" if there is none.
func (e *Engine) currentBlockDevice(serial state.Serial) string {
	nss, _, err := e.regionNamespaces(serial)
	if err != nil {
		if !errors.Is(err, kernel.ErrNotFound) {
			klog.Warningf("serial %s: %v", serialText(serial), err)
		}
		return ""
	}
	if ns := kernel.FsdaxNamespace(nss); ns != nil {
		return ns.BlockDevice
	}
	for _, ns := range nss {
		if ns.BlockDevice != "" {
			return ns.BlockDevice
		}
	}
	return ""
}

// bindGrant binds the node mount of the use of mode fs of a companion grant
// at its bind target, or finds it bound there, its intent named first.
func (e *Engine) bindGrant(ctx context.Context, req *GrantRequest, u use) error {
	if !api.ValidName(filepath.Base(req.BindTarget)) {
		return fmt.Errorf("grant %s: invalid name %q", req.Ref, filepath.Base(req.BindTarget))
	}
	found, err := e.bindLease(&u, req.BindTarget, func(target string) bool { return e.bindUsed(target, req.Ref) })
	if err != nil {
		return err
	}
	if found {
		e.logf(req.Asked.Source, "grant %s: %s is bound at %s already", req.Ref, u.nodeMount, req.BindTarget)
	} else {
		e.logf(req.Asked.Source, "grant %s: bound %s at %s", req.Ref, u.nodeMount, req.BindTarget)
	}
	return nil
}

// bindUsed tells whether a prepared grant other than except has the lease
// bind target.
func (e *Engine) bindUsed(target string, except state.GrantRef) bool {
	r := e.records()
	for i := range r.Grants {
		g := &r.Grants[i]
		if g.Ref != except && g.Got.Bind != nil && g.Got.Bind.Target == target && prepared(g) {
			return true
		}
	}
	return false
}

// bindLease binds the node mount of an fs use at target and reports
// whether the bind was there already: read-only binds of writable types by
// a clone with the read-only attribute, others by MS_BIND, so that the
// bind and its propagated copies have the flags of the node mount. The bind
// must be a mount of the root of the node mount of its type with the flags
// ro (rw for a use that writes), nosuid and nodev; a new bind without them
// is unmounted again; another mount at the target, or one that otherBind
// says is the bind of another prepared grant, is neither used nor
// unmounted. A new bind that fails the check and cannot be unmounted is
// recorded as stale.
func (e *Engine) bindLease(u *use, target string, otherBind func(string) bool) (bool, error) {
	s := serialText(u.serial)
	node, err := e.k.Mounted(u.nodeMount)
	switch {
	case err != nil:
		return false, err
	case node == nil:
		return false, fmt.Errorf("device %s: %s is not mounted", s, u.nodeMount)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return false, err
	}
	mi, err := e.k.Mounted(target)
	if err != nil {
		return false, err
	}
	if mi != nil {
		return true, checkExistingBind(u, target, mi, node, otherBind)
	}
	err = e.locked(func() error {
		if u.readOnly && !config.FsTypeReadOnly(node.FsType) {
			return e.k.BindReadOnly(u.nodeMount, target)
		}
		return e.k.Mount(u.nodeMount, target, "", syscall.MS_BIND, "")
	})
	if err != nil {
		e.removeMountDir(u.source, target)
		return false, fmt.Errorf("device %s: binding %s at %s: %w", s, u.nodeMount, target, err)
	}
	return false, e.verifyBind(u, target, node)
}

// checkExistingBind returns an error unless the mount mi at target is the
// lease bind of the node mount node of the use, and of no other prepared
// grant (otherBind).
func checkExistingBind(u *use, target string, mi, node *kernel.MountInfo, otherBind func(string) bool) error {
	s := serialText(u.serial)
	switch {
	case !isLeaseBind(mi, node, u.readOnly):
		return fmt.Errorf("device %s: %s is a %s mount of %s, not of %s", s, target, mi.FsType, mi.Source, u.nodeMount)
	case otherBind != nil && otherBind(target):
		return fmt.Errorf("device %s: %s is the bind of another lease", s, target)
	}
	return nil
}

// verifyBind returns an error, after it unmounted the new bind at target
// again (or recorded it stale when that fails), when the bind is not the
// lease bind of the node mount node of the use.
func (e *Engine) verifyBind(u *use, target string, node *kernel.MountInfo) error {
	s := serialText(u.serial)
	mi, err := e.k.Mounted(target)
	if err == nil && (mi == nil || !isLeaseBind(mi, node, u.readOnly)) {
		err = fmt.Errorf("device %s: the bind of %s at %s is not a %s nosuid nodev %s mount", s, u.nodeMount, target, roWord(u.readOnly), node.FsType)
	}
	if err == nil {
		return nil
	}
	if uerr := e.locked(func() error { return e.k.Unmount(target) }); uerr != nil {
		e.errorf(u.source, "device %s: unmounting %s: %v; trying again at the next release", s, target, uerr)
		e.addStale(u.serial, target, state.StaleBind)
	} else {
		e.removeMountDir(u.source, target)
	}
	return err
}

// isLeaseBind tells whether a mount is a bind of the node mount node with
// the flags of a lease bind, ro or rw by readOnly.
func isLeaseBind(mi, node *kernel.MountInfo, readOnly bool) bool {
	if mi.FsType != node.FsType || mi.Source != node.Source || mi.Root != node.Root {
		return false
	}
	for _, f := range []string{map[bool]string{true: "ro", false: "rw"}[readOnly], "nosuid", "nodev"} {
		if !slices.Contains(mi.MountFlags, f) {
			return false
		}
	}
	return true
}

// leaseBindType tells whether a mount may be a lease bind: of a block
// device, of a filesystem type that mode fs mounts.
func (e *Engine) leaseBindType(mi *kernel.MountInfo) bool {
	return strings.HasPrefix(mi.Source, e.devRoot()+"/") && (config.KnownFsType(mi.FsType) || slices.Contains(e.opts.FsTypes, mi.FsType))
}

// unbind unmounts a lease bind target, never detaching it, and removes its
// directory. A bind that cannot be unmounted (busy while the borrower has
// files of it open or mapped), or that has another mount on it than a
// lease bind, is an error.
func (e *Engine) unbind(source state.Source, what, target string) error {
	for i := 0; ; i++ {
		mi, err := e.k.Mounted(target)
		if err == nil && mi == nil {
			break
		}
		if err == nil && !e.leaseBindType(mi) {
			return fmt.Errorf("%s: %s is a %s mount of %s, not a lease bind", what, target, mi.FsType, mi.Source)
		}
		if err == nil && i >= maxUnbinds {
			err = errors.New("still mounted")
		}
		if err == nil {
			err = e.locked(func() error { return e.k.Unmount(target) })
		}
		if err != nil {
			return fmt.Errorf("%s: unmounting %s: %w", what, target, err)
		}
		e.logf(source, "%s: unbound %s", what, target)
	}
	e.removeMountDir(source, target)
	return nil
}

// addStale records a node mount or lease bind of the memdev with the
// serial whose unmount failed, once, in a lazy commit; a memdev without a
// record keeps nothing.
func (e *Engine) addStale(serial state.Serial, path string, kind state.StaleKind) {
	err := e.commitLazy(context.Background(), func(r *state.Records) error {
		if m := r.Memdev(serial); m != nil {
			m.Stale = addRef(m.Stale, state.StalePath{Path: path, Kind: kind})
		}
		return nil
	})
	if err != nil {
		klog.Errorf("engine: memdev %s: recording stale %s %s: %v", serial, kind, path, err)
	}
}
