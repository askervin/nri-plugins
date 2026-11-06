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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/pkg/cxl/api"

	"github.com/containers/nri-plugins/pkg/cxl/memctl"
)

// The local allocator gives the memory of node-local CXL memdevs (the
// memdev devices of cxl.nri.io) to claims. It creates one devdax
// region per memdev on first use and destroys it after the last use. Every
// allocation result gets a slice of the region: a dax device whose size is
// a multiple of the memory block size. A numa slice is bound to kmem and
// onlined movable, its memory belongs to the NUMA node of the region that
// all numa slices of the memdev share; a dax slice is a devdax device of
// its own. Slices of both modes share a region. A shared memdev (listed in
// sharedDevices) is never sliced: all its claims get the first dax device
// of its region, whose content is zeroed once when the region is created and
// never while it exists, and its region stays while
// the memdev is configured shared. See docs/memory/cxl/local.md.

const (
	// localStateFileName is the state file of the local allocator in the
	// plugin data directory of cxl.nri.io.
	localStateFileName = "localDevices.json"
	// orphanOwner owns the slices whose release failed (no claim UID is
	// "-"): they are never handed out, and released again before the
	// next slice of their memdev.
	orphanOwner = "-"
	// cxlRegionAlign is the alignment of the physical address of a CXL
	// region in its window: a region starts at most block size -
	// cxlRegionAlign after a memory block boundary.
	cxlRegionAlign = 256 << 20
	// bootIDFile identifies the running kernel (under the sysfs root).
	bootIDFile = "proc/sys/kernel/random/boot_id"
	// rollbackTimeout bounds the cleanup after a failure.
	rollbackTimeout = time.Minute
	// zeroChunk is the size of the windows in which a slice is zeroed.
	zeroChunk = 64 << 20
)

// errNoRoom is returned when the dax region of a memdev has less free
// memory than a slice needs.
var errNoRoom = errors.New("no room for the slice")

// localSlice is the memory of one allocation result on a local memdev: a
// dax device of the region of the memdev.
type localSlice struct {
	Request string `json:"request"`
	// Result is the index of the allocation result in the claim (of a
	// persistent device).
	Result int    `json:"result,omitempty"`
	Region string `json:"region"`
	// Mode is api.ModeNUMA (the memory of the slice is system RAM of the
	// NUMA node of the region) or api.ModeDax (a devdax device).
	Mode string `json:"mode"`
	// Size is the slice size in bytes.
	Size uint64 `json:"size"`
	// Dax is the dax device of the slice (daxX.Y).
	Dax       string `json:"dax,omitempty"`
	DaxDevice string `json:"daxDevice,omitempty"` // dax: /dev/daxX.Y
	Major     int    `json:"major,omitempty"`
	Minor     int    `json:"minor,omitempty"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
	// The use of a persistent device by the allocation result (Mode
	// api.ModeBlock or api.ModeFs, Size the size of the block device,
	// ReadOnly effective): fs: the effective access, the type and the node
	// mount of the filesystem, the loop device of a cached node mount and
	// the directory in the containers.
	Access     string `json:"access,omitempty"`
	FsType     string `json:"fsType,omitempty"`
	NodeMount  string `json:"nodeMount,omitempty"`
	LoopDevice string `json:"loopDevice,omitempty"`
	Path       string `json:"path,omitempty"`
}

// localDevice is a local memdev that the allocator uses.
type localDevice struct {
	Serial    uint64 `json:"serial"`
	SerialHex string `json:"serialHex"`
	Memdev    string `json:"memdev"`
	// Region is the region that the allocator created on the memdev, ""
	// while it is created: then the region on the memdev that Creating
	// names is the allocator's, or every region on the memdev if Creating
	// is "" (the memdev had none, checkRegions).
	Region string `json:"region,omitempty"`
	// Creating is the region that cxl create-region creates for the
	// device while Region is "", recorded before it runs (regionNote); ""
	// if its name is not known (a record of an older plugin).
	Creating string `json:"creating,omitempty"`
	Node     int    `json:"node"` // NUMA node of the memory of the region, -1 if unknown
	// Dax is the first dax device of the region, "" while the region is
	// not set up: its creation failed or was cut, or it was kept for
	// claims whose Prepare did not finish (keepRegion), until setUpRegion.
	Dax string `json:"dax,omitempty"`
	// Shared is true for a shared memdev: every claim has the whole dax
	// device Dax; of a persistent device, sharedDevices listed it when its
	// region was created.
	Shared bool `json:"shared,omitempty"`
	// Persistent is true for a memdev of persistent memory: its region is
	// a pmem region that all claims use, never sliced, zeroed or onlined.
	Persistent bool `json:"persistent,omitempty"`
	// NdRegion is the nvdimm region of the pmem region, "" while the
	// region is not set up (the role of Dax of other devices).
	NdRegion string `json:"ndRegion,omitempty"`
	// Namespace is the fsdax namespace (map mem) of NdRegion, BlockDevice
	// its block device (/dev/pmemK) and BlockMajor, BlockMinor its
	// numbers; "" while there is none.
	Namespace   string `json:"namespace,omitempty"`
	BlockDevice string `json:"blockDevice,omitempty"`
	BlockMajor  int    `json:"blockMajor,omitempty"`
	BlockMinor  int    `json:"blockMinor,omitempty"`
	// Claims are the slices of the claims that use the memdev, by claim
	// UID. A claim without slices holds the region: the claim whose
	// Acquire creates the region (recorded before it, so that a Prepare
	// cut in the creation leaves its claim), and a claim whose Prepare
	// did not finish, for its Unprepare or its Prepare again
	// (keepRegion).
	Claims map[string][]*localSlice `json:"claims"`
}

// claimUIDs returns the UIDs of the claims of the device, without
// orphanOwner, in ascending order.
func (d *localDevice) claimUIDs() []string {
	uids := []string{}
	for _, uid := range slices.Sorted(maps.Keys(d.Claims)) {
		if uid != orphanOwner {
			uids = append(uids, uid)
		}
	}
	return uids
}

// localState is the content of the state file: the devices the allocator
// uses, and the boot of the kernel that they belong to.
type localState struct {
	BootID  string         `json:"bootID"`
	Devices []*localDevice `json:"devices"`
}

// localAllocator creates and destroys the regions and dax slices of local
// memdevs for claims, and keeps its state in a file.
type localAllocator struct {
	mem        *memctl.Manager
	stateFile  string
	bootID     string // "" if unknown
	retryDelay time.Duration
	// zero writes zeros to the memory of a dax device: major, minor,
	// size, align.
	zero    func(major, minor int, size, align uint64) error
	mu      sync.Mutex
	devices map[uint64]*localDevice // by serial
	// shared has the serials of the memdevs that the configuration
	// declares shared: their idle regions are kept.
	shared map[uint64]bool
	// fence gets the NUMA nodes of numa slices before their memory goes
	// online, nil for none.
	fence *nodeFence
	// configured returns the configured usable size of a memdev (0: all
	// of it), nil for none; verify runs the address line probe on new
	// regions. probesFile keeps the probe results.
	configured func(memdev string, serial uint64) uint64
	verify     bool
	probesFile string
	// probe runs the address line probe on a dax device.
	probe func(dax string) (*memctl.Aliasing, error)
	// poolGuard refuses a memdev that is a pool device (or may be one),
	// checked before the allocator creates a region on a memdev or
	// onlines its memory; nil for no check.
	poolGuard func(ctx context.Context, serial uint64) error

	// usesSnap is a snapshot of the use of the devices, and blockSize
	// the memory block size in bytes (0 if unknown), for the publisher.
	// They have their own lock so that a rescan never waits for a
	// Prepare.
	snapMu    sync.Mutex
	usesSnap  map[uint64]localUse
	blockSize uint64
	// probes are the results of the address line probes, by serial.
	probes map[uint64]localProbe

	// pn is the shared persistent code of the node mounts of persistent
	// memdevs, nil until SetPersistent. badBlock has the persistent
	// devices whose block device the start found changed, by serial.
	pn       *persistentNode
	badBlock map[uint64]error
}

// localUse is how the allocator uses a memdev.
type localUse struct {
	// Shared is true when the memdev is used as a shared device, false
	// when it is sliced; of a persistent device, whether it is shared.
	Shared bool
	// Persistent is true when the memdev is used as a persistent device.
	Persistent bool
	// Claims are the UIDs of the claims that use the memdev.
	Claims []string
}

// localSnapshot is what the publisher of local memdevs needs from the
// local allocator.
type localSnapshot struct {
	// Uses are the uses of the memdevs that the allocator uses or is
	// preparing, by serial.
	Uses map[uint64]localUse
	// BlockSize is the memory block size in bytes, 0 if unknown.
	BlockSize uint64
	// Probed are the usable sizes that the address line probe found, by
	// serial.
	Probed map[uint64]uint64
}

// probed returns the usable size that the address line probe found for
// the memdev with the serial, 0 if none.
func (l *localSnapshot) probed(serial uint64) uint64 {
	if l == nil {
		return 0
	}
	return l.Probed[serial]
}

// uses tells whether the allocator uses the memdev with the serial.
func (l *localSnapshot) uses(serial uint64) bool {
	if l == nil {
		return false
	}
	_, ok := l.Uses[serial]
	return ok
}

// use returns how the allocator uses the memdev with the serial, and
// whether it uses it.
func (l *localSnapshot) use(serial uint64) (localUse, bool) {
	if l == nil {
		return localUse{}, false
	}
	u, ok := l.Uses[serial]
	return u, ok
}

// newLocalAllocator returns a local allocator with its state loaded from
// stateFile. The devices of a state from another boot than bootID are
// dropped without touching them ("" bootID: the boot is unknown, the state
// is kept).
func newLocalAllocator(mem *memctl.Manager, stateFile, bootID string) (*localAllocator, error) {
	a := &localAllocator{
		mem:        mem,
		stateFile:  stateFile,
		bootID:     bootID,
		retryDelay: defaultRegionRetryDelay,
		zero: func(major, minor int, size, align uint64) error {
			return zeroDax(mem.DevRoot, major, minor, size, align)
		},
		devices:    map[uint64]*localDevice{},
		shared:     map[uint64]bool{},
		verify:     true,
		probe:      mem.ProbeAliasing,
		probesFile: filepath.Join(filepath.Dir(stateFile), localProbesFileName),
	}
	if err := a.load(); err != nil {
		return nil, err
	}
	if err := a.loadProbes(); err != nil {
		return nil, err
	}
	if _, err := a.readBlockSize(); err != nil {
		klog.Warningf("local: %v: local memory devices are not published until the memory block size is known", err)
	}
	a.updateSnapshot()
	return a, nil
}

// readBlockSize returns the memory block size from sysfs and keeps it for
// Snapshot.
func (a *localAllocator) readBlockSize() (uint64, error) {
	bs, err := a.mem.MemoryBlockSize()
	if err != nil {
		return 0, fmt.Errorf("memory block size: %w", err)
	}
	a.snapMu.Lock()
	a.blockSize = bs
	a.snapMu.Unlock()
	return bs, nil
}

// isAddDevError matches the transient region creation failure right
// after a hotplug.
func isAddDevError(err error) bool {
	return strings.Contains(err.Error(), "add_dev")
}

// readBootID returns the boot id of the running kernel, "" if it cannot be
// read.
func readBootID(sysfsRoot string) string {
	b, err := os.ReadFile(filepath.Join(sysfsRoot, "/", bootIDFile))
	if err != nil {
		klog.Warningf("cannot read the boot id: %v; the claims, slices and leases of an earlier boot are taken as those of this one", err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

// otherBoot tells whether a record of the boot recorded is of another boot
// than the running one, bootID. A record without a boot id, written by a
// driver that did not record it, is taken as one of this boot (a driver
// upgraded without a reboot), and so is every record when the boot id of
// the running kernel is unknown.
func otherBoot(recorded, bootID string) bool {
	return recorded != "" && bootID != "" && recorded != bootID
}

// rollbackContext returns a context for cleaning up after a failure that
// the end of ctx does not cancel.
func rollbackContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
}

// Snapshot returns the uses of the memdevs that the allocator uses or is
// preparing, and the memory block size. Nil for a nil (disabled)
// allocator.
func (a *localAllocator) Snapshot() *localSnapshot {
	if a == nil {
		return nil
	}
	a.snapMu.Lock()
	snap := &localSnapshot{Uses: maps.Clone(a.usesSnap), BlockSize: a.blockSize}
	a.snapMu.Unlock()
	snap.Probed = a.probedSizes()
	if snap.BlockSize == 0 {
		snap.BlockSize, _ = a.readBlockSize()
	}
	return snap
}

// updateSnapshot refreshes the snapshot of the uses of the devices.
// Called with a.mu held.
func (a *localAllocator) updateSnapshot() {
	m := make(map[uint64]localUse, len(a.devices))
	for serial, d := range a.devices {
		m[serial] = localUse{Shared: d.Shared, Persistent: d.Persistent, Claims: d.claimUIDs()}
	}
	a.snapMu.Lock()
	a.usesSnap = m
	a.snapMu.Unlock()
}

// SetShared sets the serials of the memdevs that the configuration
// declares shared.
func (a *localAllocator) SetShared(serials map[uint64]bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.shared = maps.Clone(serials)
	if a.shared == nil {
		a.shared = map[uint64]bool{}
	}
}

// Acquire gives a slice of the local memdev with the serial to an
// allocation result of a claim. It returns the slice and the NUMA node of
// a numa slice (-1 for a dax slice). The slice size is size rounded up to
// a multiple of the memory block size.
//   - claimUID, request: the claim and the request of the allocation result
//   - serial: the serial of the memdev
//   - mode: api.ModeNUMA (system RAM of the NUMA node of the memdev) or
//     api.ModeDax (a devdax device of its own)
//   - size: bytes that the allocation result consumes
//   - readOnly: the dax slice is for reading only
func (a *localAllocator) Acquire(ctx context.Context, claimUID, request string, serial uint64, mode string, size uint64, readOnly bool) (*localSlice, int, error) {
	if a == nil {
		return nil, -1, errors.New("local memdevs are not managed (manageMemdevs: false)")
	}
	if mode != api.ModeNUMA && mode != api.ModeDax {
		return nil, -1, fmt.Errorf("invalid mode %q", mode)
	}
	if size == 0 {
		return nil, -1, errors.New("size 0")
	}
	if err := a.checkPool(ctx, serial); err != nil {
		return nil, -1, err
	}
	bs, err := a.readBlockSize()
	if err != nil {
		return nil, -1, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.device(ctx, serial, bs, claimUID)
	if err != nil {
		return nil, -1, err
	}
	s := &localSlice{Request: request, Region: d.Region, Mode: mode, Size: size, ReadOnly: readOnly}
	if err := a.addSlice(ctx, d, claimUID, s, bs); err != nil {
		a.dropUnused(ctx, d, claimUID)
		return nil, -1, fmt.Errorf("memdev %s (serial 0x%x): %w", d.Memdev, serial, err)
	}
	d.Claims[claimUID] = append(d.Claims[claimUID], s)
	node := -1
	if mode == api.ModeNUMA {
		node = d.Node
	}
	klog.Infof("local: memdev %s (serial 0x%x) %s: claim %s request %s: slice %s mode %s size %d node %d%s",
		d.Memdev, serial, d.Region, claimUID, request, s.Dax, mode, s.Size, node, strings.TrimRight(" "+s.DaxDevice, " "))
	a.updateSnapshot()
	if err := a.save(); err != nil {
		return nil, -1, err
	}
	return s, node, nil
}

// checkPool returns the error of poolGuard for the memdev with the serial,
// logged: a pool device is never used as a local memdev (bug-09).
func (a *localAllocator) checkPool(ctx context.Context, serial uint64) error {
	if a.poolGuard == nil {
		return nil
	}
	if err := a.poolGuard(ctx, serial); err != nil {
		klog.Errorf("local: refusing memdev serial 0x%x: %v", serial, err)
		return err
	}
	return nil
}

// AcquireShared gives the shared local memdev with the serial to an
// allocation result of a claim: the first dax device of its region, bound
// to device_dax and never resized. A region is created and its dax device
// zeroed if the memdev has none; a kept region is reused as it is. The
// slice is the whole dax device. The memdev counts as configured shared
// from then on (SetShared), also when it appeared after the start.
//   - claimUID, request: the claim and the request of the allocation result
//   - serial: the serial of the memdev
//   - readOnly: the device node of the claim is for reading only
//   - use: "exclusive" or the shares of the claim ("1 share"), for the log
func (a *localAllocator) AcquireShared(ctx context.Context, claimUID, request string, serial uint64, readOnly bool, use string) (*localSlice, error) {
	if a == nil {
		return nil, errors.New("local memdevs are not managed (manageMemdevs: false)")
	}
	if err := a.checkPool(ctx, serial); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.shared[serial] = true
	d, err := a.sharedDevice(ctx, serial, claimUID)
	if err != nil {
		return nil, err
	}
	s := &localSlice{Request: request, Region: d.Region, Mode: api.ModeDax, Dax: d.Dax, ReadOnly: readOnly}
	err = a.mem.SetDaxDriver(ctx, d.Dax, memctl.DriverDeviceDax)
	if err == nil {
		s.Size, err = a.mem.DaxDeviceSize(d.Dax)
	}
	if err == nil {
		s.Major, s.Minor, err = a.mem.DaxDevNumbers(d.Dax)
	}
	if err != nil {
		if len(d.Claims[claimUID]) == 0 {
			delete(d.Claims, claimUID)
		}
		a.persist()
		return nil, fmt.Errorf("memdev %s (serial 0x%x): %s: %w", d.Memdev, serial, d.Dax, err)
	}
	s.DaxDevice = filepath.Join(a.mem.DevRoot, d.Dax)
	d.Claims[claimUID] = append(d.Claims[claimUID], s)
	klog.Infof("local: memdev %s (serial 0x%x): claim %s request %s: shared %s size %d read-only %v %s",
		d.Memdev, serial, claimUID, request, s.Dax, s.Size, readOnly, use)
	a.updateSnapshot()
	if err := a.save(); err != nil {
		return nil, err
	}
	return s, nil
}

// sharedDevice returns the shared device with the serial for an Acquire of
// a claim, with its devdax region created and zeroed if it has none. A
// device that is used as slices by claims is refused; one that is sliced
// without claims is released first. A region that is not set up (its
// creation failed or was cut, or it was kept for a claim) is made anew, or
// set up and zeroed again when its release would leave a hole in the
// decoders (releaseInOrder, setUpRegion). A new device records the claim
// before its region is created (see device).
func (a *localAllocator) sharedDevice(ctx context.Context, serial uint64, claimUID string) (*localDevice, error) {
	memdev, err := a.mem.FindMemdev(serial)
	if err != nil {
		return nil, err
	}
	d := a.devices[serial]
	if d != nil {
		d.Memdev = memdev
	}
	if d != nil && d.Persistent {
		if d, err = a.notPersistent(ctx, d, "a shared device"); err != nil {
			return nil, err
		}
	}
	if d != nil && !d.Shared {
		if uids := d.claimUIDs(); len(uids) > 0 {
			return nil, fmt.Errorf("memdev %s (serial 0x%x): used as slices by claims %v; a shared device cannot be sliced", memdev, serial, uids)
		}
		if err := a.releaseOrphans(ctx, d); err != nil {
			a.persist()
			return nil, err
		}
		if err := a.releaseRegion(ctx, d); err != nil {
			return nil, err
		}
		d = nil
	}
	if d != nil && d.Region != "" && !slices.Contains(a.mem.Regions(memdev), d.Region) {
		klog.Warningf("local: memdev %s (serial 0x%x): %s of the shared device is gone, forgetting it and its claims %v", memdev, serial, d.Region, d.claimUIDs())
		delete(a.devices, serial)
		a.updateSnapshot()
		d = nil
	}
	if d != nil && (d.Region == "" || d.Dax == "") {
		// leftovers of a creation that failed or was cut, or a region
		// kept for a claim
		a.adoptCreated(d)
		var above []string
		if d.Region != "" {
			above, err = a.releaseInOrder(ctx, d)
		} else {
			err = a.releaseRegion(ctx, d)
		}
		switch {
		case err != nil:
			return nil, err
		case len(above) > 0:
			return a.setUpShared(ctx, d)
		}
		d = nil
	}
	if err := a.checkRegions(memdev, d); err != nil {
		return nil, err
	}
	if d != nil {
		return d, nil
	}
	d = &localDevice{
		Serial:    serial,
		SerialHex: fmt.Sprintf("%x", serial),
		Memdev:    memdev,
		Node:      -1,
		Shared:    true,
		Claims:    map[string][]*localSlice{claimUID: nil},
	}
	a.devices[serial] = d
	a.updateSnapshot()
	err = a.save()
	if err == nil {
		bs, berr := a.readBlockSize()
		if berr != nil {
			// the block size only checks the alignment of the region
			bs = cxlRegionAlign
		}
		err = a.createProbedRegion(ctx, d, bs)
	}
	if err == nil {
		err = a.zeroShared(ctx, d)
	}
	if err == nil {
		err = a.save()
	}
	if err != nil {
		// not set up (or not zeroed): setUpShared if it is kept
		d.Dax = ""
		a.dropUnused(ctx, d, claimUID)
		return nil, err
	}
	return d, nil
}

// setUpShared sets up the kept region of a shared device again
// (setUpRegion) and zeroes its dax device, as for a new region.
func (a *localAllocator) setUpShared(ctx context.Context, d *localDevice) (*localDevice, error) {
	if err := a.checkRegions(d.Memdev, d); err != nil {
		return nil, err
	}
	err := a.setUpRegion(ctx, d)
	if err == nil {
		err = a.zeroShared(ctx, d)
	}
	if err == nil {
		err = a.save()
	}
	if err != nil {
		d.Dax = ""
		a.persist()
		return nil, err
	}
	return d, nil
}

// zeroShared writes zeros to the whole dax device of the new region of a
// shared device, so that its first claim never sees what earlier users of
// the memory left there.
func (a *localAllocator) zeroShared(ctx context.Context, d *localDevice) error {
	start := time.Now()
	err := a.mem.SetDaxDriver(ctx, d.Dax, memctl.DriverDeviceDax)
	var size, align uint64
	var major, minor int
	if err == nil {
		_, align, _, err = a.mem.DaxRegionInfo(d.Region)
	}
	if err == nil {
		size, err = a.mem.DaxDeviceSize(d.Dax)
	}
	if err == nil {
		major, minor, err = a.mem.DaxDevNumbers(d.Dax)
	}
	if err == nil {
		err = a.zero(major, minor, size, align)
	}
	if err != nil {
		return fmt.Errorf("memdev %s (serial 0x%x): zeroing new shared %s: %w", d.Memdev, d.Serial, d.Dax, err)
	}
	klog.Infof("local: memdev %s (serial 0x%x): zeroed new shared %s size %d in %s", d.Memdev, d.Serial, d.Dax, size, since(start))
	return nil
}

// device returns the device with the serial for an Acquire of a claim,
// with its region created (memory blocks of bs bytes) and the slices of
// failed releases released (see reuse). A new device records the claim
// before its region is created: a Prepare cut in the creation leaves a
// record with the claim, which then holds what the creation made
// (Reconcile).
func (a *localAllocator) device(ctx context.Context, serial, bs uint64, claimUID string) (*localDevice, error) {
	memdev, err := a.mem.FindMemdev(serial)
	if err != nil {
		return nil, err
	}
	d := a.devices[serial]
	if d != nil && d.Persistent {
		d.Memdev = memdev
		if d, err = a.notPersistent(ctx, d, "a sliced device"); err != nil {
			return nil, err
		}
	}
	if d != nil && d.Shared {
		d.Memdev = memdev
		if uids := d.claimUIDs(); len(uids) > 0 {
			return nil, fmt.Errorf("memdev %s (serial 0x%x): used shared by claims %v; a sliced device cannot be shared", memdev, serial, uids)
		}
	}
	if d != nil {
		d.Memdev = memdev
		if err := a.releaseOrphans(ctx, d); err != nil {
			a.persist()
			return nil, err
		}
		reuse, err := a.reuse(ctx, d)
		if err != nil {
			return nil, err
		}
		if reuse {
			return d, nil
		}
	}
	if err := a.checkRegions(memdev, nil); err != nil {
		return nil, err
	}
	d = &localDevice{
		Serial:    serial,
		SerialHex: fmt.Sprintf("%x", serial),
		Memdev:    memdev,
		Node:      -1,
		Claims:    map[string][]*localSlice{claimUID: nil},
	}
	a.devices[serial] = d
	a.updateSnapshot()
	err = a.save()
	if err == nil {
		err = a.createProbedRegion(ctx, d, bs)
	}
	if err == nil {
		err = a.save()
	}
	if err != nil {
		// not set up: setUpRegion if it is kept
		d.Dax = ""
		a.dropUnused(ctx, d, claimUID)
		return nil, err
	}
	return d, nil
}

// reuse tells whether an Acquire uses the region of a known device, and
// releases the region if not. A device without claims has the leftovers
// of a failed release or of a restart: released. A region that is not set
// up (Dax "": its creation failed or was cut, or it was kept for claims
// whose Prepare did not finish) is released when that leaves no hole in
// the decoders now (releaseInOrder), else set up again (setUpRegion). The
// one region that a creation left (Region "") is taken as such a region
// first (adoptCreated); a creation that left none, or more than one, is
// released.
func (a *localAllocator) reuse(ctx context.Context, d *localDevice) (bool, error) {
	a.adoptCreated(d)
	if len(d.Claims) == 0 || d.Region == "" {
		return false, a.releaseRegion(ctx, d)
	}
	if d.Dax == "" {
		above, err := a.releaseInOrder(ctx, d)
		if err != nil || len(above) == 0 {
			return false, err
		}
	}
	if err := a.checkRegions(d.Memdev, d); err != nil {
		return false, err
	}
	if d.Dax == "" {
		if err := a.setUpRegion(ctx, d); err != nil {
			a.persist()
			return false, err
		}
		if err := a.save(); err != nil {
			return false, err
		}
	}
	return true, nil
}

// checkRegions returns an error if the memdev has a region other than the
// one of the device (d nil: any region).
func (a *localAllocator) checkRegions(memdev string, d *localDevice) error {
	for _, r := range a.mem.Regions(memdev) {
		if d == nil || r != d.Region {
			return fmt.Errorf("memdev %s has region %s that the plugin did not create", memdev, r)
		}
	}
	return nil
}

// createRegion creates the devdax region of a device, and retries once
// after a transient failure. A region that does not start at a boundary of
// the memory blocks of bs bytes is logged.
func (a *localAllocator) createRegion(ctx context.Context, d *localDevice, bs uint64) error {
	start := time.Now()
	ri, err := a.region(ctx, d)
	if err != nil && isAddDevError(err) {
		klog.Warningf("local: memdev %s (serial 0x%x): %v; retrying once in %v", d.Memdev, d.Serial, err, a.retryDelay)
		select {
		case <-ctx.Done():
		case <-time.After(a.retryDelay):
			ri, err = a.region(ctx, d)
		}
	}
	if err != nil {
		// the region that the failed creation left, if any
		a.adoptCreated(d)
		return fmt.Errorf("memdev %s (serial 0x%x): %w", d.Memdev, d.Serial, err)
	}
	d.Region, d.Dax, d.Node, d.Creating = ri.Region, ri.Dax, ri.Node, ""
	klog.Infof("local: memdev %s (serial 0x%x): created %s (devdax, dax %s, node %d) in %s", d.Memdev, d.Serial, d.Region, d.Dax, d.Node, since(start))
	if r, err := a.mem.RegionRange(d.Region); err == nil && r.Start%bs != 0 {
		whole, end := uint64(0), (r.End+1)/bs*bs
		if start := roundUp(r.Start, bs); end > start {
			whole = end - start
		}
		klog.Warningf("local: memdev %s (serial 0x%x): %s at %v does not start at a memory block boundary (block size %d): slices use only its %d bytes of whole blocks",
			d.Memdev, d.Serial, d.Region, r, bs, whole)
	}
	return nil
}

// region creates the devdax region of the memdev of a device, and records
// its name in the device first (regionNote).
func (a *localAllocator) region(ctx context.Context, d *localDevice) (*memctl.RegionInfo, error) {
	size := a.usableSize(d.Memdev, d.Serial)
	if ram, err := a.mem.RamSize(d.Memdev); err == nil && size >= ram {
		size = 0
	}
	if size > 0 {
		klog.Infof("local: memdev %s (serial 0x%x): creating a region of its first %d bytes only (usable size)", d.Memdev, d.Serial, size)
	}
	ri, err := a.mem.CreateRegionNoted(ctx, d.Memdev, memctl.ModeDax, "", size, a.regionNote(d))
	if err != nil {
		return nil, err
	}
	if ri.Driver != memctl.DriverDeviceDax {
		return nil, fmt.Errorf("%s: %s is bound to %q, not %s", d.Memdev, ri.Dax, ri.Driver, memctl.DriverDeviceDax)
	}
	return ri, nil
}

// regionNote returns the memctl.RegionNote of the creation of the region
// of a device: the name of the new region is recorded in the device
// (Creating) and saved before cxl create-region runs, and replaced by the
// name that it created if that differs. A start after a cut creation then
// releases that region only, also one that the cut left hollow
// (createdRegions, deleteHollowCreated).
func (a *localAllocator) regionNote(d *localDevice) memctl.RegionNote {
	return func(region, _ string, _ bool) error {
		if region == "" || region == d.Creating {
			return nil
		}
		old := d.Creating
		d.Creating = region
		if err := a.save(); err != nil {
			d.Creating = old
			return fmt.Errorf("recording region %s: %w", region, err)
		}
		return nil
	}
}

// setUpRegion sets up a region that was kept for claims without being set
// up (Dax ""): its creation failed or was cut, or its last slices are
// gone, and its release would have left a hole in the decoders
// (keepRegion). Like a new region it gets its
// first dax device over all of its memory, bound to device_dax, and the
// address line probe. A region that a cut release disabled is enabled
// again, and the kernel gives it that dax device; else the dax devices
// that the cut left are deleted, and the first one is made again. A region
// whose memory aliases is not made smaller: that needs a new region, which
// the next Acquire makes once nothing lies above it (errAliasedBelow).
func (a *localAllocator) setUpRegion(ctx context.Context, d *localDevice) error {
	start := time.Now()
	var err error
	if _, _, _, derr := a.mem.DaxRegionInfo(d.Region); derr != nil {
		// disabled: no dax region
		err = a.mem.EnableRegion(ctx, d.Region)
	} else {
		err = a.spanKept(ctx, d)
	}
	var ri *memctl.RegionInfo
	if err == nil {
		// reuses the region of the memdev: waits for its dax device,
		// offlines the memory that kmem has, binds device_dax
		ri, err = a.mem.CreateRegionSize(ctx, d.Memdev, memctl.ModeDax, "", 0)
	}
	if err == nil && ri.Driver != memctl.DriverDeviceDax {
		err = fmt.Errorf("%s is bound to %q, not %s", ri.Dax, ri.Driver, memctl.DriverDeviceDax)
	}
	if err != nil {
		return fmt.Errorf("memdev %s (serial 0x%x): setting up kept %s: %w", d.Memdev, d.Serial, d.Region, err)
	}
	d.Dax, d.Node = ri.Dax, ri.Node
	klog.Infof("local: memdev %s (serial 0x%x): set up kept %s (devdax, dax %s, node %d) in %s", d.Memdev, d.Serial, d.Region, d.Dax, d.Node, since(start))
	usable, err := a.probeRegion(d)
	if err == nil && usable > 0 {
		err = errAliasedBelow(d, usable)
	}
	if err != nil {
		d.Dax = ""
		return err
	}
	return nil
}

// spanKept gives the first dax device of the kept region of a device all
// of the memory of the region, bound to device_dax, unless it has it and a
// driver already. The dax devices of the region (none is a slice: the
// region was not set up) are deleted first, numa ones offlined: a cut
// resize or driver switch leaves the first one smaller or unbound.
func (a *localAllocator) spanKept(ctx context.Context, d *localDevice) error {
	avail, _, devs, err := a.mem.DaxRegionInfo(d.Region)
	if err != nil {
		return err
	}
	first := ""
	for _, dax := range devs {
		if strings.HasSuffix(dax, ".0") {
			first = dax
		}
	}
	if first == "" {
		return fmt.Errorf("%s has no dax device", d.Region)
	}
	if avail == 0 && len(devs) == 1 && a.mem.DaxDriver(first) != "" {
		return nil
	}
	a.deleteOrphans(ctx, d)
	if own := d.Claims[orphanOwner]; len(own) > 0 {
		return fmt.Errorf("%d dax devices of %s cannot be deleted", len(own), d.Region)
	}
	if avail, _, _, err = a.mem.DaxRegionInfo(d.Region); err == nil {
		err = a.mem.ResizeDaxDevice(ctx, first, avail)
	}
	if err == nil {
		err = a.mem.SetDaxDriver(ctx, first, memctl.DriverDeviceDax)
	}
	return err
}

// since returns the time since start in milliseconds for logs ("12.345ms").
func since(start time.Time) string {
	return fmt.Sprintf("%.3fms", float64(time.Since(start))/float64(time.Millisecond))
}

// logSlice logs a step of a slice of a claim that began at start.
func logSlice(d *localDevice, claimUID, step string, s *localSlice, start time.Time, details string) {
	klog.Infof("local: memdev %s (serial 0x%x): claim %s: %s slice %s mode %s size %d%s in %s",
		d.Memdev, d.Serial, claimUID, step, s.Dax, s.Mode, s.Size, details, since(start))
}

// roundUp returns v rounded up to a multiple of step (v if step is 0).
func roundUp(v, step uint64) uint64 {
	if step == 0 || v%step == 0 {
		return v
	}
	return (v/step + 1) * step
}

// addSlice makes the dax device of a slice of a claim in the region of a
// device and sets s.Dax: the first dax device of the region when no claim
// uses it, else a new one, placed first-fit by the kernel. The slice size
// is s.Size rounded up to a multiple of the memory block size bs and of the
// align of the dax region. A slice that first-fit placed across a block
// boundary is placed on the first whole free blocks of the region instead.
// A numa slice is bound to kmem and onlined movable; a dax slice is bound
// to device_dax and zeroed. A slice that cannot be deleted after a failure
// is kept for orphanOwner.
func (a *localAllocator) addSlice(ctx context.Context, d *localDevice, claimUID string, s *localSlice, bs uint64) error {
	avail, align, devs, err := a.mem.DaxRegionInfo(d.Region)
	if err != nil {
		return err
	}
	if size := roundUp(roundUp(s.Size, bs), align); size != s.Size {
		klog.Warningf("local: memdev %s (serial 0x%x): claim %s: slice of %d bytes rounded up to %d (memory block size %d, align %d)",
			d.Memdev, d.Serial, claimUID, s.Size, size, bs, align)
		s.Size = size
	}
	first, err := a.reusable(d, devs, avail, s.Size)
	if err != nil {
		return err
	}
	start := time.Now()
	dax := first
	if first != "" {
		err = a.mem.ResizeDaxDevice(ctx, first, s.Size)
	} else {
		dax, err = a.mem.CreateDaxDevice(ctx, d.Region, s.Size)
	}
	if err == nil {
		dax, err = a.alignSlice(ctx, d, claimUID, dax, s.Size, bs)
	}
	if err == nil {
		s.Dax = dax
		ranges, _ := a.mem.DaxDeviceRanges(dax)
		logSlice(d, claimUID, "created", s, start, fmt.Sprintf(" at %v", ranges))
		if s.Mode == api.ModeNUMA {
			err = a.onlineSlice(ctx, d, claimUID, s, bs)
		} else {
			err = a.bindSlice(ctx, dax, s)
			if err == nil {
				err = a.zeroSlice(d, claimUID, s, align)
			}
		}
	}
	if err != nil && dax != "" {
		rctx, cancel := rollbackContext(ctx)
		defer cancel()
		failed := &localSlice{Region: d.Region, Mode: s.Mode, Size: s.Size, Dax: dax}
		if derr := a.deleteSlice(rctx, d, claimUID, failed); derr != nil {
			klog.Errorf("local: %v; keeping %s for a later release", derr, dax)
			d.Claims[orphanOwner] = append(d.Claims[orphanOwner], failed)
		}
	}
	return err
}

// alignSlice returns the dax device of a slice of size bytes with memory
// on whole memory blocks of bs bytes: dax, or a new device on the first
// whole free blocks of the region, in address order, that replaces dax.
func (a *localAllocator) alignSlice(ctx context.Context, d *localDevice, claimUID, dax string, size, bs uint64) (string, error) {
	ranges, err := a.mem.DaxDeviceRanges(dax)
	if err != nil {
		return dax, err
	}
	aligned := len(ranges) > 0
	for _, r := range ranges {
		aligned = aligned && r.Aligned(bs)
	}
	if aligned {
		return dax, nil
	}
	klog.Warningf("local: memdev %s (serial 0x%x): claim %s: slice %s at %v is not aligned to the memory block size %d, placing it explicitly",
		d.Memdev, d.Serial, claimUID, dax, ranges, bs)
	if err := a.mem.DeleteDaxDevice(ctx, d.Region, dax); err != nil {
		return dax, err
	}
	gaps, err := a.mem.RegionFreeGaps(d.Region)
	if err != nil {
		return "", err
	}
	whole := blockRanges(gaps, size, bs)
	if whole == nil {
		return "", fmt.Errorf("%w: no %d bytes of whole free memory blocks in %s (free %v, memory block size %d)", errNoRoom, size, d.Region, gaps, bs)
	}
	return a.mem.CreateDaxDeviceRanges(ctx, d.Region, whole)
}

// blockRanges returns the parts of the ranges that are whole memory blocks
// of bs bytes, in address order, up to size bytes; nil if they have less.
func blockRanges(ranges []memctl.Range, size, bs uint64) []memctl.Range {
	var out []memctl.Range
	for _, r := range ranges {
		start, end := roundUp(r.Start, bs), (r.End+1)/bs*bs
		if start >= end || size == 0 {
			continue
		}
		n := min(end-start, size)
		out = append(out, memctl.Range{Start: start, End: start + n - 1})
		size -= n
	}
	if size > 0 {
		return nil
	}
	return out
}

// localUsableSize returns the bytes of whole memory blocks of bs bytes
// that a region on a memdev of size bytes is sure to hold, wherever in its
// window it starts.
func localUsableSize(size, bs uint64) uint64 {
	if bs == 0 {
		return 0
	}
	if bs > cxlRegionAlign {
		head := bs - cxlRegionAlign
		if size <= head {
			return 0
		}
		size -= head
	}
	return size / bs * bs
}

// onlineSlice binds the dax device of a numa slice of a claim to kmem,
// onlines its memory blocks movable, and sets the NUMA node of the device
// to the node of the memory. The node is fenced before the memory goes
// online when the dax device tells it, else right after.
func (a *localAllocator) onlineSlice(ctx context.Context, d *localDevice, claimUID string, s *localSlice, bs uint64) error {
	start := time.Now()
	// The node is fenced before kmem adds the memory of the device.
	fenced := a.mem.TargetNode(s.Dax)
	a.fence.Fence(ctx, fenced)
	// kmem gets this device only: a sysfs bind, no new_id, no daxctl.
	if err := a.mem.SetDaxDriverSysfs(ctx, s.Dax, memctl.DriverKmem); err != nil {
		return err
	}
	if err := a.mem.WaitDaxBlocks(ctx, s.Dax); err != nil {
		return err
	}
	blocks, err := a.mem.DaxDeviceBlocks(s.Dax, bs)
	if err != nil {
		return err
	}
	if err := a.mem.SetBlocksState(blocks, "online_movable"); err != nil {
		return err
	}
	node := a.mem.TargetNode(s.Dax)
	if node < 0 {
		node = a.mem.BlocksNode(blocks)
	}
	if node < 0 {
		return fmt.Errorf("cannot find the NUMA node of %s", s.Dax)
	}
	if a.fence != nil && node != fenced {
		klog.V(3).Infof("local: memdev %s (serial 0x%x): claim %s: NUMA node %d of %s known only after onlining, fencing it late",
			d.Memdev, d.Serial, claimUID, node, s.Dax)
		a.fence.Fence(ctx, node)
	}
	d.Node = node
	logSlice(d, claimUID, "onlined", s, start, fmt.Sprintf(" blocks %v node %d", blocks, node))
	return nil
}

// reusable returns the first dax device of the region of a device if no
// slice uses it and kmem does not have it ("" otherwise), after checking
// that the dax region has room for a slice of size bytes: avail free bytes,
// and the size of that dax device.
func (a *localAllocator) reusable(d *localDevice, devs []string, avail, size uint64) (string, error) {
	first := ""
	for _, dax := range devs {
		if strings.HasSuffix(dax, ".0") && !d.usesDax(dax) && a.mem.DaxDriver(dax) != memctl.DriverKmem {
			first = dax
			break
		}
	}
	if first != "" {
		cur, err := a.mem.DaxDeviceSize(first)
		if err != nil {
			return "", err
		}
		avail += cur
	}
	if avail < size {
		klog.Errorf("local: memdev %s (serial 0x%x): %d bytes free in %s, a slice needs %d: claims allocated more than the capacity?", d.Memdev, d.Serial, avail, d.Region, size)
		return "", fmt.Errorf("%w: %d bytes free in %s, the slice needs %d", errNoRoom, avail, d.Region, size)
	}
	return first, nil
}

// zeroSlice writes zeros to the memory of a dax slice of a claim, so that
// a claim never sees what an earlier one left there.
func (a *localAllocator) zeroSlice(d *localDevice, claimUID string, s *localSlice, align uint64) error {
	start := time.Now()
	if err := a.zero(s.Major, s.Minor, s.Size, align); err != nil {
		return fmt.Errorf("zeroing %s: %w", s.Dax, err)
	}
	logSlice(d, claimUID, "zeroed", s, start, "")
	return nil
}

// zeroDax writes zeros to the memory of the dax character device
// major:minor of size bytes, through a private device node in a temporary
// directory under devRoot, in windows that are multiples of align.
func zeroDax(devRoot string, major, minor int, size, align uint64) error {
	// A device node can be opened only on a file system without nodev:
	// devRoot (devtmpfs), not the temporary directory (often tmpfs nodev).
	dir, err := os.MkdirTemp(devRoot, ".cxl-local-zero-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	node := filepath.Join(dir, "dax")
	if err := syscall.Mknod(node, syscall.S_IFCHR|0600, int(unix.Mkdev(uint32(major), uint32(minor)))); err != nil {
		return fmt.Errorf("mknod %d:%d: %w", major, minor, err)
	}
	f, err := os.OpenFile(node, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return zeroFile(f, size, align)
}

// zeroFile writes zeros to the first size bytes of a file through shared
// mappings of at most zeroChunk bytes, rounded up to a multiple of align.
func zeroFile(f *os.File, size, align uint64) error {
	chunk := uint64(zeroChunk)
	if align > 0 && chunk%align != 0 {
		chunk = (chunk/align + 1) * align
	}
	for off := uint64(0); off < size; off += chunk {
		n := min(chunk, size-off)
		b, err := syscall.Mmap(int(f.Fd()), int64(off), int(n), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("mmap %d bytes at %d: %w", n, off, err)
		}
		clear(b)
		if err := syscall.Munmap(b); err != nil {
			return fmt.Errorf("munmap: %w", err)
		}
	}
	return nil
}

// bindSlice binds the dax device of a slice to device_dax and sets the
// device of the slice.
func (a *localAllocator) bindSlice(ctx context.Context, dax string, s *localSlice) error {
	if err := a.mem.SetDaxDriver(ctx, dax, memctl.DriverDeviceDax); err != nil {
		return err
	}
	major, minor, err := a.mem.DaxDevNumbers(dax)
	if err != nil {
		return err
	}
	s.Dax, s.DaxDevice, s.Major, s.Minor = dax, filepath.Join(a.mem.DevRoot, dax), major, minor
	return nil
}

// regionPath returns the sysfs path of a region.
func (a *localAllocator) regionPath(region string) string {
	if a == nil || region == "" {
		return ""
	}
	return filepath.Join(a.mem.SysRoot, "bus", "cxl", "devices", region)
}

// holds tells whether the allocator holds the dax device for a slice of a
// claim.
func (a *localAllocator) holds(claimUID, dax string) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range a.devices {
		for _, s := range d.Claims[claimUID] {
			if s.Dax == dax {
				return true
			}
		}
	}
	return false
}

// usesDax tells whether a slice of the device has the dax device.
func (d *localDevice) usesDax(dax string) bool {
	for _, own := range d.Claims {
		for _, s := range own {
			if s.Dax == dax {
				return true
			}
		}
	}
	return false
}

// Release releases the slices of a claim (numa slices are offlined), and
// the region of a memdev whose last slice they were. The claims of a
// shared memdev are dropped; its region stays while the memdev is
// configured shared. The memdev stays enabled. Nothing to release is not
// an error, and does not wait for the Acquires of other claims (listed).
func (a *localAllocator) Release(ctx context.Context, claimUID string) error {
	return a.release(ctx, claimUID, false)
}

// ReleaseFailed releases what a Prepare of a claim that failed acquired, as
// Release does, but keeps the region of a memdev whose last claim it is
// for the claim while regions of other memdevs lie above it (keepRegion):
// the Unprepare of the claim releases it, its Prepare again reuses it.
func (a *localAllocator) ReleaseFailed(ctx context.Context, claimUID string) error {
	return a.release(ctx, claimUID, true)
}

// release releases the slices of a claim (Release), keeping the regions
// that keepRegion keeps if keep.
func (a *localAllocator) release(ctx context.Context, claimUID string, keep bool) error {
	if a == nil || !a.listed(claimUID) {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var errs []error
	changed := false
	for _, serial := range a.serials() {
		d := a.devices[serial]
		if _, ok := d.Claims[claimUID]; !ok {
			continue
		}
		changed = true
		if err := a.releaseClaim(ctx, d, claimUID, keep); err != nil {
			errs = append(errs, err)
		}
	}
	if changed {
		a.updateSnapshot()
		errs = append(errs, a.save())
	}
	return errors.Join(errs...)
}

// listed tells whether the snapshot of the uses of the devices lists the
// claim. The callers of Release and ReleaseFailed hold the lock of the
// claim (nodeState.locks), and only an Acquire of the claim adds it to a
// device (and to the snapshot, before it creates a region). So a claim
// that is not listed has nothing to release, and its release need not
// wait for a.mu, which an Acquire of another claim may hold for long (the
// zeroing of a whole shared device).
func (a *localAllocator) listed(claimUID string) bool {
	a.snapMu.Lock()
	defer a.snapMu.Unlock()
	for _, u := range a.usesSnap {
		if slices.Contains(u.Claims, claimUID) {
			return true
		}
	}
	return false
}

// releaseClaim releases the slices of a claim on a device, and the region
// of the device if the claim was its last one, unless keep and regions of
// other memdevs lie above it (releaseOrKeep). On error the claim keeps
// what is not released yet.
func (a *localAllocator) releaseClaim(ctx context.Context, d *localDevice, claimUID string, keep bool) error {
	if d.Persistent {
		return a.releasePersistent(ctx, d, claimUID, keep)
	}
	if d.Shared {
		return a.releaseShared(ctx, d, claimUID, keep)
	}
	if err := a.deleteSlices(ctx, d, claimUID); err != nil {
		return err
	}
	for uid := range d.Claims {
		if uid != claimUID && uid != orphanOwner {
			delete(d.Claims, claimUID)
			return nil
		}
	}
	// the claim stays until the region is released
	d.Claims[claimUID] = nil
	if err := a.releaseOrphans(ctx, d); err != nil {
		// the region stays for the slices that cannot be released
		delete(d.Claims, claimUID)
		klog.Errorf("local: %v", err)
		return nil
	}
	if keep {
		return a.releaseOrKeep(ctx, d, []string{claimUID})
	}
	return a.releaseRegion(ctx, d)
}

// releaseOrKeep releases the region of a device whose last claims are
// uids, whose Prepares did not finish (releaseInOrder), or keeps it for
// them when regions of other memdevs lie above it (keepRegion).
func (a *localAllocator) releaseOrKeep(ctx context.Context, d *localDevice, uids []string) error {
	above, err := a.releaseInOrder(ctx, d)
	if len(above) > 0 {
		a.keepRegion(ctx, d, uids, above)
	}
	return err
}

// releaseShared drops a claim of a shared device, and releases the region
// of the device if it has no claims left and is not configured shared,
// unless keep and regions of other memdevs lie above it (releaseOrKeep).
func (a *localAllocator) releaseShared(ctx context.Context, d *localDevice, claimUID string, keep bool) error {
	delete(d.Claims, claimUID)
	uids := d.claimUIDs()
	klog.Infof("local: memdev %s (serial 0x%x): claim %s: released shared %s, claims left %v", d.Memdev, d.Serial, claimUID, d.Dax, uids)
	if len(uids) > 0 {
		return nil
	}
	if a.shared[d.Serial] {
		klog.Infof("local: memdev %s (serial 0x%x): keeping %s and %s of the idle shared device", d.Memdev, d.Serial, d.Region, d.Dax)
		return nil
	}
	if keep {
		return a.releaseOrKeep(ctx, d, []string{claimUID})
	}
	return a.releaseRegion(ctx, d)
}

// deleteSlices deletes the slices of a claim on a device, the last one
// first. On error the claim keeps the slices that are not deleted.
func (a *localAllocator) deleteSlices(ctx context.Context, d *localDevice, claimUID string) error {
	own := d.Claims[claimUID]
	for len(own) > 0 {
		if err := a.deleteSlice(ctx, d, claimUID, own[len(own)-1]); err != nil {
			d.Claims[claimUID] = own
			return err
		}
		own = own[:len(own)-1]
	}
	return nil
}

// releaseOrphans releases the slices of orphanOwner on a device. On error
// orphanOwner keeps the slices that are not released.
func (a *localAllocator) releaseOrphans(ctx context.Context, d *localDevice) error {
	if err := a.deleteSlices(ctx, d, orphanOwner); err != nil {
		return err
	}
	delete(d.Claims, orphanOwner)
	return nil
}

// keepOrphans gives the slices of a claim on a device, whose release
// failed, to orphanOwner, and forgets the claim.
func (d *localDevice) keepOrphans(claimUID string) {
	if own := d.Claims[claimUID]; len(own) > 0 {
		klog.Warningf("local: memdev %s (serial 0x%x): claim %s: keeping %d slices for a later release", d.Memdev, d.Serial, claimUID, len(own))
		d.Claims[orphanOwner] = append(d.Claims[orphanOwner], own...)
	}
	delete(d.Claims, claimUID)
}

// deleteSlice offlines the memory of a slice of a claim that is bound to
// kmem, and deletes its dax device (the first dax device of the region is
// kept with size 0). A slice without a dax device has nothing of its own.
func (a *localAllocator) deleteSlice(ctx context.Context, d *localDevice, claimUID string, s *localSlice) error {
	if s.Dax == "" {
		return nil
	}
	if err := a.offlineSlice(d, claimUID, s); err != nil {
		return err
	}
	start := time.Now()
	if err := a.mem.DeleteDaxDevice(ctx, d.Region, s.Dax); err != nil {
		return fmt.Errorf("memdev %s (serial 0x%x): releasing slice %s: %w", d.Memdev, d.Serial, s.Dax, err)
	}
	logSlice(d, claimUID, "deleted", s, start, "")
	return nil
}

// offlineSlice offlines the memory blocks of a slice of a claim whose dax
// device is bound to kmem.
func (a *localAllocator) offlineSlice(d *localDevice, claimUID string, s *localSlice) error {
	if a.mem.DaxDriver(s.Dax) != memctl.DriverKmem {
		return nil
	}
	bs, err := a.readBlockSize()
	if err != nil {
		return fmt.Errorf("memdev %s (serial 0x%x): releasing slice %s: %w", d.Memdev, d.Serial, s.Dax, err)
	}
	blocks, err := a.mem.DaxDeviceBlocks(s.Dax, bs)
	if err == nil {
		start := time.Now()
		if err = a.mem.SetBlocksState(blocks, "offline"); err == nil {
			logSlice(d, claimUID, "offlined", s, start, fmt.Sprintf(" blocks %v", blocks))
			return nil
		}
	}
	return fmt.Errorf("memdev %s (serial 0x%x): releasing slice %s: cannot offline its memory (in use?): %w", d.Memdev, d.Serial, s.Dax, err)
}

// releaseRegion releases the region of a device and forgets the device. A
// device whose region is being created (Region "") releases what the
// creation left (createdRegions, deleteHollowCreated).
func (a *localAllocator) releaseRegion(ctx context.Context, d *localDevice) error {
	_, err := a.releaseRegions(ctx, d, false)
	return err
}

// releaseInOrder releases the region of a device and forgets the device,
// as releaseRegion does, unless regions of other memdevs lie above it in
// the decoders: its release would leave a hole below them. It returns them
// then and keeps the device; the region stays, disabled if they came
// during the release. memctl.ReleaseRegionInOrder checks again after cxl
// disable-region, under the lock of the region creations of the process,
// so that a region that a pool Prepare creates meanwhile counts.
func (a *localAllocator) releaseInOrder(ctx context.Context, d *localDevice) ([]string, error) {
	return a.releaseRegions(ctx, d, true)
}

// releaseRegions is releaseRegion, and releaseInOrder if inOrder.
func (a *localAllocator) releaseRegions(ctx context.Context, d *localDevice, inOrder bool) ([]string, error) {
	start := time.Now()
	regions := []string{d.Region}
	if d.Region == "" {
		if err := a.deleteHollowCreated(d); err != nil {
			return nil, err
		}
		regions = a.createdRegions(d)
	}
	for _, r := range regions {
		var above []string
		var err error
		if inOrder {
			above, err = a.mem.ReleaseRegionInOrder(ctx, d.Memdev, r)
		} else {
			err = a.mem.ReleaseRegion(ctx, r)
		}
		if err != nil {
			return nil, fmt.Errorf("memdev %s (serial 0x%x): releasing its region: %w", d.Memdev, d.Serial, err)
		}
		if len(above) > 0 {
			return above, nil
		}
	}
	delete(a.devices, d.Serial)
	if len(regions) == 0 {
		klog.Infof("local: memdev %s (serial 0x%x): forgetting it, it has no region of the plugin", d.Memdev, d.Serial)
		return nil, nil
	}
	klog.Infof("local: memdev %s (serial 0x%x): released %s in %s", d.Memdev, d.Serial, strings.Join(regions, ", "), since(start))
	return nil, nil
}

// createdRegions returns the regions that the creation of the region of a
// device (Region "") left on its memdev: the region recorded for it
// (Creating) if the memdev has it, else none. Without a recorded name
// (an older plugin) every region on the memdev is what the creation left:
// the memdev had none (checkRegions).
func (a *localAllocator) createdRegions(d *localDevice) []string {
	regions := a.mem.Regions(d.Memdev)
	if d.Creating == "" {
		return regions
	}
	if slices.Contains(regions, d.Creating) {
		return []string{d.Creating}
	}
	return nil
}

// adoptCreated makes the one region that the creation of the region of a
// device with claims left (Region "", createdRegions) the region of the
// device, not set up (Dax ""), and tells whether it did: the claims hold
// it then as a region kept for them (keepRegion).
func (a *localAllocator) adoptCreated(d *localDevice) bool {
	if d.Region != "" || len(d.claimUIDs()) == 0 {
		return false
	}
	regions := a.createdRegions(d)
	if len(regions) != 1 {
		return false
	}
	d.Region, d.Dax, d.NdRegion, d.Node, d.Creating = regions[0], "", "", -1, ""
	return true
}

// deleteHollowCreated deletes the region recorded for the creation of the
// region of a device (Creating) if the creation left it hollow: a cxl
// create-region killed before it set the target (memctl.HollowRegion).
// Regions does not list such a region, and it holds its address range in
// the root decoder until it is deleted.
func (a *localAllocator) deleteHollowCreated(d *localDevice) error {
	if d.Creating == "" || !a.mem.HollowRegion(d.Creating) {
		return nil
	}
	klog.Warningf("local: memdev %s (serial 0x%x): %s, whose creation did not finish, has no target decoder: deleting it", d.Memdev, d.Serial, d.Creating)
	if err := a.mem.DeleteHollowRegion(d.Creating); err != nil {
		return fmt.Errorf("memdev %s (serial 0x%x): %w", d.Memdev, d.Serial, err)
	}
	return nil
}

// dropUnused releases the region of a device after a failed Acquire of a
// claim if no other claim uses it, and saves the state. When regions of
// other memdevs lie above it, the region is kept for the claim instead
// (keepRegion): its release would leave a hole in the decoders now.
func (a *localAllocator) dropUnused(ctx context.Context, d *localDevice, claimUID string) {
	if len(d.Claims[claimUID]) == 0 {
		delete(d.Claims, claimUID)
	}
	if len(d.Claims) == 0 {
		ctx, cancel := rollbackContext(ctx)
		defer cancel()
		if err := a.releaseOrKeep(ctx, d, []string{claimUID}); err != nil {
			klog.Errorf("local: %v", err)
		}
	}
	a.persist()
}

// keepRegion keeps the region of a device, which has no slices, for claims
// whose Prepare did not finish (cut, or failed), instead of releasing it:
// the regions above, of other memdevs, would leave a hole in the decoders
// of their ports (memctl.DecoderHole), and the kernel would create no
// region through those ports until they are gone. The claims hold the
// region: their Unprepare releases it, their Prepare again sets it up
// again (setUpRegion) and uses it. The dax devices of the region that
// belong to no slice are deleted, so that no memory of it stays online,
// and the region is not set up any more (Dax ""): its first dax device has
// no memory now, and a cut release may have disabled the region.
func (a *localAllocator) keepRegion(ctx context.Context, d *localDevice, uids, above []string) {
	for _, uid := range uids {
		d.Claims[uid] = nil
	}
	if !d.Persistent {
		// a pmem region has no dax devices of the allocator
		a.deleteOrphans(ctx, d)
	}
	d.Dax, d.NdRegion = "", ""
	region := d.Region
	if region == "" {
		region = strings.Join(a.mem.Regions(d.Memdev), ", ")
	}
	klog.Warningf("local: memdev %s (serial 0x%x): keeping %s for claims %v, whose Prepare did not finish: %s lie above it, its release would leave a hole in the decoders of their ports; their Unprepare releases it, their Prepare again reuses it",
		d.Memdev, d.Serial, region, uids, strings.Join(above, ", "))
}

// persist refreshes the snapshot and saves the state, logging an error.
func (a *localAllocator) persist() {
	a.updateSnapshot()
	if err := a.save(); err != nil {
		klog.Errorf("local: %v", err)
	}
}

// Reconcile matches the state with the system and the prepared claims:
// devices whose memdev or region is gone are forgotten, slices that are
// gone are dropped, claims that are not in prepared are released (numa
// slices offlined), and so are the slices of failed releases, devices
// without claims and dax devices that belong to no slice. The regions
// that the creation of the region of a device left (reconcileCreating) are
// released, but not those of a memdev that is a pool device now (pool, by
// serial). A region of claims that are not prepared, whose Prepares did
// not finish, is kept for them when regions of other memdevs lie above it
// (keepRegion). A slice whose release fails is kept for orphanOwner. A
// shared device without claims keeps its region while it is configured
// shared (SetShared).
func (a *localAllocator) Reconcile(ctx context.Context, prepared map[string]bool, pool map[uint64]bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, serial := range a.serials() {
		a.reconcileDevice(ctx, a.devices[serial], prepared, pool)
	}
	a.restorePersistent(ctx)
	a.updateSnapshot()
	if err := a.save(); err != nil {
		klog.Errorf("local: %v", err)
	}
	klog.Infof("local: %d memdevs in use after reconcile", len(a.devices))
}

// reconcileDevice reconciles one device (see Reconcile).
func (a *localAllocator) reconcileDevice(ctx context.Context, d *localDevice, prepared map[string]bool, pool map[uint64]bool) {
	memdev, err := a.mem.FindMemdev(d.Serial)
	if err != nil {
		klog.Warningf("local: memdev %s (serial 0x%x) is gone, forgetting it and its claims %v", d.Memdev, d.Serial, slices.Sorted(maps.Keys(d.Claims)))
		delete(a.devices, d.Serial)
		return
	}
	d.Memdev = memdev
	if d.Region == "" {
		a.reconcileCreating(ctx, d, pool)
		return
	}
	if !slices.Contains(a.mem.Regions(memdev), d.Region) {
		klog.Warningf("local: memdev %s (serial 0x%x): %s is gone, forgetting it and its claims %v", memdev, d.Serial, d.Region, slices.Sorted(maps.Keys(d.Claims)))
		delete(a.devices, d.Serial)
		return
	}
	if d.Persistent {
		a.reconcilePersistent(d, prepared)
		return
	}
	if d.Shared {
		a.reconcileShared(ctx, d, prepared)
		return
	}
	// the claims that are not prepared lose their slices (those whose
	// release fails go to orphanOwner), and get the region if it is kept
	// for them
	var unfinished []string
	for _, uid := range slices.Sorted(maps.Keys(d.Claims)) {
		switch {
		case uid == orphanOwner:
			a.dropGoneSlices(d, uid)
		case !prepared[uid]:
			klog.Infof("local: memdev %s (serial 0x%x): claim %s is not prepared, releasing it", memdev, d.Serial, uid)
			if err := a.deleteSlices(ctx, d, uid); err != nil {
				klog.Errorf("local: %v", err)
				d.keepOrphans(uid)
			}
			delete(d.Claims, uid)
			unfinished = append(unfinished, uid)
		default:
			a.dropGoneSlices(d, uid)
		}
	}
	if err := a.releaseOrphans(ctx, d); err != nil {
		klog.Errorf("local: %v", err)
	}
	switch {
	case len(d.Claims) > 0:
		// held by prepared claims, or by slices that cannot be released
		a.deleteOrphans(ctx, d)
	case len(unfinished) > 0:
		if err := a.releaseOrKeep(ctx, d, unfinished); err != nil {
			klog.Errorf("local: %v", err)
		}
	default:
		if err := a.releaseRegion(ctx, d); err != nil {
			klog.Errorf("local: %v", err)
		}
	}
}

// reconcileCreating reconciles a device whose region was being created
// (Region ""): the plugin stopped during the creation (a driver restart
// cuts a running Prepare, and so do a kill and a crash). What the creation
// left (createdRegions: the region recorded for it, enabled or disabled
// by a cut rollback, or hollow) is released, unless the memdev is a pool
// device now (pool): its regions are then not touched. When a region of
// another memdev lies above the region that the creation left, its
// release would leave a hole in the decoders: it is kept for the claims of
// the record (the claim whose Prepare created it, releaseOrKeep), and set
// up again by their Prepare again (setUpRegion).
func (a *localAllocator) reconcileCreating(ctx context.Context, d *localDevice, pool map[uint64]bool) {
	left := a.createdRegions(d)
	if d.Creating != "" && a.mem.HollowRegion(d.Creating) {
		left = append(left, d.Creating+" (hollow)")
	}
	switch {
	case len(left) == 0:
		klog.Warningf("local: memdev %s (serial 0x%x): its region was being created, the creation left none: forgetting it", d.Memdev, d.Serial)
		delete(a.devices, d.Serial)
		return
	case pool[d.Serial]:
		klog.Warningf("local: memdev %s (serial 0x%x): its region was being created, and it is a pool device now: forgetting it without touching its regions %v", d.Memdev, d.Serial, a.mem.Regions(d.Memdev))
		delete(a.devices, d.Serial)
		return
	}
	if uids := d.claimUIDs(); a.adoptCreated(d) {
		klog.Warningf("local: memdev %s (serial 0x%x): its region was being created: %s is what the creation left, releasing it", d.Memdev, d.Serial, d.Region)
		if err := a.releaseOrKeep(ctx, d, uids); err != nil {
			klog.Errorf("local: %v", err)
		}
		return
	}
	klog.Warningf("local: memdev %s (serial 0x%x): its region was being created: releasing %v, what the creation left", d.Memdev, d.Serial, left)
	if err := a.releaseRegion(ctx, d); err != nil {
		klog.Errorf("local: %v", err)
	}
}

// reconcileShared reconciles a shared device whose region exists: claims
// that are not prepared are dropped, and the region of a device without
// claims is released unless the device is configured shared.
func (a *localAllocator) reconcileShared(ctx context.Context, d *localDevice, prepared map[string]bool) {
	for _, uid := range slices.Sorted(maps.Keys(d.Claims)) {
		if !prepared[uid] {
			klog.Infof("local: memdev %s (serial 0x%x): claim %s of the shared device is not prepared, dropping it", d.Memdev, d.Serial, uid)
			delete(d.Claims, uid)
			continue
		}
		a.dropGoneSlices(d, uid)
	}
	uids := d.claimUIDs()
	switch {
	case a.shared[d.Serial]:
		klog.Infof("local: memdev %s (serial 0x%x): keeping shared %s and %s, claims %v", d.Memdev, d.Serial, d.Region, d.Dax, uids)
	case len(uids) > 0:
		klog.Warningf("local: memdev %s (serial 0x%x): not configured shared any more: keeping %s for claims %v, not publishing the memdev until they are gone", d.Memdev, d.Serial, d.Region, uids)
	default:
		klog.Infof("local: memdev %s (serial 0x%x): not configured shared any more, releasing its region", d.Memdev, d.Serial)
		if err := a.releaseRegion(ctx, d); err != nil {
			klog.Errorf("local: %v", err)
		}
	}
}

// deleteOrphans deletes the dax devices of the region of a device that
// belong to no slice and have memory (numa ones are offlined first).
func (a *localAllocator) deleteOrphans(ctx context.Context, d *localDevice) {
	for _, dax := range a.mem.DaxDevices(d.Region) {
		size, err := a.mem.DaxDeviceSize(dax)
		if err != nil || size == 0 || d.usesDax(dax) {
			continue
		}
		s := &localSlice{Mode: api.ModeDax, Size: size, Dax: dax}
		if a.mem.DaxDriver(dax) == memctl.DriverKmem {
			s.Mode = api.ModeNUMA
		}
		klog.Warningf("local: memdev %s (serial 0x%x): %s (mode %s, %d bytes) belongs to no claim, deleting it", d.Memdev, d.Serial, dax, s.Mode, size)
		if err := a.deleteSlice(ctx, d, orphanOwner, s); err != nil {
			klog.Errorf("local: %v; keeping %s for a later release", err, dax)
			s.Region = d.Region
			d.Claims[orphanOwner] = append(d.Claims[orphanOwner], s)
		}
	}
}

// dropGoneSlices drops the slices of a claim whose dax device is gone or
// has another size, and the claim if no slice is left.
func (a *localAllocator) dropGoneSlices(d *localDevice, claimUID string) {
	kept := []*localSlice{}
	for _, s := range d.Claims[claimUID] {
		if s.Dax != "" {
			if size, err := a.mem.DaxDeviceSize(s.Dax); err != nil || size != s.Size {
				klog.Warningf("local: memdev %s (serial 0x%x): claim %s: slice %s of %d bytes is gone, dropping it", d.Memdev, d.Serial, claimUID, s.Dax, s.Size)
				continue
			}
		}
		kept = append(kept, s)
	}
	if len(kept) == 0 {
		delete(d.Claims, claimUID)
		return
	}
	d.Claims[claimUID] = kept
}

// serials returns the serials of the devices in ascending order.
func (a *localAllocator) serials() []uint64 {
	return slices.Sorted(maps.Keys(a.devices))
}

// save writes the state file.
func (a *localAllocator) save() error {
	st := localState{BootID: a.bootID, Devices: make([]*localDevice, 0, len(a.devices))}
	for _, serial := range a.serials() {
		st.Devices = append(st.Devices, a.devices[serial])
	}
	return writeStateFile(a.stateFile, st)
}

// load reads the state file, if there is one. A list of devices without a
// boot id is read as the state of an unknown boot.
func (a *localAllocator) load() error {
	data, err := readStateFile(a.stateFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", a.stateFile, err)
	}
	var st localState
	if err := json.Unmarshal(data, &st); err != nil {
		if lerr := json.Unmarshal(data, &st.Devices); lerr != nil {
			return fmt.Errorf("parsing %s: %w", a.stateFile, err)
		}
	}
	if a.bootID != "" && st.BootID != a.bootID {
		klog.Warningf("local: %s is from another boot (%q, this is %q): forgetting its %d memdevs without touching them",
			a.stateFile, st.BootID, a.bootID, len(st.Devices))
		return nil
	}
	for _, d := range st.Devices {
		if d.Claims == nil {
			d.Claims = map[string][]*localSlice{}
		}
		a.devices[d.Serial] = d
	}
	klog.Infof("local: loaded %d memdevs from %s", len(a.devices), a.stateFile)
	return nil
}

// writeJSONFile replaces the file with v in JSON, readable by the owner
// only. The new content is synced before the rename, and the directory
// after it: after a crash or a power loss the file has the old content or
// the new one, never an empty or a partial one.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := writeSynced(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming %s: %w", tmp, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("syncing the directory of %s: %w", path, err)
	}
	return nil
}

// writeSynced writes data to the file name and syncs it.
func writeSynced(name string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDir syncs a directory, so that a rename in it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
