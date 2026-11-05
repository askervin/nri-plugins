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

package state

import (
	"slices"
)

// Region is the record of a CXL region on the node: one of ours, or a
// foreign one that the driver observes and never touches. A region of ours
// owns the dax devices and node mounts that grants use; each lists its
// users. A memdev may have several regions, and a region several target
// memdevs.
//
// Identity: Name (regionN), or NotedName while the region is being
// created (RegionRef).
//
// States: RegionState. NONE: no record. NOTED: the name that cxl
// create-region will give is committed before it runs. CREATING:
// create-region runs. OWNED: ours, enabled. KEPT: ours, disabled, kept
// below newer regions of another memdev (its release would leave a decoder
// hole) or for a claim whose Prepare did not finish. HOLLOW_OWNED: ours,
// hollow (its memdev went or create-region was cut), deleted when its
// blocks are offline. FOREIGN: on a memdev that no record of ours names;
// published as a region device, never touched. SetUp: the first dax device
// (or the nd region) of the region is made; false again while KEPT.
//
// Transitions: RegionTable and RegionSetUpTable below; a transition not in
// them is refused.
//
// Invariants: a region of ours is exactly one record, in state OWNED, KEPT
// or HOLLOW_OWNED after a Prepare, referenced by every memdev of Targets.
//
// Persistence: intent (NotedName before create-region) and fact. A load in
// another boot drops the record: region names are given anew at every
// boot.
//
// Locks and waits: create, enable, disable, destroy and delete run under
// the engine lock, with the note committed before the command.
type Region struct {
	Name      string      `json:"name,omitempty"`
	NotedName string      `json:"notedName,omitempty"`
	Mode      RegionMode  `json:"mode"`
	Targets   []Serial    `json:"targets"`
	Owner     RegionOwner `json:"owner"`
	// Decoder is the root decoder that gave the noted name, for the
	// content of the pool's preparing records (transitional: removed in
	// H6 (schema 2)).
	Decoder string `json:"decoder,omitempty"`
	// Locked is a region that the firmware committed and locked.
	Locked bool        `json:"locked,omitempty"`
	State  RegionState `json:"state"`
	SetUp  bool        `json:"setUp,omitempty"`
	// Zeroed is a region whose memory was zeroed once (a new shared
	// local region).
	Zeroed bool `json:"zeroed,omitempty"`
	// NumaNode is the NUMA node of the memory of the region.
	NumaNode   *int        `json:"numaNode,omitempty"`
	Size       uint64      `json:"size,omitempty"`
	DaxDevices []DaxDevice `json:"daxDevices,omitempty"`
	Pmem       *Pmem       `json:"pmem,omitempty"`
	Mounts     []Mount     `json:"mounts,omitempty"`
}

// RegionMode is the mode of a region.
type RegionMode string

const (
	RegionRam  RegionMode = "ram"
	RegionPmem RegionMode = "pmem"
	// RegionDcd is reserved for dynamic capacity.
	RegionDcd RegionMode = "dcd"
)

// RegionOwner tells whether a region is the driver's.
type RegionOwner string

const (
	OwnerOurs    RegionOwner = "ours"
	OwnerForeign RegionOwner = "foreign"
)

// RegionState is the state of a Region.
type RegionState string

const (
	RegionNone        RegionState = "NONE"
	RegionNoted       RegionState = "NOTED"
	RegionCreating    RegionState = "CREATING"
	RegionOwned       RegionState = "OWNED"
	RegionKept        RegionState = "KEPT"
	RegionHollowOwned RegionState = "HOLLOW_OWNED"
	RegionForeign     RegionState = "FOREIGN"
)

// Pmem is the nvdimm side of a pmem region.
type Pmem struct {
	NdRegion    string       `json:"ndRegion,omitempty"`
	Namespace   string       `json:"namespace,omitempty"`
	BlockDevice *BlockDevice `json:"blockDevice,omitempty"`
}

// DaxDevice is a dax device of a region of ours with the grants that use
// it: one user for an exclusive part of a memdev, every grant of the memdev
// for the Whole device of a shared memdev, more for a lease that joins a
// claim's device.
//
// Identity: Name (daxN.M) in its region.
//
// States: DaxDeviceState. ABSENT: no device. CREATING: dax_region/create
// written, the name read back. SIZED: sized, unbound. DEVICE_DAX: bound to
// device_dax. KMEM_OFFLINE, KMEM_ONLINE: bound to kmem, its memory blocks
// offline or online (movable). RELEASING: being offlined, unbound and
// deleted. SEED: daxN.0 at size 0, which the kernel never deletes.
//
// Transitions: DaxDeviceTable below; a transition not in it is refused.
//
// Invariants: a device that is not the seed and not the Whole device of a
// kept region has a user that is REALISED or RELEASING after a Prepare; the
// recovery deletes the others.
//
// Persistence: fact; the kernel gives the name after the creation, so it
// is not part of an intent.
//
// Locks and waits: every dax bus write under the engine lock; the memory
// block waits outside it.
type DaxDevice struct {
	Name   string         `json:"name"`
	Dev    DevNumbers     `json:"dev,omitzero"`
	Size   uint64         `json:"size,omitempty"`
	Ranges []AddressRange `json:"ranges,omitempty"`
	Driver DaxDriver      `json:"driver,omitempty"`
	State  DaxDeviceState `json:"state"`
	Users  []GrantRef     `json:"users,omitempty"`
	// Whole is the device of the whole region (the seed of a sliced
	// region, the shared device of a shared memdev).
	Whole bool `json:"whole,omitempty"`
}

// AddressRange is a range of physical addresses, End included.
type AddressRange struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// DaxDriver is the driver of a dax device, "" for none.
type DaxDriver string

const (
	DriverDeviceDax DaxDriver = "device_dax"
	DriverKmem      DaxDriver = "kmem"
)

// DaxDeviceState is the state of a DaxDevice.
type DaxDeviceState string

const (
	DaxAbsent      DaxDeviceState = "ABSENT"
	DaxCreating    DaxDeviceState = "CREATING"
	DaxSized       DaxDeviceState = "SIZED"
	DaxDeviceDax   DaxDeviceState = "DEVICE_DAX"
	DaxKmemOffline DaxDeviceState = "KMEM_OFFLINE"
	DaxKmemOnline  DaxDeviceState = "KMEM_ONLINE"
	DaxReleasing   DaxDeviceState = "RELEASING"
	DaxSeed        DaxDeviceState = "SEED"
)

// Mount is a node mount of the filesystem of a pmem region with one
// access, and the grants that use it.
//
// Identity: the region and Access; Path is <data dir of the grant's source
// driver>/mounts/<serial hex>-<access>.
//
// States: MountState. ABSENT: not mounted. MOUNTED_RO, MOUNTED_RW: mounted,
// read-write while a writer grant uses it. FOREIGN: something else is
// mounted at the path; never used or unmounted. UNRESTORED: at a start the
// mount of a REALISED grant could not be restored. STALE: its unmount
// failed busy; also in the memdev's Stale list, retried.
//
// Transitions: MountTable below; a transition not in it is refused.
//
// Invariants: MOUNTED_RW iff Writer; the block device is read-only iff no
// writer grant uses the region.
//
// Persistence: intent (the path in a grant's Intent before the mount) and
// fact.
//
// Locks and waits: mounts under the engine lock; the holder wait of a
// release outside it.
type Mount struct {
	Access Access     `json:"access"`
	Path   string     `json:"path"`
	State  MountState `json:"state"`
	// Loop is the loop device of a cached mount.
	Loop   string `json:"loop,omitempty"`
	FsType string `json:"fsType,omitempty"`
	// Writer is a mount that a writer grant uses.
	Writer bool       `json:"writer,omitempty"`
	Users  []GrantRef `json:"users,omitempty"`
}

// MountState is the state of a Mount.
type MountState string

const (
	MountAbsent     MountState = "ABSENT"
	MountedRO       MountState = "MOUNTED_RO"
	MountedRW       MountState = "MOUNTED_RW"
	MountForeign    MountState = "FOREIGN"
	MountUnrestored MountState = "UNRESTORED"
	MountStale      MountState = "STALE"
)

// regionStored are the states of a region record in the store.
var regionStored = list(RegionNoted, RegionCreating, RegionOwned, RegionKept, RegionHollowOwned, RegionForeign)

// RegionTable is the transition table of Region.State.
var RegionTable = Table[RegionState]{
	Object: "Region",
	Field:  "State",
	States: list(RegionNone, RegionNoted, RegionCreating, RegionOwned, RegionKept, RegionHollowOwned, RegionForeign),
	Rows: []Transition[RegionState]{
		{
			From: list(RegionNone), To: RegionNoted, Triggers: list(TriggerPrepare),
			When:    "a Prepare needs a region on the memdev",
			Guard:   "engine lock held; the next name read from the root decoder",
			Effects: "commit (d) of NotedName before cxl create-region",
		},
		{
			From: list(RegionNoted), To: RegionCreating, Triggers: list(TriggerPrepare),
			When:    "cxl create-region started",
			Effects: "kernel command (engine lock held for the command)",
		},
		{
			From: list(RegionCreating), To: RegionOwned, Triggers: list(TriggerPrepare),
			When:    "create-region returned; the region's targets are this memdev",
			Guard:   "the name is NotedName, or the created name read again",
			Effects: "commit (d) of Name and Mode",
		},
		{
			From: list(RegionNoted, RegionCreating), To: RegionNone, Triggers: list(TriggerPrepare, TriggerRecover),
			When: "create-region failed with nothing created (decoder hole; endpoint not ready: retried once after " +
				"3 s); or the recovery finds no region of the noted name",
			Guard:   "no region of the noted name exists",
			Effects: "commit (d) clearing the note",
		},
		{
			From: list(RegionNoted, RegionCreating), To: RegionOwned, Triggers: list(TriggerRecover),
			When:    "the recovery finds a region of the noted name whose targets are this memdev",
			Effects: "commit (d) of Name",
		},
		{
			From: list(RegionNoted, RegionCreating), To: RegionHollowOwned, Triggers: list(TriggerRecover),
			When:    "the recovery finds a hollow region of the noted name",
			Effects: "the memdev's Hollow gets the name; commit (l)",
		},
		{
			From: list(RegionOwned), To: RegionKept, Triggers: releasers,
			When:    "a release with Policy \"in order\" found a newer region of another memdev above after cxl disable-region",
			Effects: "the region stays disabled; SetUp false; commit (d)",
		},
		{
			From: list(RegionKept), To: RegionOwned, Triggers: list(TriggerPrepare),
			When:    "a new grant needs the region",
			Guard:   "enable-region succeeded",
			Effects: "commit (d); set up again (SetUp true after the first device)",
		},
		{
			From: list(RegionKept), To: RegionNone, Triggers: releasers,
			When:    "a release with Policy destroy (top of the stack now; an Unprepare of local sliced; pool)",
			Guard:   "blocks offline",
			Effects: "cxl destroy-region; commit (d)",
		},
		{
			From: list(RegionOwned), To: RegionNone, Triggers: releasers,
			When:  "the last user released and Policy says destroy; or the recovery finds the region missing",
			Guard: "blocks offline",
			Effects: "disable and destroy under the engine lock (the in-order check repeated after the disable); " +
				"commit (d); a missing region: the record cleared, the grants kept for kubelet",
		},
		{
			From: list(RegionOwned, RegionKept), To: RegionHollowOwned, Triggers: list(TriggerObserve, TriggerRecover),
			When:    "the memdev was removed under the region",
			Effects: "the memdev's Hollow gets the name; commit (l)",
		},
		{
			From: list(RegionHollowOwned), To: RegionNone, Triggers: list(TriggerUnprepare, TriggerPrepare, TriggerRecover),
			When:    "the hollow region deleted",
			Guard:   "every block of its range offline",
			Effects: "delete_region written under the engine lock; commit (d)",
		},
		{
			From: list(RegionNone), To: RegionForeign, Triggers: list(TriggerObserve, TriggerRecover),
			When:    "a region on a memdev that no record of ours names is observed",
			Effects: "published as a region device; its memdev never published as sliced",
		},
		{
			From: list(RegionForeign), To: RegionNone, Triggers: list(TriggerObserve, TriggerRecover),
			When:    "the foreign region is gone",
			Effects: "record removed",
		},
		{
			From: regionStored, To: RegionNone, Triggers: list(TriggerLoad),
			When:    "the document is of another boot",
			Effects: "the record dropped: region names are given anew at every boot",
		},
	},
	Refused: []Refusal[RegionState]{
		{From: list(RegionNone), To: list(RegionCreating), Why: "no creation without the note"},
		{
			From: list(RegionForeign),
			To:   list(RegionNoted, RegionCreating, RegionOwned, RegionKept, RegionHollowOwned),
			Why:  "a foreign region never becomes ours",
		},
	},
}

// RegionSetUpTable is the transition table of Region.SetUp.
var RegionSetUpTable = Table[bool]{
	Object: "Region",
	Field:  "SetUp",
	States: list(false, true),
	Rows: []Transition[bool]{
		{
			From: list(false), To: true, Triggers: list(TriggerPrepare),
			When: "the Whole or first dax device made (local shared: zeroed; pool numa: kmem; pool dax: " +
				"device_dax), or the nd region settled (pmem)",
			Guard:   "the region is OWNED",
			Effects: "commit (d)",
		},
		{
			From: list(true), To: false, Triggers: releasers,
			When:    "the region becomes KEPT (disabled)",
			Effects: "commit (d) with the KEPT state",
		},
	},
}

// daxBound are the states of a dax device bound to a driver.
var daxBound = list(DaxDeviceDax, DaxKmemOffline, DaxKmemOnline)

// DaxDeviceTable is the transition table of DaxDevice.State.
var DaxDeviceTable = Table[DaxDeviceState]{
	Object: "DaxDevice",
	Field:  "State",
	States: list(DaxAbsent, DaxCreating, DaxSized, DaxDeviceDax, DaxKmemOffline, DaxKmemOnline, DaxReleasing, DaxSeed),
	Rows: []Transition[DaxDeviceState]{
		{
			From: list(DaxAbsent), To: DaxCreating, Triggers: list(TriggerPrepare),
			When:    "a grant needs a dax device (or the Whole device at set-up)",
			Guard:   "engine lock held",
			Effects: "dax_region/create written; the name read back",
		},
		{
			From: list(DaxCreating), To: DaxSized, Triggers: list(TriggerPrepare),
			When: "size (or explicit ranges) written and verified",
			Guard: "room in the dax region; whole-block placement verified (created again through the mapping " +
				"attribute if not)",
			Effects: "commit (d) of name, dev and ranges; Users the grant",
		},
		{
			From: list(DaxCreating), To: DaxAbsent, Triggers: list(TriggerPrepare),
			When:    "size or ranges failed, or the verification failed",
			Effects: "deleted; error",
		},
		{
			From: list(DaxAbsent), To: DaxKmemOffline, Triggers: list(TriggerPrepare),
			When:    "the first device (daxN.0) of a new ram region appeared, bound to kmem by the kernel",
			Effects: "its blocks offlined and held offline; commit (d)",
		},
		{
			From: list(DaxKmemOffline), To: DaxSized, Triggers: list(TriggerPrepare),
			When:    "kmem unbound from the offline device (the set-up of a region for device_dax or for slices)",
			Effects: "commit (d)",
		},
		{
			From: list(DaxSized), To: DaxSeed, Triggers: list(TriggerPrepare),
			When:    "daxN.0 resized to 0: the seed of a sliced region",
			Effects: "commit (d)",
		},
		{
			From: list(DaxSeed), To: DaxSized, Triggers: list(TriggerPrepare),
			When:    "the seed sized again (the Whole device of a region set up again)",
			Guard:   "room in the dax region",
			Effects: "commit (d)",
		},
		{
			From: list(DaxSized), To: DaxDeviceDax, Triggers: list(TriggerPrepare),
			When:    "bound to device_dax by sysfs",
			Effects: "zeroed (a local dax grant, a new shared region); commit (d)",
		},
		{
			From: list(DaxSized), To: DaxKmemOffline, Triggers: list(TriggerPrepare),
			When:    "bound to kmem by sysfs bind (never new_id)",
			Guard:   "the NUMA node fenced",
			Effects: "wait for the blocks; commit (d)",
		},
		{
			From: list(DaxKmemOffline), To: DaxKmemOnline, Triggers: list(TriggerPrepare),
			When:    "the blocks onlined movable",
			Guard:   "all blocks exist; the udev online settled",
			Effects: "commit (d); the NUMA node's MemTotal grows",
		},
		{
			From: daxBound, Stays: true, Triggers: releasers,
			When: "a second grant uses the device (a shared device, a shared part, a lease joining), or a user " +
				"grant RELEASING",
			Guard:   "a new user: the device is shareable for that kind",
			Effects: "Users gets the grant or loses it; commit (d)",
		},
		{
			From: list(DaxSized, DaxDeviceDax, DaxKmemOffline, DaxKmemOnline), To: DaxReleasing, Triggers: releasers,
			When:    "Users empty and not kept (the Whole device of a configured shared memdev stays)",
			Effects: "kmem: blocks offlined (EBUSY: stays, error up); unbound; resized to 0",
		},
		{
			From: list(DaxReleasing), To: DaxAbsent, Triggers: releasers,
			When:    "delete written",
			Effects: "commit (d)",
		},
		{
			From: list(DaxReleasing), To: DaxSeed, Triggers: releasers,
			When:    "daxN.0 released: the kernel keeps it at size 0",
			Effects: "commit (d)",
		},
		{
			From:     list(DaxCreating, DaxSized, DaxDeviceDax, DaxKmemOffline, DaxKmemOnline),
			To:       DaxAbsent,
			Triggers: list(TriggerRecover),
			When: "the recovery deletes a dax device of a region of ours without users and not the kept Whole " +
				"device",
			Guard:   "blocks offline first",
			Effects: "deleted",
		},
	},
	Refused: []Refusal[DaxDeviceState]{
		{From: list(DaxSized), To: list(DaxKmemOnline), Why: "never online without the fence step"},
	},
}

// mounted are the states of a mounted Mount.
var mounted = list(MountedRO, MountedRW)

// MountTable is the transition table of Mount.State.
var MountTable = Table[MountState]{
	Object: "Mount",
	Field:  "State",
	States: list(MountAbsent, MountedRO, MountedRW, MountForeign, MountUnrestored, MountStale),
	Rows: []Transition[MountState]{
		{
			From: list(MountAbsent), To: MountedRO, Triggers: list(TriggerPrepare),
			When:  "the first fs grant of the access, no writer grant",
			Guard: "filesystem type allowed and detected; block device set read-only first; the access rules",
			Effects: "mount (direct: dax=always verified; cached: loop and dax=never); commit (d) with Users the " +
				"grant",
		},
		{
			From: list(MountAbsent), To: MountedRW, Triggers: list(TriggerPrepare),
			When: "the first fs grant is a writer (readOnly false)",
			Guard: "a single-host type, or a cluster type on a coherent device; no unexplained superblock (refused " +
				"otherwise: fail closed)",
			Effects: "block device read-write; mount rw; commit (d)",
		},
		{
			From: list(MountedRO), To: MountedRW, Triggers: list(TriggerPrepare),
			When:    "a writer grant arrives on a mounted access",
			Guard:   "type upgradable (ext4, xfs); no unexplained superblock; no other access mounted",
			Effects: "block device, loop device and superblock read-write; commit (d)",
		},
		{
			From: list(MountedRW), To: MountedRO, Triggers: releasers,
			When: "the last writer grant released, readers remain",
			Effects: "syncfs, superblock read-only, loop and block device read-only; EBUSY (a file open for " +
				"write): error up, state unchanged",
		},
		{
			From: mounted, Stays: true, Triggers: releasers,
			When: "an fs grant of the same access arrives, or one is released while others remain; or the " +
				"recovery verified the mount or mounted it again by block device identity",
			Effects: "Users gets the grant or loses it; commit (d)",
		},
		{
			From: mounted, To: MountAbsent, Triggers: releasers,
			When:    "the last user released",
			Effects: "unmounted (never detached); directory removed; commit (d)",
		},
		{
			From: mounted, To: MountStale, Triggers: releasers,
			When: "the unmount failed with EBUSY",
			Effects: "the memdev's Stale list gets the path; retried at every release of the memdev and by the " +
				"periodic pass",
		},
		{
			From:     list(MountStale),
			To:       MountAbsent,
			Triggers: list(TriggerUnprepare, TriggerPrepare, TriggerRecover, TriggerReconcile),
			When:     "a retry unmounts it",
			Effects:  "commit (d)",
		},
		{
			From: list(MountAbsent, MountedRO, MountedRW, MountUnrestored), To: MountUnrestored, Triggers: list(TriggerRecover),
			When: "the recovery cannot mount a REALISED grant's node mount again (region gone, namespace or " +
				"block device changed, mount failed), or fails again at a later start",
			Effects: "the grants of the mount REALISED_UNRESTORED; commit (l)",
		},
		{
			From: list(MountUnrestored), To: MountedRO, Triggers: list(TriggerPrepare, TriggerRecover),
			When:    "a Prepare again, or the recovery at a restart, mounts it, no writer",
			Guard:   "identity verified",
			Effects: "commit (d)",
		},
		{
			From: list(MountUnrestored), To: MountedRW, Triggers: list(TriggerPrepare, TriggerRecover),
			When:    "a Prepare again, or the recovery at a restart, mounts it for a writer",
			Guard:   "identity verified",
			Effects: "commit (d)",
		},
		{
			From: list(MountUnrestored), To: MountAbsent, Triggers: releasers,
			When:    "the last user released",
			Effects: "nothing to unmount; commit (d)",
		},
		{
			From: list(MountAbsent, MountedRO, MountedRW), To: MountForeign, Triggers: list(TriggerRecover),
			When:    "the recovery finds something else mounted at the path",
			Effects: "error logged; never used, never unmounted by the driver; the grants REALISED_UNRESTORED",
		},
	},
	Refused: []Refusal[MountState]{
		{
			From: list(MountForeign),
			To:   list(MountedRO, MountedRW, MountAbsent, MountStale),
			Why:  "a foreign mount is never used or unmounted",
		},
	},
}

// Ref returns the reference of the region: its name, or its noted name
// while it has none.
func (r *Region) Ref() RegionRef {
	if r.Name != "" {
		return RegionRef(r.Name)
	}
	return RegionRef(r.NotedName)
}

// Ours tells whether the region is the driver's.
func (r *Region) Ours() bool {
	return r.Owner == OwnerOurs
}

// DaxDevice returns the dax device with the name, nil if there is none.
func (r *Region) DaxDevice(name string) *DaxDevice {
	for i := range r.DaxDevices {
		if r.DaxDevices[i].Name == name {
			return &r.DaxDevices[i]
		}
	}
	return nil
}

// WholeDevice returns the Whole dax device of the region, nil if there is
// none.
func (r *Region) WholeDevice() *DaxDevice {
	for i := range r.DaxDevices {
		if r.DaxDevices[i].Whole {
			return &r.DaxDevices[i]
		}
	}
	return nil
}

// Mount returns the node mount with the access, nil if there is none.
func (r *Region) Mount(access Access) *Mount {
	for i := range r.Mounts {
		if r.Mounts[i].Access == access {
			return &r.Mounts[i]
		}
	}
	return nil
}

// TargetsSerial tells whether the region targets the memdev with the serial.
func (r *Region) TargetsSerial(serial Serial) bool {
	return slices.Contains(r.Targets, serial)
}
