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

// Memdev is the engine's record of one memdev under the driver's care,
// local or pool: its facts, the regions of ours on it, the hollow regions
// and stale mounts and binds left to delete, and its grants.
//
// Identity: Serial. Name is the kernel's memN at the last observation; it
// changes with the probe order.
//
// States: MemdevState. UNUSED: no grant and no region of ours, not in the
// store. ACTIVE: at least one grant. IDLE_KEPT: no grant, its region kept
// (a configured shared device; a persistent device below newer regions; a
// region that a rollback or the recovery kept below newer regions). GONE:
// the memdev is absent while grants exist (a pool device detached under us, a local hot-remove).
// Busy (in memory only, MemdevBusyTable): a wait or zeroing of the memdev is
// in progress outside the engine lock; other requests for the memdev queue.
//
// Transitions: MemdevTable and MemdevBusyTable below; a transition not in
// them is refused.
//
// Invariants: Regions name Region records that target the serial; Grants
// name the grant records of the serial; a memdev in the store is not
// UNUSED.
//
// Persistence: fact; committed with the grants that change it. A load in
// another boot drops the record: its regions, dax devices, mounts and
// binds do not survive a reboot.
//
// Locks and waits: the engine's per-memdev request queue; kernel commands
// under the engine lock; waits outside it with Busy set.
type Memdev struct {
	Serial  Serial      `json:"serial"`
	Name    string      `json:"name,omitempty"`
	Source  Source      `json:"source"`
	Facts   MemdevFacts `json:"facts"`
	Regions []RegionRef `json:"regions,omitempty"`
	// Hollow are the hollow regions of ours on the memdev, deleted when
	// their blocks are offline.
	Hollow []RegionRef `json:"hollow,omitempty"`
	// Stale are the node mounts and lease binds whose unmount failed
	// busy, retried at every release of the memdev and by the periodic
	// pass.
	Stale  []StalePath `json:"stale,omitempty"`
	Grants []GrantRef  `json:"grants,omitempty"`
	State  MemdevState `json:"state"`
}

// MemdevFacts are what the driver knows of a memdev from the kernel, the
// configuration and the pool.
type MemdevFacts struct {
	// Ram and Pmem are the volatile and persistent capacities in bytes.
	Ram  uint64 `json:"ram,omitempty"`
	Pmem uint64 `json:"pmem,omitempty"`
	// Usable is the number of bytes the driver uses, 0 for all of it (the
	// configured usable size and the address line probe).
	Usable     uint64 `json:"usable,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	Persistent bool   `json:"persistent,omitempty"`
	Coherent   bool   `json:"coherent,omitempty"`
	// BlockSize is the memory block size of the system.
	BlockSize uint64 `json:"blockSize,omitempty"`
	// NumaAffinity is the CPU NUMA node of the memdev.
	NumaAffinity *int   `json:"numaAffinity,omitempty"`
	HostBridge   string `json:"hostBridge,omitempty"`
}

// StalePath is a node mount or lease bind whose unmount failed busy.
type StalePath struct {
	Path string    `json:"path"`
	Kind StaleKind `json:"kind"`
}

// StaleKind is what a StalePath is.
type StaleKind string

const (
	StaleMount StaleKind = "mount"
	StaleBind  StaleKind = "bind"
)

// MemdevState is the state of a Memdev.
type MemdevState string

const (
	MemdevUnused   MemdevState = "UNUSED"
	MemdevActive   MemdevState = "ACTIVE"
	MemdevIdleKept MemdevState = "IDLE_KEPT"
	MemdevGone     MemdevState = "GONE"
)

// MemdevTable is the transition table of Memdev.State.
var MemdevTable = Table[MemdevState]{
	Object: "Memdev",
	Field:  "State",
	States: list(MemdevUnused, MemdevActive, MemdevIdleKept, MemdevGone),
	Rows: []Transition[MemdevState]{
		{
			From: list(MemdevUnused), To: MemdevActive, Triggers: list(TriggerPrepare),
			When:  "the first grant of the serial is JOURNALED",
			Guard: "provenance allows the source",
			Effects: "commit (d) with the facts (ram, pmem, usable, shared, persistent, block size, host bridge); " +
				"pool: provenance POOL in the same commit",
		},
		{
			From: list(MemdevActive), Stays: true, Triggers: list(TriggerPrepare, TriggerUnprepare, TriggerRecover),
			When:    "grants come and go while at least one remains",
			Effects: "commits with the grants",
		},
		{
			From: list(MemdevActive), To: MemdevUnused, Triggers: releasers,
			When: "the last grant RELEASED and Policy says destroy (local sliced, local shared not configured any " +
				"more, pool)",
			Guard:   "the region destroyed; a pool memdev disabled",
			Effects: "commit (d) removing the record",
		},
		{
			From: list(MemdevActive), To: MemdevIdleKept, Triggers: releasers,
			When: "the last grant RELEASED and Policy says keep (local shared while configured; local persistent " +
				"with regions above; a rollback or recovery that keeps)",
			Effects: "commit (d)",
		},
		{
			From: list(MemdevIdleKept), To: MemdevActive, Triggers: list(TriggerPrepare),
			When:    "a new grant JOURNALED",
			Guard:   "the kept region enabled and set up again if needed",
			Effects: "commit (d)",
		},
		{
			From: list(MemdevIdleKept), To: MemdevUnused, Triggers: list(TriggerRecover, TriggerPrepare),
			When: "the recovery or the next Prepare of the memdev finds the keep reason gone (shared not " +
				"configured any more; nothing above a kept persistent region; an idle leftover)",
			Guard:   "Policy says destroy",
			Effects: "region destroyed; commit (d) removing the record",
		},
		{
			From:     list(MemdevActive, MemdevIdleKept),
			To:       MemdevGone,
			Triggers: list(TriggerRecover, TriggerObserve),
			When: "the memdev is absent at the start, or it went while grants exist (pool device detached under " +
				"us; local hot-remove)",
			Effects: "commit (l); the hollow regions of ours noted in Hollow; grants kept for kubelet's Unprepare",
		},
		{
			From: list(MemdevGone), To: MemdevUnused, Triggers: list(TriggerUnprepare, TriggerRecover),
			When:    "the last grant RELEASED (by serial) and Hollow empty",
			Guard:   "hollow regions deleted when their blocks are offline",
			Effects: "commit (d) removing the record",
		},
		{
			From: list(MemdevGone), To: MemdevActive, Triggers: list(TriggerObserve, TriggerRecover),
			When:    "the memdev appeared while grants exist (the same serial attached again)",
			Guard:   "the grants are of PREPARED_STALE preparations or REALISED with objects to verify",
			Effects: "commit (l)",
		},
		{
			From: list(MemdevActive, MemdevIdleKept, MemdevGone), To: MemdevUnused, Triggers: list(TriggerLoad),
			When:    "the document is of another boot",
			Effects: "the record dropped: its regions, dax devices, mounts and binds did not survive the reboot",
		},
	},
	Refused: []Refusal[MemdevState]{
		{From: list(MemdevUnused), To: list(MemdevIdleKept), Why: "a kept region always had a grant or a cut first"},
	},
}

// MemdevBusyTable is the transition table of the Busy flag of a memdev,
// held by the engine in memory.
var MemdevBusyTable = Table[bool]{
	Object: "Memdev",
	Field:  "Busy",
	States: list(false, true),
	Rows: []Transition[bool]{
		{
			From: list(false), To: true, Triggers: list(TriggerPrepare, TriggerUnprepare, TriggerRecover),
			When:    "a wait (memdev appearance, nd settle, holder) or zeroing starts outside the engine lock",
			Effects: "other requests for the memdev queue",
		},
		{
			From: list(true), To: false, Triggers: list(TriggerPrepare, TriggerUnprepare, TriggerRecover),
			When:    "the wait or zeroing ends (success, timeout or error)",
			Effects: "the queue proceeds",
		},
	},
}

// HasGrant tells whether the memdev lists the grant ref.
func (m *Memdev) HasGrant(ref GrantRef) bool {
	return slices.Contains(m.Grants, ref)
}

// HasRegion tells whether the memdev lists the region ref among its
// regions or its hollow regions.
func (m *Memdev) HasRegion(ref RegionRef) bool {
	return slices.Contains(m.Regions, ref) || slices.Contains(m.Hollow, ref)
}
