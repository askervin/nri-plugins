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
	"github.com/containers/nri-plugins/pkg/cxl/config"
)

// Preparation is the record of one claim as one driver prepares it: the
// record that kubelet's prepared flag of the claim refers to. Its results
// say what each allocation result of the driver got: a grant on a memdev,
// a region, the DRAM nodes or the lease claim. The PrepareResult, the CDI
// devices, the env of the containers and their claimed NUMA nodes are
// derived from the results.
//
// Identity: the claim UID and the driver (cxl.nri.io or the pool driver);
// ClaimName is <namespace>/<name> of the claim.
//
// States: PreparationState. UNKNOWN is no record. PREPARING: the record and
// the grants it may realise are committed before any kernel object is
// touched; a process stop here is a cut Prepare. PREPARED: every grant
// realised, the CDI spec written. PREPARED_UNRESTORED: a grant's node mount,
// dax or block device did not verify at a start; no CDI device until a
// Prepare again restores it. PREPARED_STALE: prepared in another boot;
// nothing of it exists in the kernel. UNPREPARING: being released. KEPT: not
// prepared, but a region is kept for the claim because its release would
// leave a decoder hole.
//
// Transitions: PreparationTable below; a transition not in it is refused.
//
// Invariants: a PREPARED preparation's grants are REALISED; a
// PREPARED_UNRESTORED one's are REALISED or REALISED_UNRESTORED; a result of
// kind grant names a grant record of the claim with the result's index; a
// companion claim (Lease set) gives no CDI devices.
//
// Persistence: intent and fact; committed durably before kubelet gets a
// response. BootID is the boot of the Prepare: a record of another boot is
// PREPARED_STALE after the load.
//
// Locks and waits: the kubelet helper serializes Prepare and Unprepare per
// driver; the record is changed only by store commits.
type Preparation struct {
	UID       string           `json:"uid"`
	Driver    string           `json:"driver"`
	ClaimName string           `json:"claimName"`
	BootID    string           `json:"bootID,omitempty"`
	State     PreparationState `json:"state"`
	// Lease is the lease id of a companion claim, "" for other claims.
	Lease string `json:"lease,omitempty"`
	// Reason tells why a preparation is PREPARED_STALE.
	Reason  string   `json:"reason,omitempty"`
	Results []Result `json:"results"`
}

// PreparationState is the state of a Preparation.
type PreparationState string

const (
	PreparationUnknown     PreparationState = "UNKNOWN"
	PreparationPreparing   PreparationState = "PREPARING"
	PreparationPrepared    PreparationState = "PREPARED"
	PreparationUnrestored  PreparationState = "PREPARED_UNRESTORED"
	PreparationStale       PreparationState = "PREPARED_STALE"
	PreparationUnpreparing PreparationState = "UNPREPARING"
	PreparationKept        PreparationState = "KEPT"
)

// ResultKind is the kind of a Result.
type ResultKind string

const (
	// ResultGrant is memory of a memdev given by a grant.
	ResultGrant ResultKind = "grant"
	// ResultRegion is a region that existed before the driver, online as
	// a NUMA node.
	ResultRegion ResultKind = "region"
	// ResultDRAM is the DRAM nodes of the system.
	ResultDRAM ResultKind = "dram"
	// ResultLeaseClaim is the lease device: the lease claim of the claim.
	ResultLeaseClaim ResultKind = "leaseClaim"
)

// Result is one allocation result of the driver in a claim, with what it
// got. Exactly one of Grant, Region, DRAM and LeaseClaim is set, as Kind
// says; a result of kind grant may have Memdev, the facts of its memdev.
type Result struct {
	// Index is the index of the allocation result in the claim, the n of
	// its CDI device claim-<uid>-<n>.
	Index   int        `json:"index"`
	Kind    ResultKind `json:"kind"`
	Request string     `json:"request"`
	// Pool and Device are the DRA pool and device of the allocation
	// result.
	Pool    string `json:"pool"`
	Device  string `json:"device"`
	ShareID string `json:"shareID,omitempty"`
	// Settings are the container settings of the resolved MemoryConfig
	// of the result.
	Settings config.ResultSettings `json:"settings,omitzero"`
	Grant    *GrantRef             `json:"grant,omitempty"`
	// Memdev are the facts of the memdev of a result of kind grant, for
	// the views of the state files (transitional: removed in H6 (schema
	// 2)).
	Memdev     *MemdevResult     `json:"memdev,omitempty"`
	Region     *RegionResult     `json:"region,omitempty"`
	DRAM       *DRAMResult       `json:"dram,omitempty"`
	LeaseClaim *LeaseClaimResult `json:"leaseClaim,omitempty"`
}

// MemdevResult are the facts of the memdev of a result of kind grant at
// its Prepare, for the views of the state files (transitional: removed in
// H6 (schema 2)).
type MemdevResult struct {
	Shared     bool `json:"shared,omitempty"`
	Persistent bool `json:"persistent,omitempty"`
	// NumaAffinity are the CPU NUMA nodes of the memdev.
	NumaAffinity []int `json:"numaAffinity,omitempty"`
}

// RegionResult is a result of kind region: a region that existed before
// the driver.
type RegionResult struct {
	Name string `json:"name"`
	// SysfsPath is the sysfs directory of the region, for the views of
	// the state files (transitional: removed in H6 (schema 2)).
	SysfsPath string `json:"sysfsPath,omitempty"`
	NumaNode  int    `json:"numaNode"`
	Size      uint64 `json:"size"`
	// Consumed is the memory capacity that the allocation consumed.
	Consumed int64 `json:"consumed,omitempty"`
	// NumaAffinity are the CPU NUMA nodes of the memdevs of the region.
	NumaAffinity []int `json:"numaAffinity,omitempty"`
}

// DRAMResult is a result of kind dram.
type DRAMResult struct {
	NumaNodes []int  `json:"numaNodes"`
	Size      uint64 `json:"size"`
	Consumed  int64  `json:"consumed,omitempty"`
}

// LeaseClaimResult is a result of kind leaseClaim: the lease claim record
// with the claim's UID.
type LeaseClaimResult struct {
	UID string `json:"uid"`
	// Consumed is the memory capacity that the allocation consumed.
	Consumed int64 `json:"consumed,omitempty"`
}

// preparationStored are the states of a preparation record in the store.
var preparationStored = list(PreparationPreparing, PreparationPrepared, PreparationUnrestored, PreparationStale,
	PreparationUnpreparing, PreparationKept)

// PreparationTable is the transition table of Preparation.State.
var PreparationTable = Table[PreparationState]{
	Object: "Preparation",
	Field:  "State",
	States: list(PreparationUnknown, PreparationPreparing, PreparationPrepared, PreparationUnrestored,
		PreparationStale, PreparationUnpreparing, PreparationKept),
	Rows: []Transition[PreparationState]{
		{
			From: list(PreparationUnknown), To: PreparationPreparing, Triggers: list(TriggerPrepare),
			When: "validation and the companion gate passed",
			Guard: "allocation present; config decodes; local: device in the last published ResourceSlice; pool: " +
				"status data present",
			Effects: "commit (d) of the preparation with its results (the intent); companion: lease LENDING in the " +
				"same commit",
		},
		{
			From: list(PreparationPreparing), To: PreparationPrepared, Triggers: list(TriggerPrepare),
			When:  "every result realised, CDI spec written",
			Guard: "all grants REALISED",
			Effects: "commit (d) jointly with lease READY (companion) or lease claim OPEN (lease result); kubelet " +
				"gets the result",
		},
		{
			From: list(PreparationPreparing), To: PreparationUnknown, Triggers: list(TriggerPrepare, TriggerUnprepare),
			When: "the Prepare failed and its rollback released everything; or an Unprepare released everything " +
				"recorded",
			Guard:   "no KEPT region, no Stale entry",
			Effects: "commit (d) removing the record; kubelet gets the error (Prepare) or nil (Unprepare)",
		},
		{
			From: list(PreparationPreparing), To: PreparationKept, Triggers: list(TriggerPrepare, TriggerRecover),
			When: "the Prepare failed and its rollback kept a region (in-order release refused); or the recovery " +
				"kept a cut region below newer regions",
			Guard:   "Policy says keep",
			Effects: "commit (d); error to kubelet (retry) or nothing (recovery)",
		},
		{
			From: list(PreparationPreparing), Stays: true, Triggers: list(TriggerRecover),
			When:    "recovery phase 1 of a cut Prepare: leftovers released, the record stays for kubelet's retry",
			Effects: "commit (d) of the grants back to JOURNALED or RELEASED",
		},
		{
			From: list(PreparationPreparing), Stays: true, Triggers: list(TriggerPrepare),
			When:    "Prepare retried by kubelet: continues per result",
			Guard:   "REALISED grants that verify are reused",
			Effects: "as the first Prepare",
		},
		{
			From: list(PreparationPrepared), Stays: true, Triggers: list(TriggerPrepare),
			When:    "Prepare again (kubelet restart, companion re-announce)",
			Effects: "no commit; companion: OnLending and OnPrepared announced again",
		},
		{
			From: list(PreparationPrepared), To: PreparationUnrestored, Triggers: list(TriggerRecover),
			When:    "a grant's objects do not verify (mount, dax or block identity)",
			Effects: "commit (l); no CDI device for the claim; logged",
		},
		{
			From: list(PreparationUnrestored), To: PreparationPrepared, Triggers: list(TriggerPrepare, TriggerRecover),
			When:    "Prepare again, or the recovery at a restart, mounts again or verifies again",
			Guard:   "all grants REALISED again",
			Effects: "commit (d); CDI spec rewritten",
		},
		{
			From: list(PreparationUnrestored), Stays: true, Triggers: list(TriggerRecover),
			When:    "the recovery at a restart fails again",
			Effects: "commit (l); logged",
		},
		{
			From: list(PreparationUnrestored), Stays: true, Triggers: list(TriggerPrepare),
			When:    "Prepare again fails",
			Effects: "error to kubelet",
		},
		{
			From: preparationStored, To: PreparationStale, Triggers: list(TriggerLoad),
			When:  "the record's boot id differs from the running boot",
			Guard: "its driver keeps the records of another boot",
			Effects: "commit (l): grants keep Serial, Source and Asked, Got and Intent cleared; no CDI device; " +
				"nothing released at start",
		},
		{
			From: preparationStored, To: PreparationUnknown, Triggers: list(TriggerLoad),
			When: "the record's boot id differs from the running boot",
			Guard: "its driver drops the records of another boot (cxl.nri.io until its preparations are kept as " +
				"stale)",
			Effects: "commit (l) removing the record and its grants; kubelet's Prepare again prepares the claim anew, " +
				"an Unprepare finds nothing",
		},
		{
			From: list(PreparationStale), To: PreparationPreparing, Triggers: list(TriggerPrepare),
			When:    "Prepare again (kubelet after a reboot)",
			Effects: "the old grants dropped in the same commit (d); then as UNKNOWN -> PREPARING",
		},
		{
			From: list(PreparationStale), Stays: true, Triggers: list(TriggerPrepare),
			When:    "a Prepare again fails validation or the companion gate",
			Effects: "error to kubelet; the record stays for the next Prepare or the Unprepare",
		},
		{
			From: list(PreparationStale), To: PreparationUnknown, Triggers: list(TriggerUnprepare),
			Effects: "release by serial: a pool memdev disabled iff no grant of this boot uses the serial; no " +
				"revoke; commit (d) removing the record",
		},
		{
			From: list(PreparationPrepared, PreparationUnrestored), To: PreparationUnpreparing, Triggers: list(TriggerUnprepare),
			Guard:   "lease claim: CloseClaim returned; companion: OnReleasing done",
			Effects: "commit (d)",
		},
		{
			From: list(PreparationUnpreparing), To: PreparationUnknown, Triggers: list(TriggerUnprepare),
			When:    "every grant RELEASED",
			Effects: "commit (d) removing the record; kubelet gets nil",
		},
		{
			From: list(PreparationUnpreparing), Stays: true, Triggers: list(TriggerUnprepare),
			When: "a release step failed (EBUSY, a revoke before the lender is set up)",
			Effects: "error to kubelet (retried about every second); records unchanged; the retry finds out from " +
				"the kernel what exists",
		},
		{
			From: list(PreparationUnpreparing), Stays: true, Triggers: list(TriggerRecover),
			When: "the record at the start: no remount; cxl.nri.io's CDI spec keeps the claim's devices " +
				"(CDIUnpreparing) until kubelet's Unprepare retry removes them, the pool driver's has none",
			Effects: "nothing at start",
		},
		{
			From: list(PreparationUnpreparing), Stays: true, Triggers: list(TriggerPrepare),
			When:    "a Prepare again before kubelet's Unprepare retry",
			Effects: "the result is returned as prepared (both drivers); a companion is announced again; no commit",
		},
		{
			From: list(PreparationKept), To: PreparationPreparing, Triggers: list(TriggerPrepare),
			When:    "Prepare again",
			Effects: "the kept region is enabled and set up again",
		},
		{
			From: list(PreparationKept), Stays: true, Triggers: list(TriggerPrepare),
			When:    "a Prepare again fails validation or the companion gate",
			Effects: "error to kubelet; the record and the kept region stay for the next Prepare or the Unprepare",
		},
		{
			From: list(PreparationKept), To: PreparationUnknown, Triggers: list(TriggerUnprepare),
			Effects: "the kept region destroyed per Policy; commit (d) removing the record",
		},
		{
			From: list(PreparationKept), Stays: true, Triggers: list(TriggerRecover),
			When:    "the recovery at a later start released some of its kept grants and kept the others",
			Effects: "commit (d) dropping the results of the released grants",
		},
		{
			From: list(PreparationKept), To: PreparationUnknown, Triggers: list(TriggerRecover),
			When: "the recovery at a later start released every grant that it kept (nothing lies above its " +
				"regions any more, or its idle shared memdev keeps its region)",
			Effects: "commit (d) removing the record; kubelet's Prepare again prepares the claim anew, its " +
				"Unprepare finds nothing",
		},
	},
	Refused: []Refusal[PreparationState]{
		{
			From: list(PreparationPrepared),
			To:   list(PreparationPreparing),
			Why:  "a Prepare again never realises a PREPARED claim anew within a boot",
		},
		{From: list(PreparationUnknown), To: list(PreparationPrepared), Why: "nothing is prepared without the intent commit"},
	},
}

// Prepared tells whether kubelet may take the claim as prepared: PREPARED,
// PREPARED_UNRESTORED or UNPREPARING.
func (p *Preparation) Prepared() bool {
	switch p.State {
	case PreparationPrepared, PreparationUnrestored, PreparationUnpreparing:
		return true
	}
	return false
}

// Result returns the result with the index n, nil if there is none.
func (p *Preparation) Result(n int) *Result {
	for i := range p.Results {
		if p.Results[i].Index == n {
			return &p.Results[i]
		}
	}
	return nil
}
