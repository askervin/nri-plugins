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
	"time"
)

// Lease is one request of a running container for memory, served through
// the socket of its lease claim. Its memory comes from a companion claim
// cxl-lease-<id> whose grants the broker lends to the requester. The lease
// owns its Lend.
//
// Identity: ID, 8 hex digits; the requester (Pod, Container); Claim, the
// UID of the lease claim whose socket received the request; RequestID, the
// client's idempotency key.
//
// States: LeaseState (the protocol's words). NONE: no record. CREATING:
// stored before any API object exists. PENDING: the companion claim and
// pod exist. LENDING: the companion claim's Prepare passed the companion
// gate. READY: fd passable, bind mounted or NUMA node lent. RELEASING: the
// deletion of the companion is requested, the lend revoked first.
// RELEASING_BUSY: the companion's unbind failed busy (a mapped file); the
// companion stays Terminating until the holder ends. FAILED: Error says
// why; a failed lease is released in place and stays FAILED until it is
// gone, so that a list shows why.
//
// Transitions: LeaseTable below; a transition not in it is refused.
//
// Invariants: Lend is set only while the lease is READY, RELEASING,
// RELEASING_BUSY or FAILED; no lend on a NUMA node whose memory is
// offline.
//
// Persistence: intent (CREATING before the API objects) and fact. A load in
// another boot drops every lease; the first reconcile deletes their
// companions.
//
// Locks and waits: the broker's mutex, never held across a lender or API
// call.
type Lease struct {
	ID        string     `json:"id"`
	Claim     string     `json:"claim"`
	RequestID string     `json:"requestId,omitempty"`
	Pod       PodRef     `json:"pod"`
	Container string     `json:"container"`
	Asked     LeaseAsked `json:"asked"`
	// Got is what the companion claim's Prepare gave, set at READY.
	Got   *LeaseGot  `json:"got,omitempty"`
	State LeaseState `json:"state"`
	Error string     `json:"error,omitempty"`
	// ReleaseRequested: a release was started.
	ReleaseRequested bool `json:"releaseRequested,omitempty"`
	// DeletionRequested: the deletion of the companion pod and claim was
	// requested.
	DeletionRequested bool      `json:"deletionRequested,omitempty"`
	Lend              *Lend     `json:"lend,omitempty"`
	Created           time.Time `json:"created"`
}

// LeaseAsked is what a lease request asks for.
type LeaseAsked struct {
	// Source is the requested source, "" for local, then pool.
	Source Source `json:"source,omitempty"`
	// DeviceSource is the source of the device that Serial names when
	// no source was requested.
	DeviceSource Source `json:"deviceSource,omitempty"`
	// Mode is the effective mode.
	Mode   Mode `json:"mode"`
	Shared bool `json:"shared,omitempty"`
	// SharedDevice: the ResourceSlice has the device as a shared one.
	SharedDevice bool `json:"sharedDevice,omitempty"`
	// ReadOnly of dax and block: the fd is read-only.
	ReadOnly bool `json:"readOnly,omitempty"`
	// ReadWrite of fs: the opt-in to mount read-write.
	ReadWrite bool   `json:"readWrite,omitempty"`
	Access    Access `json:"access,omitempty"`
	FsType    string `json:"fsType,omitempty"`
	// Name is the mount point of an fs lease, unique per lease claim.
	Name string `json:"name,omitempty"`
	// Size is the requested quantity.
	Size   string `json:"size,omitempty"`
	Serial Serial `json:"serial,omitzero"`
}

// LeaseGot is what the companion claim's Prepare gave a lease.
type LeaseGot struct {
	Source Source `json:"source,omitempty"`
	Serial Serial `json:"serial,omitzero"`
	// SharedDevice: the prepared device is a shared device.
	SharedDevice bool   `json:"sharedDevice,omitempty"`
	Bytes        uint64 `json:"bytes,omitempty"`
	// Dax and Block are the host paths of the device of a dax or block
	// lease.
	Dax    string `json:"dax,omitempty"`
	Block  string `json:"block,omitempty"`
	Access Access `json:"access,omitempty"`
	FsType string `json:"fsType,omitempty"`
	// Path is the directory of the filesystem of an fs lease in the
	// container.
	Path string `json:"path,omitempty"`
}

// Lend is what a lease lends its requester: a NUMA node added to its
// cpuset.mems (numa) or a bind of a node mount (fs).
type Lend struct {
	NumaNode   *int   `json:"numaNode,omitempty"`
	BindTarget string `json:"bindTarget,omitempty"`
}

// LeaseState is the state of a Lease.
type LeaseState string

const (
	LeaseNone          LeaseState = "NONE"
	LeaseCreating      LeaseState = "CREATING"
	LeasePending       LeaseState = "PENDING"
	LeaseLending       LeaseState = "LENDING"
	LeaseReady         LeaseState = "READY"
	LeaseReleasing     LeaseState = "RELEASING"
	LeaseReleasingBusy LeaseState = "RELEASING_BUSY"
	LeaseFailed        LeaseState = "FAILED"
)

// leaseStored are the states of a lease record in the store.
var leaseStored = list(LeaseCreating, LeasePending, LeaseLending, LeaseReady, LeaseReleasing, LeaseReleasingBusy, LeaseFailed)

// LeaseTable is the transition table of Lease.State.
var LeaseTable = Table[LeaseState]{
	Object: "Lease",
	Field:  "State",
	States: list(LeaseNone, LeaseCreating, LeasePending, LeaseLending,
		LeaseReady, LeaseReleasing, LeaseReleasingBusy, LeaseFailed),
	Rows: []Transition[LeaseState]{
		{
			From: list(LeaseNone), To: LeaseCreating, Triggers: list(TriggerRequest),
			When:    "a request on a lease claim's socket: authenticated, validated, serial resolved",
			Guard:   "the lease claim OPEN",
			Effects: "commit (d) before any API object exists",
		},
		{
			From: list(LeaseCreating), To: LeasePending, Triggers: list(TriggerRequest),
			When:    "the companion claim and pod created",
			Guard:   "still CREATING (OnLending may have won)",
			Effects: "commit (d)",
		},
		{
			From: list(LeaseCreating), To: LeaseFailed, Triggers: list(TriggerRequest),
			When:    "the companion creation failed (AlreadyExists, API error)",
			Effects: "commit (d); then the release starts",
		},
		{
			From: list(LeaseCreating, LeasePending), To: LeaseLending, Triggers: list(TriggerOnLending),
			When:    "the companion gate passed (name, namespace, owner, state; the spec hash on this first Prepare)",
			Effects: "commit (d) jointly with the Preparation PREPARING",
		},
		{
			From: list(LeaseLending, LeaseReady), Stays: true, Triggers: list(TriggerOnLending),
			When:    "a retried or announced-again Prepare of the companion",
			Effects: "no commit",
		},
		{
			From: list(LeaseLending), To: LeaseReady, Triggers: list(TriggerOnPrepared),
			When:  "the companion's Prepare hands over the lent devices",
			Guard: "the mode matches",
			Effects: "commit (d) jointly with the companion PREPARED; the waiting client gets the response (fd for " +
				"dax and block)",
		},
		{
			From: list(LeaseReady), Stays: true, Triggers: list(TriggerOnPrepared),
			When:    "the companion's Prepare announced again",
			Effects: "no commit",
		},
		{
			From: list(LeaseLending), Stays: true, Triggers: list(TriggerPrepare),
			When:    "the companion's device preparation failed (kubelet retries)",
			Effects: "no commit; the client waits until its --wait ends",
		},
		{
			From: list(LeaseLending, LeaseReady), To: LeaseFailed, Triggers: list(TriggerOnLendFailed, TriggerOnPrepared),
			When:    "a bind or lend error; a wrong mode",
			Effects: "commit (d); the release starts",
		},
		{
			From:     list(LeaseCreating, LeasePending, LeaseLending, LeaseReady, LeaseFailed),
			To:       LeaseFailed,
			Triggers: list(TriggerOnReleasing),
			When:     "the companion claim unprepared behind the broker (the companion pod deleted by someone)",
			Effects:  "commit (d); the reconcile releases it",
		},
		{
			From: list(LeasePending, LeaseLending), To: LeaseReleasing, Triggers: list(TriggerRequest),
			When:    "the request's --wait ended",
			Effects: "the client gets Failed \"timeout: not Ready after D\"; commit (d)",
		},
		{
			From: list(LeaseReady), To: LeaseReleasing, Triggers: list(TriggerRelease, TriggerUnprepare, TriggerReconcile),
			When: "a release by the client; the requester pod done; CloseClaim of the lease claim; the reconcile " +
				"(companion gone)",
			Effects: "commit (d) of ReleaseRequested; the node revoked; pod and claim deleted (Foreground); " +
				"DeletionRequested (d)",
		},
		{
			From: list(LeaseFailed), Stays: true, Triggers: list(TriggerRelease, TriggerReconcile, TriggerUnprepare),
			When: "the release after the failure, the reconcile, or CloseClaim",
			Effects: "released in place: commit (d) of ReleaseRequested; the node revoked; pod and claim deleted " +
				"(Foreground); DeletionRequested (d); the lease stays FAILED so that a list shows why",
		},
		{
			From: list(LeaseFailed), To: LeaseNone, Triggers: list(TriggerRelease, TriggerReconcile),
			When:    "pod and claim both NotFound",
			Effects: "commit (d) removing the lease",
		},
		{
			From: list(LeaseReady), To: LeaseFailed, Triggers: list(TriggerRecover),
			When:    "the companion's bind cannot be restored at a start: its Preparation is PREPARED_UNRESTORED",
			Effects: "commit (d); the release starts; the requester's next list shows the lease Failed",
		},
		{
			From: list(LeaseReady, LeaseReleasing), To: LeaseReleasingBusy, Triggers: list(TriggerUnprepare),
			When:    "the companion's unbind failed with EBUSY (a mapped file)",
			Effects: "commit (d); the companion stays Terminating; reads work until the holder ends",
		},
		{
			From: list(LeaseReleasingBusy), To: LeaseReleasing, Triggers: list(TriggerUnprepare, TriggerReconcile),
			When:    "the holder ended and the unbind succeeded",
			Effects: "commit (d)",
		},
		{
			From: list(LeaseReleasing), To: LeaseNone, Triggers: list(TriggerRelease, TriggerReconcile),
			When: "pod and claim both NotFound",
			Effects: "commit (d) removing the lease; the lease claim's directories removed when CLOSED and no " +
				"lease left",
		},
		{
			From: list(LeaseReleasing), Stays: true, Triggers: list(TriggerRecover),
			When:    "the record at a start: ReleaseRequested set, the release is not running",
			Effects: "the first reconcile starts the release again",
		},
		{
			From: list(LeaseCreating), To: LeaseReleasing, Triggers: list(TriggerReconcile),
			When:    "the record older than 2 min at a start (left over by a crash)",
			Effects: "commit (d)",
		},
		{
			From: leaseStored, To: LeaseNone, Triggers: list(TriggerLoad),
			When:    "the document is of another boot",
			Effects: "dropped; the companions deleted by the first reconcile",
		},
	},
	Refused: []Refusal[LeaseState]{
		{From: list(LeaseReady), To: list(LeasePending), Why: "a lent lease does not go back"},
		{From: list(LeaseReleasing), To: list(LeaseReady), Why: "a release is not undone"},
	},
}
