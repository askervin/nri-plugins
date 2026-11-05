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

// LeaseClaim is a claim on the lease device, prepared by cxl.nri.io for a
// pod: its lease socket, its directories and the pods it is reserved for.
// It owns <data dir>/leases/<uid>/cxl.sock, <data dir>/leases/<uid>/fs and,
// with FsDir, <data dir>/lease-fs/<uid>; the CDI device lease-<uid> gives
// them to the claim's containers.
//
// Identity: UID, the claim UID (also the socket directory and the CDI
// device name); Namespace and Name of the claim.
//
// States: LeaseClaimState. NONE: no record. OPEN: listening.
// OPEN_NO_LISTENER: listening again at a start failed; retried. CLOSING:
// CloseClaim releases every lease of the claim; new requests are refused;
// a start listens on it again.
// CLOSED: listener and connections closed, record removed. REMOVING: its
// directories are being removed (a bind still mounted keeps
// lease-fs/<uid> until the last lease is gone).
//
// Transitions: LeaseClaimTable below; a transition not in it is refused.
//
// Invariants: a lease claim in the store is OPEN, OPEN_NO_LISTENER or
// CLOSING; lease-fs/<uid> and leases/<uid> exist only for lease claims of
// prepared claims.
//
// Persistence: fact; committed jointly with the Preparation PREPARED of the
// claim. Kept across reboots: kubelet prepares the claim again.
//
// Locks and waits: the broker's mutex; CloseClaim waits up to 5 s for the
// leases of the claim.
type LeaseClaim struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Pods are the pods of reservedFor at the Prepare, refreshed when a
	// peer's pod is unknown.
	Pods []PodRef `json:"pods"`
	// FsDir is <data dir>/lease-fs/<uid>, "" for a claim prepared by a
	// driver without fs leases.
	FsDir string          `json:"fsDir,omitempty"`
	State LeaseClaimState `json:"state"`
}

// LeaseClaimState is the state of a LeaseClaim.
type LeaseClaimState string

const (
	LeaseClaimNone           LeaseClaimState = "NONE"
	LeaseClaimOpen           LeaseClaimState = "OPEN"
	LeaseClaimOpenNoListener LeaseClaimState = "OPEN_NO_LISTENER"
	LeaseClaimClosing        LeaseClaimState = "CLOSING"
	LeaseClaimClosed         LeaseClaimState = "CLOSED"
	LeaseClaimRemoving       LeaseClaimState = "REMOVING"
)

// LeaseClaimTable is the transition table of LeaseClaim.State.
var LeaseClaimTable = Table[LeaseClaimState]{
	Object: "LeaseClaim",
	Field:  "State",
	States: list(LeaseClaimNone, LeaseClaimOpen, LeaseClaimOpenNoListener,
		LeaseClaimClosing, LeaseClaimClosed, LeaseClaimRemoving),
	Rows: []Transition[LeaseClaimState]{
		{
			From: list(LeaseClaimNone), To: LeaseClaimOpen, Triggers: list(TriggerPrepare),
			When: "a Prepare of a claim with a lease result (OpenClaim)",
			Effects: "socket created in a private directory and renamed; CDI device lease-<uid>; FsDir made; " +
				"commit (d) jointly with the Preparation PREPARED",
		},
		{
			From: list(LeaseClaimOpen), Stays: true, Triggers: list(TriggerPrepare, TriggerRequest),
			When:    "OpenClaim again; Pods refreshed from reservedFor when a peer's pod is unknown",
			Effects: "commit (l)",
		},
		{
			From: list(LeaseClaimOpen), Stays: true, Triggers: list(TriggerRecover),
			When:  "the start listens on the socket again",
			Guard: "listen succeeded",
		},
		{
			From: list(LeaseClaimOpen), To: LeaseClaimOpenNoListener, Triggers: list(TriggerRecover),
			When:    "listening again at the start failed",
			Effects: "logged; retried by the reconcile",
		},
		{
			From: list(LeaseClaimOpenNoListener), To: LeaseClaimOpen, Triggers: list(TriggerReconcile, TriggerRecover),
			When: "a retry listens",
		},
		{
			From: list(LeaseClaimOpen, LeaseClaimOpenNoListener), To: LeaseClaimClosing, Triggers: list(TriggerUnprepare),
			When:    "an Unprepare of the claim (CloseClaim)",
			Effects: "every lease of the claim RELEASING; new requests on the socket refused; commit (d)",
		},
		{
			From: list(LeaseClaimClosing), To: LeaseClaimOpen, Triggers: list(TriggerRecover),
			When:  "the start listens on the socket of a claim whose close was cut",
			Guard: "listen succeeded",
			Effects: "commit (l); kubelet's Unprepare retry closes the claim again (requests on the socket are " +
				"served until then, as on an OPEN claim)",
		},
		{
			From: list(LeaseClaimClosing), Stays: true, Triggers: list(TriggerUnprepare),
			When:    "within 5 s not every lease has DeletionRequested",
			Effects: "\"still releasing N leases\" to kubelet (retry)",
		},
		{
			From: list(LeaseClaimClosing), To: LeaseClaimClosed, Triggers: list(TriggerUnprepare),
			When:    "every lease has DeletionRequested (not necessarily gone)",
			Effects: "listener and open connections closed; CDI device removed; commit (d) removing the record",
		},
		{
			From:     list(LeaseClaimClosed),
			To:       LeaseClaimRemoving,
			Triggers: list(TriggerRelease, TriggerReconcile, TriggerRecover),
			When:     "the last lease of the claim gone",
			Guard:    "no bind mounted under its FsDir",
			Effects:  "directories removed",
		},
		{
			From: list(LeaseClaimRemoving), To: LeaseClaimNone, Triggers: list(TriggerRelease, TriggerReconcile, TriggerRecover),
			When: "directories removed",
		},
	},
	Refused: []Refusal[LeaseClaimState]{
		{
			From: list(LeaseClaimClosing), To: list(LeaseClaimOpen), Except: list(TriggerRecover),
			Why: "a closing claim is not opened again but by the start",
		},
	},
}
