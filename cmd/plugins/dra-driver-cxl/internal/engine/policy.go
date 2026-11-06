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
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
)

// Release is what releases the region of a memdev whose last grant goes,
// the column of the release policy.
type Release string

const (
	// ReleaseUnprepare is the Unprepare of the last grant of the memdev.
	ReleaseUnprepare Release = "unprepare"
	// ReleaseRollback is the rollback of a Prepare that failed.
	ReleaseRollback Release = "rollback"
	// ReleaseRecovery is the release of a Prepare that a process stop cut,
	// at the start.
	ReleaseRecovery Release = "recovery"
	// ReleaseIdle is the release of a region of the driver that no grant
	// and no cut Prepare holds, at the start or at the next Prepare of the
	// memdev.
	ReleaseIdle Release = "idle"
)

// Kind is how the grants of a memdev use it, the row of the release
// policy.
type Kind string

const (
	// KindLocalSliced is a local memdev whose grants have parts of it.
	KindLocalSliced Kind = "local sliced"
	// KindLocalShared is a local memdev configured shared whose region is
	// established: set up and zeroed, or kept by an earlier release.
	KindLocalShared Kind = "local shared"
	// KindLocalSharedNew is a local memdev configured shared whose region a
	// Prepare made and did not set up or zero (it failed or was cut).
	KindLocalSharedNew Kind = "local shared, new region"
	// KindLocalUnshared is a local memdev used shared that is not
	// configured shared any more, its region established.
	KindLocalUnshared Kind = "local unshared"
	// KindLocalUnsharedNew is a local memdev used shared that is not
	// configured shared any more, its region new (KindLocalSharedNew).
	KindLocalUnsharedNew Kind = "local unshared, new region"
	// KindLocalPersistent is a local memdev of persistent memory whose
	// region is established: set up, or kept by an earlier release.
	KindLocalPersistent Kind = "local persistent"
	// KindLocalPersistentNew is a local memdev of persistent memory whose
	// region a Prepare made and did not set up (it failed or was cut).
	KindLocalPersistentNew Kind = "local persistent, new region"
	// KindPoolExclusive is a pool device of one grant.
	KindPoolExclusive Kind = "pool exclusive"
	// KindPoolShared is a pool device that several grants share.
	KindPoolShared Kind = "pool shared"
	// KindPoolPersistent is a pool device of persistent memory.
	KindPoolPersistent Kind = "pool persistent"
)

// Decision is what the release does with the region of a memdev, and
// whom a region that stays is for.
type Decision string

const (
	// Destroy releases the region, also below a newer region of another
	// memdev (a hole left in the decoders of a port).
	Destroy Decision = "destroy"
	// InOrder releases the region unless a newer region of another memdev
	// lies above it in the decoders of a port, before or after its
	// disable: then the region stays (disabled when the newer one came
	// during the release) for the claim of a rollback or a recovery
	// (KEPT), for the idle memdev of an Unprepare or an idle release.
	InOrder Decision = "in order"
	// InOrderIdle is InOrder with a region that stays for the idle memdev
	// also at a rollback or a recovery.
	InOrderIdle Decision = "in order, kept idle"
	// Keep leaves the region as it is, for the claim of a rollback or a
	// recovery (KEPT), for the idle memdev of an Unprepare or an idle
	// release.
	Keep Decision = "keep"
	// KeepIdle leaves the region as it is for the idle memdev, also at a
	// rollback or a recovery.
	KeepIdle Decision = "keep idle"
)

// forClaim tells whether a region that the decision keeps at the release
// is kept for the claim of the released grant (KEPT), not for the idle
// memdev.
func (d Decision) forClaim(release Release) bool {
	return (d == InOrder || d == Keep) && (release == ReleaseRollback || release == ReleaseRecovery)
}

// inOrder tells whether the decision releases the region in order.
func (d Decision) inOrder() bool {
	return d == InOrder || d == InOrderIdle
}

// keeps tells whether the decision leaves the region as it is.
func (d Decision) keeps() bool {
	return d == Keep || d == KeepIdle
}

// localPolicy are the decisions of the release policy for the kinds of
// local memdevs, by release: a sliced memdev is released in the order that
// the user chose (a hole is allowed), a shared one is kept while it is
// configured shared (zeroed once), a persistent one is kept idle while
// regions of other memdevs lie above it.
var localPolicy = map[Kind]map[Release]Decision{
	//                                Unprepare    rollback  recovery     idle
	KindLocalSliced:        byRelease(Destroy, InOrder, InOrder, Destroy),
	KindLocalShared:        byRelease(KeepIdle, KeepIdle, KeepIdle, KeepIdle),
	KindLocalSharedNew:     byRelease(KeepIdle, InOrder, InOrder, KeepIdle),
	KindLocalUnshared:      byRelease(Destroy, InOrder, Destroy, Destroy),
	KindLocalUnsharedNew:   byRelease(Destroy, InOrder, InOrder, Destroy),
	KindLocalPersistent:    byRelease(InOrderIdle, InOrder, InOrderIdle, InOrderIdle),
	KindLocalPersistentNew: byRelease(InOrderIdle, InOrder, InOrder, InOrderIdle),
}

// byRelease returns the decisions of a row of the release policy.
func byRelease(unprepare, rollback, recovery, idle Decision) map[Release]Decision {
	return map[Release]Decision{ReleaseUnprepare: unprepare, ReleaseRollback: rollback, ReleaseRecovery: recovery,
		ReleaseIdle: idle}
}

// Policy returns what happens to the region of a memdev of a kind when its
// last grant goes by release, with the regions of other memdevs above its
// regions now (regionsAbove).
func Policy(release Release, kind Kind, regionsAbove []string) Decision {
	switch kind {
	case KindPoolExclusive, KindPoolShared, KindPoolPersistent:
		// a kept pool region would block the hot-remove of the device
		if release == ReleaseRecovery && len(regionsAbove) > 0 {
			return Keep
		}
		return Destroy
	}
	if d, ok := localPolicy[kind][release]; ok {
		return d
	}
	return Keep
}

// kindOf returns the row of the release policy of a memdev of the source
// whose grants ask as asked; shared tells whether a local memdev is
// configured shared now, established whether its region is set up (and
// zeroed, of a shared memdev) or kept by an earlier release.
func kindOf(asked state.Asked, shared, established bool) Kind {
	if asked.Source == state.SourcePool {
		switch asked.Kind {
		case state.KindPersistent:
			return KindPoolPersistent
		case state.KindShared:
			return KindPoolShared
		}
		return KindPoolExclusive
	}
	switch {
	case asked.Kind == state.KindPersistent && established:
		return KindLocalPersistent
	case asked.Kind == state.KindPersistent:
		return KindLocalPersistentNew
	case asked.Kind == state.KindShared && shared && established:
		return KindLocalShared
	case asked.Kind == state.KindShared && shared:
		return KindLocalSharedNew
	case asked.Kind == state.KindShared && established:
		return KindLocalUnshared
	case asked.Kind == state.KindShared:
		return KindLocalUnsharedNew
	}
	return KindLocalSliced
}
