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
	// KindLocalShared is a local memdev configured shared.
	KindLocalShared Kind = "local shared"
	// KindLocalUnshared is a local memdev used shared that is not
	// configured shared any more.
	KindLocalUnshared Kind = "local unshared"
	// KindLocalPersistent is a local memdev of persistent memory.
	KindLocalPersistent Kind = "local persistent"
	// KindPoolExclusive is a pool device of one grant.
	KindPoolExclusive Kind = "pool exclusive"
	// KindPoolShared is a pool device that several grants share.
	KindPoolShared Kind = "pool shared"
	// KindPoolPersistent is a pool device of persistent memory.
	KindPoolPersistent Kind = "pool persistent"
)

// Decision is what the release does with the region of a memdev.
type Decision string

const (
	// Destroy releases the region, also below a newer region of another
	// memdev (a hole left in the decoders of a port).
	Destroy Decision = "destroy"
	// InOrder releases the region unless a newer region of another memdev
	// lies above it in the decoders of a port, before or after its
	// disable: then the region stays (KEPT, disabled when the newer one
	// came during the release).
	InOrder Decision = "in order"
	// Keep leaves the region as it is.
	Keep Decision = "keep"
)

// Policy returns what happens to the region of a memdev of a kind when its
// last grant goes by release, with the regions of other memdevs above its
// regions now (regionsAbove).
func Policy(release Release, kind Kind, regionsAbove []string) Decision {
	above := len(regionsAbove) > 0
	switch kind {
	case KindLocalSliced:
		switch release {
		case ReleaseUnprepare, ReleaseIdle:
			// the order that the user chose: a hole is allowed
			return Destroy
		}
		return InOrder
	case KindLocalShared:
		if release == ReleaseRollback {
			return InOrder
		}
		return Keep
	case KindLocalUnshared:
		switch release {
		case ReleaseRollback:
			return InOrder
		case ReleaseRecovery:
			return Keep
		}
		return Destroy
	case KindLocalPersistent:
		if release == ReleaseRecovery {
			return Keep
		}
		return InOrder
	case KindPoolExclusive, KindPoolShared, KindPoolPersistent:
		// a kept pool region would block the hot-remove of the device
		if release == ReleaseRecovery && above {
			return Keep
		}
		return Destroy
	}
	return Keep
}

// kindOf returns the row of the release policy of a memdev of the source
// whose grants ask as asked; shared tells whether a local memdev is
// configured shared now.
func kindOf(asked state.Asked, shared bool) Kind {
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
	case asked.Kind == state.KindPersistent:
		return KindLocalPersistent
	case asked.Kind == state.KindShared && shared:
		return KindLocalShared
	case asked.Kind == state.KindShared:
		return KindLocalUnshared
	}
	return KindLocalSliced
}
