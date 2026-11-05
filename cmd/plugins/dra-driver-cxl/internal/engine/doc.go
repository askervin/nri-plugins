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

// Package engine owns the CXL kernel objects that the driver makes on the
// node, for local and pool memdevs alike: regions, dax devices and their
// drivers, memory block states, namespaces, block device flags, node
// mounts, loop devices and lease binds. It is the only code of the driver
// that changes them, through pkg/cxl/kernel, and it keeps what it made in
// the records of package state (Memdev, Region with its DaxDevices and
// Mounts, Grant with its Bind) in the store.
//
// A grant is realised in the order journal, kernel work, verify, record:
// its intent is committed durably before the first kernel command, and
// every object it made is committed before the next command that depends on
// it, so that a process stop at any point leaves records that the recovery
// can finish (PrepareGrants, ReleaseGrants, Recover). The release of a
// region follows Policy. The engine serializes its kernel work: one request
// per memdev at a time (a queue per memdev), and one engine lock around each
// short kernel call; waits and zeroing run outside the lock with the
// memdev's Busy flag set.
//
// The transitions of the records are the tables of package state,
// rendered into docs/memory/cxl/states.md; the invariants of the records and
// the kernel together are in invariants.go.
package engine
