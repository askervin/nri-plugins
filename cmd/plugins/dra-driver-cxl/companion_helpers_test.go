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

// The fakes and fixtures of companion claims and lease claims that the
// tests of the drivers share: the lease broker itself is tested in
// internal/leases.

// leaseFsDirName is the directory of the lease-fs directories of the
// lease claims in the plugin data directory of cxl.nri.io.
const leaseFsDirName = "lease-fs"

// stopFunc is a lease broker whose Stop calls the function.
type stopFunc func()

// Stop calls the function.
func (f stopFunc) Stop() { f() }

const (
	testNode   = "node1"
	testNS     = "demo"
	testPod    = "borrower"
	testPodUID = "pod-uid-1"
	testCtr    = "app"
)
