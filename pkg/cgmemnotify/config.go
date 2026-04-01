// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cgmemnotify

// MemoryBounds defines lower and upper memory usage thresholds in bytes.
// The notifier sets memory.high to Upper and sends a notification
// when either bound is crossed.  After an upper-bound notification
// the cgroup stays throttled until the caller provides new bounds
// via SetBounds.
type MemoryBounds struct {
	Lower uint64 // Notify when memory drops below this (0 = disabled)
	Upper uint64 // Notify when memory reaches this; sets memory.high (0 = unlimited)
}

// MemNotifierConfig holds configuration for creating a MemNotifier.
type MemNotifierConfig struct {
	CgroupPath string       // Filesystem path to the cgroup directory
	CgroupName string       // Pretty name for the cgroup, used in log messages
	Bounds     MemoryBounds // Initial memory bounds
}
