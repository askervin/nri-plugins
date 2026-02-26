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

// MemoryLadder represents a memory threshold level
type MemoryLadder struct {
	HighWatermarkKB uint64 // Threshold to move up to next ladder
	LowWatermarkKB  uint64 // Threshold to move down to previous ladder
}

// MemoryLadders is a slice of memory thresholds arranged from lowest to highest
type MemoryLadders []MemoryLadder
