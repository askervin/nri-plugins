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

package memctl

import "github.com/containers/nri-plugins/pkg/cxl/kernel"

// DecoderHole is a port between the CXL root and a memdev whose HDM
// decoders were released out of order (see kernel.DecoderHole).
type DecoderHole = kernel.DecoderHole

// DecoderHoles returns the ports of the decoder path from the CXL root to
// the memdev's endpoint whose decoders were released out of order (see
// DecoderHole), nearest to the root first. A memdev without an endpoint
// has none, and so has one whose decoders cannot be read (logged).
func (mc *Manager) DecoderHoles(memdev string) []DecoderHole {
	holes, err := mc.kernel().DecoderHoles(memdev)
	if err != nil {
		mc.logf("%s: %v", memdev, err)
	}
	return holes
}

// RegionsAbove returns the regions of other memdevs on the decoders above
// those of the memdev's regions in the ports between the CXL root and the
// memdev's endpoint, nearest to the root first: while they live,
// destroying the memdev's regions leaves a hole in those ports (see
// DecoderHole). A memdev without an endpoint or regions has none. Decoders
// that cannot be read count as a region above: the list has the error then,
// in parentheses.
func (mc *Manager) RegionsAbove(memdev string) []string {
	above, err := mc.kernel().RegionsAbove(memdev)
	if err != nil {
		mc.logf("%s: %v", memdev, err)
		return append(above, "("+err.Error()+")")
	}
	return above
}

// HollowRegion tells whether a region is hollow: it is not committed and
// has no target decoder set. That is what is left of a region whose memory
// devices were removed before it was destroyed: the kernel detaches their
// endpoint decoders and resets the decode, but keeps the region with its
// address range in the root decoder (the window); no decoder maps that
// range any more. It is also, for a moment, the state of a region that cxl
// create-region is setting up, and for good that of one whose setup was
// cut (the tool killed). cxl destroy-region refuses a hollow region
// ("cxl_region_get_target_decoder: regionN: error locating decoder for
// target0"): see DeleteHollowRegion.
func (mc *Manager) HollowRegion(region string) bool {
	return mc.kernel().HollowRegion(region)
}

// RegionRootDecoder returns the root decoder of a region: the parent of its
// sysfs directory (.../root0/decoder0.1/region1).
func (mc *Manager) RegionRootDecoder(region string) (string, error) {
	return mc.kernel().RegionRootDecoder(region)
}

// DeleteHollowRegion deletes a hollow region (see HollowRegion) by writing
// its name to the delete_region attribute of its root decoder, which is
// what cxl destroy-region does last, after the target decoders that a
// hollow region does not have. It holds the lock of the region creations
// of the process (regionCreateMu): the region is then not one that a cxl
// create-region of this process is setting up; one that another process
// sets up is hollow too for a moment, and only the name noted before a
// creation (RegionNote) tells the region of the process. A region with memory blocks that are not offline is
// not deleted: kmem keeps that memory until a reboot, and the region stays
// with it, as ReleaseRegion keeps such a region. A missing region is not
// an error.
func (mc *Manager) DeleteHollowRegion(region string) error {
	return mc.kernel().DeleteHollowRegion(region)
}
