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

package kernel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Region: a CXL region regionN (/sys/bus/cxl/devices/regionN, a child of
// its root decoder) on one or more memdevs.
//
// Identity: the name only; the kernel reuses the ids of destroyed regions,
// and the nd region of a pmem region has the id of the CXL region. Which
// region is the driver's is not in sysfs: the driver knows it from the name
// it noted before the creation (CreateRegionRequest.Note).
// Facts: mode ram or pmem, address range, root decoder, target decoders and
// their memdevs, locked, the NUMA node of its memory (one per CFMWS window,
// fixed at boot).
// States (RegionState): HOLLOW (not committed and no target decoder set:
// left when its memdev was removed before the region was destroyed, or by a
// cxl create-region killed half-way, and for a moment while cxl
// create-region sets the region up; cxl destroy-region refuses it,
// DeleteHollowRegion deletes it), DISABLED (not hollow, the cxl_region
// driver not bound: what a release that stopped after cxl disable-region
// leaves, and what ReleaseRegionInOrder keeps when a region of another
// memdev came above), ENABLED (cxl_region bound: a ram region has a dax
// region, a pmem region an nd region). A region being created cannot be
// told from a hollow or disabled one: the driver knows it from its note.
// Transitions: RegionTransitions.
// Invariants: the memory blocks of a region are offline before it is
// destroyed (destroying it would leave online memory that no decoder maps,
// which reads garbage); a locked region is never destroyed.
// Waits: none; the dax or nd region of a new or enabled region appears
// asynchronously (WaitDaxRegion, WaitNdRegion).

// Region types of cxl create-region -t, and the modes of regions.
const (
	// RegionRAM is a region of volatile memory.
	RegionRAM = "ram"
	// RegionPmem is a region of persistent memory with an nd region.
	RegionPmem = "pmem"
)

// RegionState is the state of a region.
type RegionState int

const (
	// RegionAbsent: no region has the name.
	RegionAbsent RegionState = iota
	// RegionHollow: not committed and no target decoder set.
	RegionHollow
	// RegionDisabled: not hollow, no driver bound.
	RegionDisabled
	// RegionEnabled: cxl_region bound.
	RegionEnabled
)

var regionStateNames = []string{"ABSENT", "HOLLOW", "DISABLED", "ENABLED"}

func (s RegionState) String() string { return stateText(regionStateNames, int(s)) }

// MarshalText returns the name of the state.
func (s RegionState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText sets the state of its name.
func (s *RegionState) UnmarshalText(text []byte) error {
	v, err := parseState(regionStateNames, text)
	*s = RegionState(v)
	return err
}

// RegionTransitions are the changes of the state of a region.
var RegionTransitions = Table[RegionState]{
	Object:   "RegionInfo",
	Field:    "State",
	Observed: true,
	States:   list(RegionAbsent, RegionHollow, RegionDisabled, RegionEnabled),
	Rows: []Transition[RegionState]{
		{From: list(RegionAbsent), To: RegionEnabled, When: "CreateRegion",
			Guard:   "the memdev READY; no hole in its ports; room in the root decoder",
			Effects: "the region is pushed on the decoder stack of every port to the endpoint; ram: a dax region with daxN.0 bound to kmem, its memory blocks added; pmem: an nd region probing"},
		{From: list(RegionAbsent), To: RegionHollow, When: "cxl create-region cut before the target was set, or observed while it sets the region up"},
		{From: list(RegionAbsent), To: RegionDisabled, When: "observed while cxl create-region sets the region up"},
		{From: list(RegionHollow), To: RegionEnabled, When: "cxl create-region finished the region"},
		{From: list(RegionDisabled), To: RegionEnabled, When: "EnableRegion, or cxl create-region finished the region",
			Effects: "the dax or nd region made again"},
		{From: list(RegionEnabled), To: RegionDisabled, When: "DisableRegion",
			Effects: "the dax region and its dax devices, or the nd region, go; online memory stays (kmem cannot remove it)"},
		{From: list(RegionDisabled), To: RegionAbsent, When: "DestroyRegion, a reboot",
			Guard:   "every memory block of the region offline; not locked",
			Effects: "popped from the decoder stacks if on top (and the holes below reaped), else a hole left"},
		{From: list(RegionEnabled), To: RegionHollow, When: "hot-remove of its memdev",
			Effects: "the dax or nd region goes; online memory stays online until a reboot"},
		{From: list(RegionDisabled), To: RegionHollow, When: "hot-remove of its memdev"},
		{From: list(RegionHollow), To: RegionAbsent, When: "DeleteHollowRegion, a reboot",
			Guard: "every memory block of its range offline"},
		// changes that one call makes between two observations
		{From: list(RegionHollow), To: RegionDisabled, When: "observed while cxl create-region sets the region up (its target set, not yet bound)"},
		{From: list(RegionEnabled), To: RegionAbsent, When: "ReleaseRegion, ReleaseRegionInOrder (disable, then destroy), observed across them; a reboot",
			Guard:   "every memory block of the region offline after the disable; not locked; in order: no region of another memdev above",
			Effects: "popped from the decoder stacks if on top (and the holes below reaped), else a hole left"},
	},
}

// RegionInfo is the observation of a region.
type RegionInfo struct {
	Name  string      `json:"name"`
	State RegionState `json:"state"`
	// Mode is RegionRAM or RegionPmem.
	Mode      string `json:"mode"`
	Committed bool   `json:"committed"`
	// Locked: the platform locked the region, it is never destroyed.
	Locked bool `json:"locked,omitempty"`
	// Range is the address range of the region, zero while it has none.
	Range Range `json:"range"`
	// Targets are the target decoders that are set (decoderE.K).
	Targets []string `json:"targets,omitempty"`
	// Memdevs are the memdevs (memN) of the targets, Serials their serials.
	Memdevs []string `json:"memdevs,omitempty"`
	Serials []uint64 `json:"serials,omitempty"`
	// RootDecoder is the root decoder of the region (decoder0.N).
	RootDecoder string `json:"rootDecoder,omitempty"`
	// NumaNode is the NUMA node of the memory of the region, -1 if not
	// known (see Kernel.regionNode).
	NumaNode int `json:"numaNode"`
	// DaxRegion is the dax region of an enabled ram region
	// (dax_regionN), "" for none.
	DaxRegion string `json:"daxRegion,omitempty"`
	// NdRegion is the nd region of an enabled pmem region (regionN on the
	// nd bus), "" for none.
	NdRegion string `json:"ndRegion,omitempty"`
}

// topology maps the endpoints and memdevs of the node for the reading of
// regions.
type topology struct {
	memdevOfEndpoint map[string]string
	serialOfMemdev   map[string]uint64
}

// topology returns the endpoints and memdevs of the node now.
func (k *Kernel) topology() topology {
	t := topology{memdevOfEndpoint: map[string]string{}, serialOfMemdev: map[string]uint64{}}
	for memdev, ep := range k.endpoints() {
		t.memdevOfEndpoint[ep] = memdev
	}
	for _, name := range k.memdevNames() {
		if s, err := k.memdevSerial(name); err == nil {
			t.serialOfMemdev[name] = s
		}
	}
	return t
}

// regionTargets returns the target decoders of a region that are set
// (targetN for N below interleave_ways; one that is not set is empty).
func (k *Kernel) regionTargets(region string) []string {
	m, _ := filepath.Glob(k.cxlDev(region, "target[0-9]*"))
	sortNat(m)
	var out []string
	for _, p := range m {
		if v, err := ReadTrim(p); err == nil && v != "" {
			out = append(out, v)
		}
	}
	return out
}

// regionCommitted tells whether the region in sysfs directory dir is
// committed; a region without a commit attribute is not.
func regionCommitted(dir string) bool {
	c, err := ReadTrim(filepath.Join(dir, "commit"))
	return err == nil && c != "0"
}

// regionLocked tells whether the platform locked the region in sysfs
// directory dir; a region without a locked attribute is not.
func regionLocked(dir string) bool {
	l, err := ReadTrim(filepath.Join(dir, "locked"))
	return err == nil && l != "0"
}

// regionHollow tells whether the region in sysfs directory dir is hollow:
// it is not committed and has no target decoder set.
func regionHollow(dir string) bool {
	if regionCommitted(dir) {
		return false
	}
	targets, _ := filepath.Glob(filepath.Join(dir, "target[0-9]*"))
	for _, t := range targets {
		if v, err := ReadTrim(t); err != nil || v != "" {
			return false
		}
	}
	return true
}

// regionState returns the state of the region in sysfs directory dir.
func regionState(dir string) RegionState {
	switch {
	case !exists(dir):
		return RegionAbsent
	case regionHollow(dir):
		return RegionHollow
	case hasDriver(dir):
		return RegionEnabled
	}
	return RegionDisabled
}

// Region returns the observation of a region, an error of kind ErrNotFound
// if it does not exist.
func (k *Kernel) Region(region string) (RegionInfo, error) {
	return k.region(region, k.topology())
}

// region returns the observation of a region with the endpoints and
// memdevs of t.
func (k *Kernel) region(region string, t topology) (RegionInfo, error) {
	dir := k.cxlDev(region)
	r := RegionInfo{Name: region, State: regionState(dir), NumaNode: -1}
	if r.State == RegionAbsent {
		return r, errorf(ErrNotFound, "%s: %w", region, os.ErrNotExist)
	}
	var err error
	r.Mode, err = ReadTrim(filepath.Join(dir, "mode"))
	k.factErr(err)
	r.Committed = regionCommitted(dir)
	r.Locked = regionLocked(dir)
	if r.Range, err = k.RegionRange(region); err != nil {
		// a region without an address range yet has the size 0
		if size, serr := ReadUint(filepath.Join(dir, "size")); serr != nil || size > 0 {
			k.factErr(err)
		}
	}
	r.Targets = k.regionTargets(region)
	for _, target := range r.Targets {
		ep := "endpoint" + strings.TrimSuffix(strings.TrimPrefix(target, "decoder"), filepath.Ext(target))
		if memdev := t.memdevOfEndpoint[ep]; memdev != "" {
			r.Memdevs = append(r.Memdevs, memdev)
			if s, ok := t.serialOfMemdev[memdev]; ok {
				r.Serials = append(r.Serials, s)
			}
		}
	}
	r.RootDecoder, _ = k.RegionRootDecoder(region)
	if m, _ := filepath.Glob(filepath.Join(dir, "dax_region*", "dax_region")); len(m) > 0 {
		r.DaxRegion = filepath.Base(filepath.Dir(m[0]))
	}
	if r.Mode == RegionPmem && r.State == RegionEnabled {
		r.NdRegion, _ = k.NdRegionOf(region)
	}
	r.NumaNode = k.regionNode(region, r.Range)
	return r, nil
}

// regionNode returns the NUMA node of the memory of a region: the
// target_node of a dax device of the region with memory, else the node of a
// memory block wholly in its range, -1 if neither tells.
func (k *Kernel) regionNode(region string, rr Range) int {
	for _, dax := range k.DaxDevices(region) {
		if size, err := k.DaxDeviceSize(dax); err != nil || size == 0 {
			continue
		}
		if n := k.TargetNode(dax); n >= 0 {
			return n
		}
	}
	if rr == (Range{}) {
		return -1
	}
	bs, err := k.BlockSize()
	if err != nil {
		return -1
	}
	return k.BlocksNode(rr.blocks(bs))
}

// RegionRange returns the physical address range of a region.
func (k *Kernel) RegionRange(region string) (Range, error) {
	res, err := ReadTrim(k.cxlDev(region, "resource"))
	if err != nil {
		return Range{}, err
	}
	sz, err := ReadTrim(k.cxlDev(region, "size"))
	if err != nil {
		return Range{}, err
	}
	start, err1 := ParseHex(res)
	size, err2 := ParseHex(sz)
	if err := errors.Join(err1, err2); err != nil || size == 0 {
		return Range{}, fmt.Errorf("cannot parse region %s resource %q size %q", region, res, sz)
	}
	return Range{Start: start, End: start + size - 1}, nil
}

// HollowRegion tells whether a region is hollow (RegionHollow).
func (k *Kernel) HollowRegion(region string) bool {
	return regionState(k.cxlDev(region)) == RegionHollow
}

// RegionRootDecoder returns the root decoder of a region: the parent of its
// sysfs directory (.../root0/decoder0.1/region1).
func (k *Kernel) RegionRootDecoder(region string) (string, error) {
	real, err := filepath.EvalSymlinks(k.cxlDev(region))
	if err != nil {
		return "", err
	}
	parent := filepath.Base(filepath.Dir(real))
	if t, _ := ReadTrim(k.cxlDev(parent, "devtype")); t != "cxl_decoder_root" {
		return "", fmt.Errorf("%s: its parent device %s is not a root decoder", region, parent)
	}
	return parent, nil
}

// RootDecoder returns the root decoder whose target list has the host
// bridge of the memdev and that can map regions of the type (RegionRAM or
// RegionPmem), the first one in natural order.
func (k *Kernel) RootDecoder(memdev, regionType string) (string, error) {
	capAttr := ""
	switch regionType {
	case RegionRAM:
		capAttr = "cap_ram"
	case RegionPmem:
		capAttr = "cap_pmem"
	default:
		return "", fmt.Errorf("invalid region type %q (%s or %s)", regionType, RegionRAM, RegionPmem)
	}
	uid, err := k.HostBridgeUID(memdev)
	if err != nil {
		return "", err
	}
	for _, d := range k.listCXL("decoder*") {
		if t, _ := ReadTrim(k.cxlDev(d, "devtype")); t != "cxl_decoder_root" {
			continue
		}
		// a decoder without the attribute can map both types
		if v, err := ReadTrim(k.cxlDev(d, capAttr)); err == nil && v != "1" {
			continue
		}
		tl, _ := ReadTrim(k.cxlDev(d, "target_list"))
		for _, t := range strings.Split(tl, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil && n == uid {
				return d, nil
			}
		}
	}
	return "", errorf(ErrNotFound, "no root decoder for %s regions targets host bridge %d of %s", regionType, uid, memdev)
}

// nextRegionAttr returns the attribute of a root decoder with the name of
// its next region of the type.
func nextRegionAttr(regionType string) string {
	if regionType == RegionPmem {
		return "create_pmem_region"
	}
	return "create_ram_region"
}

// NextRegionName returns the name of the region that the next cxl
// create-region of the type creates under the root decoder (its
// create_ram_region or create_pmem_region).
func (k *Kernel) NextRegionName(decoder, regionType string) (string, error) {
	return ReadTrim(k.cxlDev(decoder, nextRegionAttr(regionType)))
}

// CreateRegionRequest is a region to create:
//   - Memdev: the memdev (memN) of the region
//   - Decoder: the root decoder (see RootDecoder)
//   - Type: RegionRAM or RegionPmem
//   - Size: the bytes of the memdev's capacity that the region maps, a
//     multiple of 256 MiB, the alignment of CXL regions; 0 maps all of it
//   - Note: called before cxl create-region with the name of the region it
//     will create ("" if it cannot be read): an error creates nothing
type CreateRegionRequest struct {
	Memdev  string
	Decoder string
	Type    string
	Size    uint64
	Note    func(next string) error
}

var regionNameRe = regexp.MustCompile(`"region"\s*:\s*"(region\d+)"`)

// CreateRegion creates a region (cxl create-region) and returns its name.
// The read of its name, Note and cxl create-region run in Serialize. The
// dax region or the nd region of the region appears asynchronously. Errors:
// ErrDecoderHole when a port of the memdev has a hole, ErrEndpointNotReady
// when the memdev has no endpoint port, the error of Note as it is.
func (k *Kernel) CreateRegion(ctx context.Context, req CreateRegionRequest) (string, error) {
	if req.Type != RegionRAM && req.Type != RegionPmem {
		return "", fmt.Errorf("invalid region type %q (%s or %s)", req.Type, RegionRAM, RegionPmem)
	}
	args := []string{"create-region", "-t", req.Type, "-d", req.Decoder, "-m", req.Memdev}
	if req.Size > 0 {
		args = append(args, "-s", strconv.FormatUint(req.Size, 10))
	}
	var noteErr, err error
	var out string
	serr := k.serialize(func() error {
		if req.Note != nil {
			next, _ := k.NextRegionName(req.Decoder, req.Type)
			if noteErr = req.Note(next); noteErr != nil {
				return noteErr
			}
		}
		out, err = k.exec(ctx, "cxl", args...)
		return err
	})
	switch {
	case noteErr != nil:
		return "", noteErr
	case err != nil:
		return "", k.explainCreateRegion(req.Memdev, err)
	case serr != nil:
		return "", serr
	}
	region := ""
	if m := regionNameRe.FindStringSubmatch(out); m != nil {
		region = m[1]
	} else if rs := k.Regions(req.Memdev); len(rs) > 0 {
		region = rs[0]
	} else {
		return "", fmt.Errorf("cxl create-region did not report a region: %s", out)
	}
	k.logf("%s: created %s (%s) under %s", req.Memdev, region, req.Type, req.Decoder)
	return region, nil
}

// explainCreateRegion returns the error of a failed cxl create-region with
// its kind: ErrDecoderHole with the decoder holes of the memdev's ports
// (the kernel's EBUSY does not tell which port refused the region, or until
// when), ErrEndpointNotReady when the memdev has no endpoint port (the
// add_dev race after a hot-add), ErrNoRoom when the window has no room for
// it. Decoders that cannot be read explain nothing: the error is returned
// as it is then.
func (k *Kernel) explainCreateRegion(memdev string, err error) error {
	if holes, herr := k.DecoderHoles(memdev); herr == nil {
		if derr := newErrDecoderHole(holes, err); derr != nil {
			return derr
		}
	}
	if _, eperr := k.endpoint(memdev); eperr != nil || strings.Contains(err.Error(), "add_dev") {
		return &kernelError{kind: ErrEndpointNotReady, msg: err.Error(), err: err}
	}
	if strings.Contains(strings.ToLower(err.Error()), "no space left on device") {
		return &kernelError{kind: ErrNoRoom, msg: err.Error(), err: err}
	}
	return err
}

// EnableRegion enables a disabled region (cxl enable-region): the kernel
// makes its dax or nd region again. An enabled region is left as it is; a
// region that does not exist is an error of kind ErrNotFound.
func (k *Kernel) EnableRegion(ctx context.Context, region string) error {
	dir := k.cxlDev(region)
	if _, err := os.Stat(dir); err != nil {
		return errorf(ErrNotFound, "%s: %w", region, err)
	}
	if hasDriver(dir) {
		return nil
	}
	if _, err := k.exec(ctx, "cxl", "enable-region", region); err != nil {
		return err
	}
	k.logf("enabled %s", region)
	return nil
}

// DisableRegion disables a region (cxl disable-region): its dax devices or
// its nd region go, its decoders stay committed. A region that does not
// exist is not an error.
func (k *Kernel) DisableRegion(ctx context.Context, region string) error {
	if !exists(k.cxlDev(region)) {
		return nil
	}
	if _, err := k.exec(ctx, "cxl", "disable-region", region); err != nil {
		return err
	}
	return nil
}

// DestroyRegion destroys a disabled region (cxl destroy-region). A region
// that does not exist is not an error. Errors: ErrForeign for a locked
// region, ErrBusyOnline when memory blocks of the region are online, an
// error for an enabled region (DisableRegion first) and for a hollow one,
// which only DeleteHollowRegion removes.
func (k *Kernel) DestroyRegion(ctx context.Context, region string) error {
	state := regionState(k.cxlDev(region))
	if state == RegionAbsent {
		return nil
	}
	if err := k.checkNotLocked(region); err != nil {
		return err
	}
	switch state {
	case RegionHollow:
		return fmt.Errorf("%s is hollow: cxl destroy-region cannot remove it, delete it", region)
	case RegionEnabled:
		return fmt.Errorf("%s is enabled: disable it before destroying it", region)
	}
	if online := k.onlineRegionBlocks(region); len(online) > 0 {
		return errorf(ErrBusyOnline, "%s: memory blocks %v are online (the kernel could not remove them, see dmesg): not destroying the region, the memory would read garbage", region, online)
	}
	if _, err := k.exec(ctx, "cxl", "destroy-region", region); err != nil {
		return err
	}
	k.logf("destroyed %s", region)
	return nil
}

// checkNotLocked returns an error of kind ErrForeign if the platform locked
// the region.
func (k *Kernel) checkNotLocked(region string) error {
	if regionLocked(k.cxlDev(region)) {
		return errorf(ErrForeign, "%s is locked: the platform keeps it", region)
	}
	return nil
}

// onlineRegionBlocks returns the memory blocks wholly in the range of the
// region that are online.
func (k *Kernel) onlineRegionBlocks(region string) []int {
	blocks, err := k.RegionBlocks(region)
	if err != nil {
		return nil
	}
	return k.onlineBlocks(blocks)
}

// ReleaseRegion offlines the memory of a region, and disables and destroys
// the region. Namespaces and labels of a region of persistent memory are
// not touched. A missing region is not an error.
//
// A region with memory blocks that are online after it is disabled is not
// destroyed (ErrBusyOnline): the kernel could not remove the memory (kmem
// keeps it "until the next reboot"), and destroying the region would leave
// online memory that no decoder maps, which reads garbage.
func (k *Kernel) ReleaseRegion(ctx context.Context, region string) error {
	_, err := k.releaseRegion(ctx, region, nil)
	return err
}

// ReleaseRegionInOrder releases a region of the memdev as ReleaseRegion
// does, unless regions of other memdevs lie above the memdev's regions in
// the decoders of its ports (RegionsAbove): destroying it would leave a
// hole below them (DecoderHole). It returns those regions then, and the
// region stays: as it was if they were there before the release, disabled
// if they came during it. Decoders that cannot be read are an error, before
// the release (the region untouched) or after its disable (the region
// disabled). The check after cxl disable-region and cxl destroy-region run
// in Serialize. A missing region is not an error.
func (k *Kernel) ReleaseRegionInOrder(ctx context.Context, memdev, region string) ([]string, error) {
	above, err := k.RegionsAbove(memdev)
	if err != nil || len(above) > 0 {
		return above, err
	}
	return k.releaseRegion(ctx, region, func() ([]string, error) { return k.RegionsAbove(memdev) })
}

// releaseRegion releases a region (ReleaseRegion). With above (nil: none),
// the region is destroyed only if above, called after cxl disable-region in
// Serialize, returns no region and no error; else it returns them.
func (k *Kernel) releaseRegion(ctx context.Context, region string, above func() ([]string, error)) ([]string, error) {
	if _, err := os.Stat(k.cxlDev(region)); err != nil {
		return nil, nil
	}
	if err := k.checkNotLocked(region); err != nil {
		return nil, err
	}
	// Offline every memory block of the region, whatever the driver of its
	// dax devices: a failed driver switch can leave blocks added and
	// online without kmem.
	if blocks, err := k.RegionBlocks(region); err == nil && len(blocks) > 0 {
		if err := k.SetBlocksState(blocks, BlockStateOffline); err != nil {
			return nil, fmt.Errorf("%s: cannot offline memory (in use?): %w", region, err)
		}
	}
	if _, err := k.exec(ctx, "cxl", "disable-region", region); err != nil {
		return nil, err
	}
	if online := k.onlineRegionBlocks(region); len(online) > 0 {
		return nil, errorf(ErrBusyOnline, "%s: memory blocks %v are online after disabling it (the kernel could not remove them, see dmesg): not destroying the region, the memory would read garbage", region, online)
	}
	destroy := func() error {
		if _, err := k.exec(ctx, "cxl", "destroy-region", region); err != nil {
			return err
		}
		k.logf("destroyed %s", region)
		return nil
	}
	if above == nil {
		return nil, destroy()
	}
	var rs []string
	err := k.serialize(func() error {
		var err error
		if rs, err = above(); err != nil {
			return fmt.Errorf("not destroying disabled %s: %w", region, err)
		}
		if len(rs) > 0 {
			k.logf("not destroying disabled %s: %s came above it in the decoders", region, strings.Join(rs, ", "))
			return nil
		}
		return destroy()
	})
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// DeleteHollowRegion deletes a hollow region by writing its name to the
// delete_region attribute of its root decoder, which is what cxl
// destroy-region does last, after the target decoders that a hollow region
// does not have. It runs in Serialize: the region is then not one that a
// cxl create-region of the process is setting up; one that another process
// sets up is hollow too for a moment, and only the name noted before a
// creation (CreateRegionRequest.Note) tells the region of the process. A
// region with memory blocks that are not
// offline is not deleted (ErrBusyOnline): kmem keeps that memory until a
// reboot, and the region stays with it. A region that is not hollow is not
// deleted (ErrNotHollow). A missing region is not an error.
func (k *Kernel) DeleteHollowRegion(region string) error {
	return k.serialize(func() error {
		dir := k.cxlDev(region)
		if _, err := os.Stat(dir); err != nil {
			return nil
		}
		if !regionHollow(dir) {
			return errorf(ErrNotHollow, "%s is not hollow: it is committed or has a target decoder", region)
		}
		if online := k.onlineRegionBlocks(region); len(online) > 0 {
			return errorf(ErrBusyOnline, "%s: memory blocks %v of its address range are not offline (kmem keeps them until a reboot): not deleting it", region, online)
		}
		decoder, err := k.RegionRootDecoder(region)
		if err != nil {
			return err
		}
		res, _ := ReadTrim(filepath.Join(dir, "resource"))
		attr := k.cxlDev(decoder, "delete_region")
		if err := k.writeFile(attr, region); err != nil {
			return fmt.Errorf("%s: deleting hollow %s: %w", attr, region, err)
		}
		if _, err := os.Stat(dir); err == nil {
			return fmt.Errorf("%s: %s still exists after its deletion", attr, region)
		}
		k.logf("deleted hollow %s (resource %s) through %s", region, res, attr)
		return nil
	})
}
