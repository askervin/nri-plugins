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

package dra

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/engine"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// SourceRules are what the two DRA drivers of the process do differently:
// the source of their devices, how an allocation result maps to a memdev and
// a grant, whether the driver publishes the node's ResourceSlice, its CDI
// kind, and the rules that the two drivers apply differently.
type SourceRules struct {
	// Name is the DRA driver name.
	Name string
	// Source is the source of the devices of the driver's grants.
	Source state.Source
	// Publishes: the driver publishes the node's ResourceSlice.
	Publishes bool
	// CDIKind is the kind of the CDI devices of the driver, CDISpecName
	// the name of its spec file.
	CDIKind, CDISpecName string
	// MountsDir is the directory of the node mounts of mode fs of the
	// driver's devices.
	MountsDir string
	// CDIUnpreparing: the CDI spec keeps the devices of a claim whose
	// Unprepare did not finish.
	CDIUnpreparing bool
	// FailLeaseOnFinish: a companion claim whose CDI spec or PREPARED
	// commit fails after the lend tells the broker that the lend failed.
	FailLeaseOnFinish bool
	// RetryStaleOnRefusal: a Prepare refused before a device is touched
	// unmounts the stale lease binds again, as a failed Prepare does.
	RetryStaleOnRefusal bool
	// FailUnprepareOnCDI: the Unprepare of a prepared claim whose devices
	// were released returns the error of the CDI spec written after it to
	// kubelet; otherwise the error is logged.
	FailUnprepareOnCDI bool

	// validate returns the Prepare of a claim, every result checked.
	validate func(p *Plugin, claim *resourcev1.ResourceClaim) (*prepare, error)
	// voice are the driver's words: its log lines and error texts.
	voice voice
}

// LocalRules returns the rules of cxl.nri.io: the local memdevs of the node,
// found in the last scan; publishes the node's ResourceSlice; CDI kind
// device.CDIKind; node mounts in mountsDir.
func LocalRules(mountsDir string) SourceRules {
	return SourceRules{
		Name:               device.DriverName,
		Source:             state.SourceLocal,
		Publishes:          true,
		CDIKind:            device.CDIKind,
		CDISpecName:        device.ClaimsCDISpecName,
		MountsDir:          mountsDir,
		CDIUnpreparing:     true,
		FailLeaseOnFinish:  true,
		FailUnprepareOnCDI: true,
		validate:           (*Plugin).validateLocal,
		voice:              localVoice{},
	}
}

// PoolRules returns the rules of the pool driver name: the devices that a
// pool controller attached to the node for a claim, found by the serial of
// the claim's status data; publishes nothing; CDI kind device.PoolCDIKind;
// node mounts in mountsDir; records names its records of claims whose
// Prepare did not finish in the log lines.
func PoolRules(name, mountsDir, records string) SourceRules {
	return SourceRules{
		Name:                name,
		Source:              state.SourcePool,
		CDIKind:             device.PoolCDIKind,
		CDISpecName:         device.PoolCDISpecName,
		MountsDir:           mountsDir,
		RetryStaleOnRefusal: true,
		validate:            (*Plugin).validatePool,
		voice:               poolVoice{name: name, records: records},
	}
}

// MountsDirs returns the directories of the node mounts of mode fs of the
// sources of rules, by source (engine.Options.MountsDirs).
func MountsDirs(rules ...SourceRules) map[state.Source]string {
	dirs := map[state.Source]string{}
	for _, r := range rules {
		dirs[r.Source] = r.MountsDir
	}
	return dirs
}

// voice are the words of a driver: the texts of its errors and log lines.
type voice interface {
	// refused returns the error of a Prepare refused before any device is
	// touched.
	refused(claimName string, err error) error
	// failure returns the error of a Prepare that failed after its intent.
	failure(claimName string, err error) error
	// finishFailure returns the error of a Prepare whose CDI spec or
	// PREPARED commit failed.
	finishFailure(claimName string, err error) error
	// deviceError returns the error of the grant of req.
	deviceError(req *engine.GrantRequest, request string, err error) error
	// prepared logs what the grants of a Prepare got.
	prepared(p *Plugin, pr *prepare)
	// companionPrepared logs the lend of a prepared companion claim.
	companionPrepared(claimName string, lend *lend.Lend)
	// kept logs a preparation that a failed Prepare's rollback kept.
	kept(uid, claimName string)
	// alreadyPrepared logs a Prepare of a prepared claim.
	alreadyPrepared(prep *state.Preparation)
	// remounted logs the node mounts that a Prepare again mounted again.
	remounted(prep *state.Preparation, mounts []string, why error)
	// remountError returns the error of a Prepare again that did not mount
	// the node mounts again.
	remountError(claim *resourcev1.ResourceClaim, err error) error
	// loaded logs at a start the prepared claims of the driver that the
	// records r loaded from have.
	loaded(r *state.Records, from string)
	// unrestoredWhy returns why a prepared claim has no CDI devices at a
	// start, why the recovery said (nil: it did not say).
	unrestoredWhy(why error) error
	// unrestored logs at a start a prepared claim without CDI devices,
	// found telling whether one of its grants is REALISED_UNRESTORED, of
	// the node mount.
	unrestored(prep *state.Preparation, found bool, mount string, why error)
	// notPrepared logs an Unprepare of a claim without a record.
	notPrepared(uid string)
	// unfinished logs the Unprepare of a claim that is not prepared, with
	// the serials of its grants.
	unfinished(prep *state.Preparation, serials []string)
	// unprepareError returns the error of an Unprepare of a preparation
	// (prepared tells whether it was) that failed.
	unprepareError(prep *state.Preparation, prepared bool, err error) error
	// unprepared logs the end of an Unprepare of the claim claimName (""
	// for a claim without a record) and returns its error to kubelet.
	unprepared(uid, claimName string, err error) error
	// started returns the error of the start of the kubelet plugin, and
	// logs the start.
	started(err error) error
	// rollbackError logs the error of a step of the rollback of a failed
	// Prepare of the claim uid (claimName).
	rollbackError(step rollbackStep, uid, claimName string, err error)
	// cdiVersionError and cdiWriteError return the errors of the version
	// and of the write of the CDI spec name; cdiRemoved logs the removal of
	// the spec name of no devices (err: it failed), cdiWrote the write of
	// the spec name with n devices.
	cdiVersionError(err error) error
	cdiWriteError(name string, err error) error
	cdiRemoved(name string, err error)
	cdiWrote(name string, n int)
}

// rollbackStep is a step of the rollback of a failed Prepare.
type rollbackStep int

const (
	// rollbackRevoke revokes the lend of a companion claim.
	rollbackRevoke rollbackStep = iota
	// rollbackRelease releases the grants of the claim.
	rollbackRelease
	// rollbackCommit commits the preparation KEPT, or removes it.
	rollbackCommit
	// rollbackCDI writes the CDI spec without the claim.
	rollbackCDI
)

// localVoice are the words of cxl.nri.io.
type localVoice struct{}

func (localVoice) refused(_ string, err error) error { return err }

func (localVoice) failure(claimName string, err error) error {
	return fmt.Errorf("claim %s: %w", claimName, err)
}

func (localVoice) finishFailure(_ string, err error) error {
	klog.Errorf("%v", err)
	return err
}

func (localVoice) deviceError(req *engine.GrantRequest, request string, err error) error {
	if req.Asked.Kind == state.KindPersistent {
		return fmt.Errorf("request %s: %w", request, err)
	}
	return fmt.Errorf("device %s: %w", req.Device, err)
}

// prepared logs what each allocation result on a local memdev of a Prepare
// got.
func (localVoice) prepared(p *Plugin, pr *prepare) {
	r := p.records()
	for i := range pr.reqs {
		req := &pr.reqs[i]
		g := r.Grant(req.Ref)
		if g == nil {
			continue
		}
		memdev, region, s := "", string(g.Got.Region), uint64(g.Serial)
		if m := r.Memdev(g.Serial); m != nil {
			memdev = m.Name
		}
		request := pr.request(req.Ref)
		switch g.Asked.Kind {
		case state.KindShared:
			klog.Infof("local: memdev %s (serial 0x%x): claim %s request %s: shared %s size %d read-only %v %s",
				memdev, s, pr.uid, request, g.Got.Dax, g.Got.Size, g.Asked.ReadOnly, pr.uses[req.Ref])
		case state.KindPersistent:
			dev, access, fsType := "", string(g.Got.Mount), ""
			if g.Got.BlockDevice != nil {
				dev = g.Got.BlockDevice.Name
			}
			if m := r.MountOf(g); m != nil {
				fsType = m.FsType
			}
			klog.Infof("local: memdev %s (serial 0x%x) %s: claim %s request %s: persistent %s mode %s read-only %v access %q fs %q",
				memdev, s, region, pr.uid, request, dev, g.Asked.Mode, g.Asked.ReadOnly, access, fsType)
		default:
			node, daxDevice := -1, ""
			if g.Asked.Mode == state.ModeNUMA {
				node = state.NumaNodeOf(g.Got.NumaNode)
			} else if g.Got.Dax != "" {
				daxDevice = filepath.Join(p.devRoot, g.Got.Dax)
			}
			klog.Infof("local: memdev %s (serial 0x%x) %s: claim %s request %s: slice %s mode %s size %d node %d%s",
				memdev, s, region, pr.uid, request, g.Got.Dax, g.Asked.Mode, g.Got.Size, node, strings.TrimRight(" "+daxDevice, " "))
		}
	}
}

func (localVoice) companionPrepared(string, *lend.Lend) {}

func (localVoice) kept(string, string) {}

func (localVoice) alreadyPrepared(prep *state.Preparation) {
	klog.V(3).Infof("Claim %s was already prepared, nothing to do", prep.UID)
}

func (localVoice) remounted(prep *state.Preparation, mounts []string, why error) {
	for _, mnt := range mounts {
		klog.Infof("local: claim %s: %s is mounted again (it was not: %v)", prep.UID, mnt, why)
	}
	klog.Infof("claim %s (%s): its devices are restored: it has its CDI devices again", prep.ClaimName, prep.UID)
}

func (localVoice) remountError(claim *resourcev1.ResourceClaim, err error) error {
	return fmt.Errorf("claim %v/%v: %w; unprepare the claim (delete its pods) to prepare it anew", claim.Namespace, claim.Name, err)
}

func (localVoice) loaded(*state.Records, string) {}

func (localVoice) unrestoredWhy(why error) error {
	if why == nil {
		return errors.New("its node mount is not mounted")
	}
	return why
}

func (localVoice) unrestored(prep *state.Preparation, _ bool, _ string, why error) {
	klog.Errorf("claim %s (%s) has no CDI device: %v; a new container of it fails on its CDI device, its Prepare again tries to mount it again, its Unprepare releases the device",
		prep.ClaimName, prep.UID, why)
}

func (localVoice) notPrepared(string) {}

func (localVoice) unfinished(*state.Preparation, []string) {}

func (localVoice) unprepareError(prep *state.Preparation, prepared bool, err error) error {
	who := prep.ClaimName
	if !prepared {
		who = prep.UID
	}
	return fmt.Errorf("claim %s: %w", who, err)
}

func (localVoice) unprepared(uid, _ string, err error) error {
	if err != nil {
		return fmt.Errorf("error freeing devices: %v", err)
	}
	klog.V(3).Infof("Freed devices for claim '%v'", uid)
	return nil
}

func (localVoice) started(err error) error {
	if err != nil {
		return fmt.Errorf("failed to start kubelet plugin: %v", err)
	}
	return nil
}

func (localVoice) rollbackError(step rollbackStep, uid, claimName string, err error) {
	who := claimName
	if step == rollbackCommit {
		who = uid
	}
	klog.Errorf("claim %s: rollback: %v", who, err)
}

func (localVoice) cdiVersionError(err error) error {
	return fmt.Errorf("failed to get minimum required CDI spec version: %v", err)
}

func (localVoice) cdiWriteError(name string, err error) error {
	return fmt.Errorf("failed to write CDI spec %s: %v", name, err)
}

func (localVoice) cdiRemoved(name string, err error) {
	if err != nil {
		klog.V(5).Infof("Could not remove CDI spec %s (may not exist): %v", name, err)
	} else {
		klog.V(5).Infof("Removed empty CDI spec %s", name)
	}
}

func (localVoice) cdiWrote(name string, n int) {
	klog.V(5).Infof("Wrote CDI spec %s with %d devices", name, n)
}

// poolVoice are the words of the pool driver name; records names its
// records of claims whose Prepare did not finish.
type poolVoice struct {
	name, records string
}

// fail returns an error of a Prepare of the claim, logged.
func (v poolVoice) fail(claimName string, err error) error {
	err = fmt.Errorf("%s: preparing claim %s: %w", v.name, claimName, err)
	klog.Error(err)
	return err
}

func (v poolVoice) refused(claimName string, err error) error { return v.fail(claimName, err) }

func (v poolVoice) failure(claimName string, err error) error { return v.fail(claimName, err) }

func (v poolVoice) finishFailure(claimName string, err error) error { return v.fail(claimName, err) }

func (poolVoice) deviceError(req *engine.GrantRequest, _ string, err error) error {
	return fmt.Errorf("device %s serial 0x%x: %w", req.Device, uint64(req.Serial), err)
}

// prepared logs the devices of a claim as prepared.
func (v poolVoice) prepared(p *Plugin, pr *prepare) {
	prep := p.preparation(pr.uid)
	if prep == nil {
		return
	}
	devs, err := poolDevicesOf(p.st.Snapshot(), prep, p.st.ResultOptions())
	if err != nil {
		klog.Errorf("%s: claim %s: %v", v.name, prep.ClaimName, err)
	}
	for i := range devs {
		d := &devs[i]
		if d.Persistent {
			klog.Infof("%s: claim %s: prepared %s (serial 0x%x, shared %v, mode %s, read-only %v) as %s %s namespace %s block %s access %q fs %q mount %q loop %q",
				v.name, pr.claimName, d.Device, d.Serial, d.Shared, d.Mode, d.ReadOnly, d.Memdev, d.Region,
				d.Namespace, d.BlockDevice, d.Access, d.FsType, d.NodeMount, d.LoopDevice)
			continue
		}
		klog.Infof("%s: claim %s: prepared %s (serial 0x%x, shared %v, mode %s, read-only %v) as %s %s dax %s node %d",
			v.name, pr.claimName, d.Device, d.Serial, d.Shared, d.Mode, d.ReadOnly, d.Memdev, d.Region, d.Dax, d.NumaNode)
	}
}

func (v poolVoice) companionPrepared(claimName string, lend *lend.Lend) {
	klog.Infof("%s: claim %s: companion of lease %s of %s/%s/%s prepared (nodes %v, binds %v)",
		v.name, claimName, lend.Lease, lend.Pod.Namespace, lend.Pod.Name, lend.Container, lend.NumaNodes, lend.Mounts)
}

func (v poolVoice) kept(uid, claimName string) {
	klog.Warningf("%s: rollback: claim %s (%s): not everything was released: keeping its record in %s for its Unprepare or its next Prepare",
		v.name, claimName, uid, v.records)
}

func (v poolVoice) alreadyPrepared(prep *state.Preparation) {
	klog.V(3).Infof("%s: claim %s (%s) was already prepared", v.name, prep.ClaimName, prep.UID)
}

func (v poolVoice) remounted(prep *state.Preparation, mounts []string, _ error) {
	for _, mnt := range mounts {
		klog.Infof("%s: claim %s: %s is mounted again: the claims of it have their CDI devices again", v.name, prep.ClaimName, mnt)
	}
}

func (v poolVoice) remountError(claim *resourcev1.ResourceClaim, err error) error {
	return v.fail(claim.Namespace+"/"+claim.Name, err)
}

func (v poolVoice) loaded(r *state.Records, from string) { logLoaded(r, v.name, from) }

func (poolVoice) unrestoredWhy(why error) error { return why }

func (v poolVoice) unrestored(prep *state.Preparation, found bool, mount string, why error) {
	if !found {
		return
	}
	if why == nil {
		why = errors.New("not mounted again")
	}
	klog.Errorf("%s: claim %s (%s) has no CDI device: its node mount %s is not mounted (%v); a new container of it fails on its CDI device, its Prepare again tries to mount it again, its Unprepare releases the device",
		v.name, prep.ClaimName, prep.UID, mount, why)
}

func (v poolVoice) notPrepared(uid string) {
	klog.V(3).Infof("%s: claim %s is not prepared, nothing to release", v.name, uid)
}

func (v poolVoice) unfinished(prep *state.Preparation, serials []string) {
	what := "whose Prepare did not finish"
	if prep.State == state.PreparationStale {
		reason := prep.Reason
		if reason == "" {
			reason = "not prepared"
		}
		what = "not prepared any more (" + reason + ")"
	}
	klog.Infof("%s: unpreparing claim %s (%s), %s: releasing devices %s", v.name, prep.ClaimName, prep.UID, what, strings.Join(serials, ", "))
}

func (v poolVoice) unprepareError(prep *state.Preparation, _ bool, err error) error {
	err = fmt.Errorf("%s: unpreparing claim %s: %w", v.name, prep.ClaimName, err)
	klog.Error(err)
	return err
}

func (v poolVoice) unprepared(uid, claimName string, err error) error {
	if err == nil && claimName != "" {
		klog.Infof("%s: unprepared claim %s (%s)", v.name, claimName, uid)
	}
	return err
}

func (v poolVoice) started(err error) error {
	if err != nil {
		return fmt.Errorf("failed to start kubelet plugin %s: %w", v.name, err)
	}
	klog.Infof("pool driver registered as %s", v.name)
	return nil
}

func (v poolVoice) rollbackError(step rollbackStep, _, claimName string, err error) {
	switch step {
	case rollbackRevoke:
		klog.Errorf("%s: rollback: claim %s: %v", v.name, claimName, err)
	case rollbackRelease:
		klog.Errorf("%s: rollback: %v", v.name, err)
	case rollbackCommit:
		klog.Errorf("%s: claim %s: %v", v.name, claimName, err)
	default:
		klog.Errorf("%s: %v", v.name, err)
	}
}

func (poolVoice) cdiVersionError(err error) error {
	return fmt.Errorf("CDI spec version: %w", err)
}

func (poolVoice) cdiWriteError(name string, err error) error {
	return fmt.Errorf("failed to write CDI spec %s: %w", name, err)
}

func (v poolVoice) cdiRemoved(name string, err error) {
	if err != nil {
		klog.V(5).Infof("%s: could not remove CDI spec %s (may not exist): %v", v.name, name, err)
	}
}

func (v poolVoice) cdiWrote(name string, n int) {
	klog.V(5).Infof("%s: wrote CDI spec %s with %d devices", v.name, name, n)
}

// serialsOf returns the serials of the grants of a preparation, for the log
// lines.
func serialsOf(r *state.Records, prep *state.Preparation) []string {
	var serials []string
	for _, res := range prep.Results {
		if g := grantOf(r, &res); g != nil {
			serials = append(serials, api.FormatSerial(uint64(g.Serial)))
		}
	}
	return serials
}
