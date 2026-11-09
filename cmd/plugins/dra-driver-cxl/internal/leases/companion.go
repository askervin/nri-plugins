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

package leases

import (
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/lend"
	"github.com/containers/nri-plugins/cmd/plugins/dra-driver-cxl/internal/state"
	"github.com/containers/nri-plugins/pkg/cxl/api"
	"github.com/containers/nri-plugins/pkg/cxl/config"
	"github.com/containers/nri-plugins/pkg/cxl/device"
)

// The companion of a lease: a ResourceClaim and a pause pod cxl-lease-<id>
// in the requester's namespace, labeled with the lease, the requester and
// the node, the claim owned (controller) and the pod owned by the
// requester pod, the pod pinned to this node. The claim asks for the
// device of the lease from the source of the lease, or from local then
// pool memory (firstAvailable), with one MemoryConfig of the device
// section per driver; the pod references the claim but no container uses
// it, so the drivers prepare it without CDI devices and lend its memory
// through the hooks below.

const (
	// companionClaimRef is the name of the claim in the companion pod and
	// of the request in the companion claim.
	companionClaimRef  = "lease"
	companionContainer = "pause"
)

// companionObjects returns the companion claim and pod of a lease.
func (b *Broker) companionObjects(l *state.Lease) (*resourcev1.ResourceClaim, *corev1.Pod, error) {
	name := CompanionName(l.ID)
	labels := map[string]string{
		device.LeaseLabel:        l.ID,
		device.RequesterUIDLabel: l.Pod.UID,
		device.NodeLabel:         b.opts.NodeName,
	}
	annotations := map[string]string{
		device.RequesterAnnotation: l.Pod.Namespace + "/" + l.Pod.Name + "/" + l.Container,
	}
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: l.Pod.Name, UID: types.UID(l.Pod.UID)}
	claimOwner := owner
	claimOwner.Controller = ptr(true)

	req, configs, err := b.companionRequest(l)
	if err != nil {
		return nil, nil, err
	}
	claim := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       l.Pod.Namespace,
			Labels:          labels,
			Annotations:     annotations,
			OwnerReferences: []metav1.OwnerReference{claimOwner},
		},
		Spec: resourcev1.ResourceClaimSpec{
			Devices: resourcev1.DeviceClaim{
				Requests: []resourcev1.DeviceRequest{*req},
				Config:   configs,
			},
		},
	}
	// Guaranteed QoS keeps the companion from being evicted first. The
	// CPU limit is 100m, not 1m: with a 1m limit a pause pod needs ~12 s to
	// reach Running on the e2e VMs (CFS throttling of the container start),
	// which delays the release of a lease whose companion has not started
	// yet; with 100m it takes ~2 s. The memory limit leaves room for runc
	// init, which needs about 9 MiB in the container's cgroup.
	res := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("100m"),
		corev1.ResourceMemory: resource.MustParse("16Mi"),
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       l.Pod.Namespace,
			Labels:          labels,
			Annotations:     annotations,
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Spec: corev1.PodSpec{
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchFields: []corev1.NodeSelectorRequirement{{
							Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{b.opts.NodeName},
						}},
					}},
				},
			}},
			Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			RestartPolicy:                 corev1.RestartPolicyAlways,
			AutomountServiceAccountToken:  ptr(false),
			EnableServiceLinks:            ptr(false),
			TerminationGracePeriodSeconds: ptr(int64(1)),
			// the restricted Pod Security profile: the pod is made in the
			// requester's namespace, which may enforce it
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr(true),
				RunAsUser:      ptr(companionUser),
				RunAsGroup:     ptr(companionUser),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			ResourceClaims: []corev1.PodResourceClaim{{Name: companionClaimRef, ResourceClaimName: ptr(name)}},
			Containers: []corev1.Container{{
				Name:      companionContainer,
				Image:     b.opts.Image,
				Resources: corev1.ResourceRequirements{Requests: res, Limits: res.DeepCopy()},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr(false),
					ReadOnlyRootFilesystem:   ptr(true),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
		},
	}
	return claim, pod, nil
}

// companionUser is the user and group of the companion container: the
// nobody of the pause image.
const companionUser = int64(65535)

// ptr returns a pointer to v.
func ptr[T any](v T) *T {
	return &v
}

// companionSources returns the sources of the devices that the companion
// claim of a lease accepts, the preferred one first: the requested one,
// that of the device of the serial, or local, then pool.
func (b *Broker) companionSources(l *state.Lease) ([]state.Source, error) {
	var sources []state.Source
	for _, s := range []state.Source{state.SourceLocal, state.SourcePool} {
		switch {
		case l.Asked.Source != "" && l.Asked.Source != s:
		case l.Asked.DeviceSource != "" && l.Asked.DeviceSource != s:
		case s == state.SourcePool && b.opts.PoolDriver == "":
		default:
			sources = append(sources, s)
		}
	}
	if len(sources) == 0 {
		return nil, errPoolDisabled
	}
	return sources, nil
}

// companionRequest returns the device request and the opaque configs of
// the companion claim of a lease: one MemoryConfig with the device section
// of the lease per driver. A lease with one source gets an exact request;
// with more, a request with one subrequest per source in order of
// preference (firstAvailable), and configs that apply to the subrequest of
// their driver only.
func (b *Broker) companionRequest(l *state.Lease) (*resourcev1.DeviceRequest, []resourcev1.DeviceClaimConfiguration, error) {
	sources, err := b.companionSources(l)
	if err != nil {
		return nil, nil, err
	}
	req := &resourcev1.DeviceRequest{Name: companionClaimRef}
	var configs []resourcev1.DeviceClaimConfiguration
	for _, source := range sources {
		exact, driver, err := b.companionDevices(l, source)
		if err != nil {
			return nil, nil, err
		}
		var requests []string
		if len(sources) == 1 {
			req.Exactly = exact
		} else {
			req.FirstAvailable = append(req.FirstAvailable, resourcev1.DeviceSubRequest{
				Name:            string(source),
				DeviceClassName: exact.DeviceClassName,
				Selectors:       exact.Selectors,
				Capacity:        exact.Capacity,
			})
			requests = []string{companionClaimRef + "/" + string(source)}
		}
		cfg, err := companionConfig(l, driver, requests)
		if err != nil {
			return nil, nil, err
		}
		configs = append(configs, cfg)
	}
	return req, configs, nil
}

// companionConfig returns the opaque MemoryConfig of the driver of the
// companion claim of a lease for the requests (nil: all): the mode and,
// for fs, readOnly explicitly and access and fsType only when asked for
// (no path: the companion pod gets no mount); for the other modes readOnly
// when asked for.
func companionConfig(l *state.Lease, driver string, requests []string) (resourcev1.DeviceClaimConfiguration, error) {
	dev := &config.Device{Mode: string(l.Asked.Mode)}
	switch {
	case l.Asked.Mode == state.ModeFs:
		dev.ReadOnly = ptr(readOnly(l))
		dev.Access, dev.FsType = string(l.Asked.Access), l.Asked.FsType
	case l.Asked.ReadOnly:
		dev.ReadOnly = ptr(true)
	}
	cfg := &config.MemoryConfig{APIVersion: config.APIVersion, Kind: config.Kind, Device: dev}
	params, err := json.Marshal(cfg)
	if err != nil {
		return resourcev1.DeviceClaimConfiguration{}, err
	}
	return resourcev1.DeviceClaimConfiguration{
		Requests: requests,
		DeviceConfiguration: resourcev1.DeviceConfiguration{
			Opaque: &resourcev1.OpaqueDeviceConfiguration{
				Driver:     driver,
				Parameters: runtime.RawExtension{Raw: params},
			},
		},
	}, nil
}

// companionDevices returns what the companion claim of a lease requests
// from one source, and the driver of its devices: the DeviceClass (of
// persistent devices for modes block and fs), the selectors of the serial
// and, on devices with shares, of the size, and the capacity: memory on
// devices without shares, one share when the lease shares a device, none
// (the whole device) when it takes a device with shares exclusively. Every
// persistent local memdev has shares.
func (b *Broker) companionDevices(l *state.Lease, source state.Source) (*resourcev1.ExactDeviceRequest, string, error) {
	driver, class, shares := device.DriverName, device.ClassLocal, deviceShares(l)
	switch {
	case source == state.SourcePool:
		driver, class = b.opts.PoolDriver, poolClass(l)
	case persistent(l.Asked.Mode):
		class, shares = device.ClassLocalPersistent, true
	case deviceShares(l):
		class = device.ClassLocalShared
	}
	exact := &resourcev1.ExactDeviceRequest{DeviceClassName: class}
	var cel []string
	if l.Asked.AsksSerial() {
		cel = append(cel, fmt.Sprintf(`device.attributes[%q].%s == %q`, driver, device.AttrSerial, l.Asked.Serial.String()))
	}
	var size resource.Quantity
	if l.Asked.Size != "" {
		q, err := resource.ParseQuantity(l.Asked.Size)
		if err != nil {
			return nil, "", fmt.Errorf("size %q: %w", l.Asked.Size, err)
		}
		size = q
	}
	switch {
	case !shares:
		if l.Asked.Size != "" {
			exact.Capacity = &resourcev1.CapacityRequirements{
				Requests: map[resourcev1.QualifiedName]resource.Quantity{device.CapacityMemory: size},
			}
		}
	default:
		if l.Asked.Size != "" {
			cel = append(cel, fmt.Sprintf(`device.attributes[%q].%s >= %d`, driver, device.AttrSize, size.Value()))
		}
		if l.Asked.Shared {
			exact.Capacity = &resourcev1.CapacityRequirements{
				Requests: map[resourcev1.QualifiedName]resource.Quantity{device.CapacityShares: resource.MustParse("1")},
			}
		}
	}
	for _, e := range cel {
		exact.Selectors = append(exact.Selectors, resourcev1.DeviceSelector{CEL: &resourcev1.CELDeviceSelector{Expression: e}})
	}
	return exact, driver, nil
}

// deviceShares tells whether the device of a lease is a shared device:
// one share of it, or the whole device.
func deviceShares(l *state.Lease) bool {
	return l.Asked.Shared || l.Asked.SharedDevice
}

// poolClass returns the DeviceClass of the pool device of a lease.
func poolClass(l *state.Lease) string {
	switch {
	case persistent(l.Asked.Mode):
		return device.ClassPoolPersistent
	case deviceShares(l):
		return device.ClassPoolShared
	}
	return device.ClassPool
}

// createCompanion creates the claim, then the pod of a lease.
func (b *Broker) createCompanion(l *state.Lease) error {
	if b.opts.Client == nil {
		return errors.New("no Kubernetes client")
	}
	claim, pod, err := b.companionObjects(l)
	if err != nil {
		return err
	}
	ctx, cancel := b.apiContext()
	defer cancel()
	created, err := b.opts.Client.ResourceV1().ResourceClaims(claim.Namespace).Create(ctx, claim, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating companion claim %s/%s: %w", claim.Namespace, claim.Name, err)
	}
	b.mu.Lock()
	b.specHashes[l.ID] = lend.SpecHash(&created.Spec)
	b.mu.Unlock()
	if _, err := b.opts.Client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating companion pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	klog.Infof("lease broker: lease %s: created companion claim and pod %s/%s", l.ID, pod.Namespace, pod.Name)
	return nil
}

// The hooks (lend.LeaseHooks) that the drivers call for the companion
// claims with the claim locked: they only touch the records of the broker.

// CompanionSpecHash returns the hash of the spec of the companion claim of
// the lease id as the API server returned it at its creation ("" if this
// process did not create it), and whether the lease waits for the first
// Prepare of the claim (CREATING or PENDING).
func (b *Broker) CompanionSpecHash(id string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.leases[id]
	if l == nil {
		return "", false
	}
	return b.specHashes[id], l.State == state.LeaseCreating || l.State == state.LeasePending
}

// OnLending is the companion gate: it checks that a claim is the companion
// of a lease that is being created or lent (its name cxl-lease-<id>, its
// namespace and owner pod those of the requester), marks the lease LENDING
// and returns the lend of the requester's container, with the filesystem
// directory of the lease claim and the name of an fs lease.
func (b *Broker) OnLending(id string, claim *resourcev1.ResourceClaim) (*lend.Lend, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.leases[id]
	if l == nil || claim.Name != CompanionName(id) || claim.Namespace != l.Pod.Namespace || !ownedBy(claim, l.Pod.UID) {
		return nil, fmt.Errorf("claim %s/%s: not the companion of lease %s", claim.Namespace, claim.Name, id)
	}
	switch l.State {
	case state.LeaseCreating, state.LeasePending:
		apply(l, state.LeaseLending, state.TriggerOnLending)
		b.saveLocked()
	case state.LeaseLending, state.LeaseReady:
		apply(l, l.State, state.TriggerOnLending)
	default:
		return nil, fmt.Errorf("lease %s is %s", l.ID, stateName(l.State))
	}
	rec := &lend.Lend{Lease: id, Pod: l.Pod, Container: l.Container}
	if l.Asked.Mode == state.ModeFs {
		if lc := b.claims[l.Claim]; lc != nil {
			rec.FsDir = lc.FsDir
		}
		rec.Name = l.Asked.Name
	}
	return rec, nil
}

// ownedBy tells whether a claim has an owner reference with the uid.
func ownedBy(claim *resourcev1.ResourceClaim, uid string) bool {
	for _, o := range claim.OwnerReferences {
		if string(o.UID) == uid {
			return true
		}
	}
	return false
}

// OnPrepared makes a lease READY with the first prepared device of its
// companion and its lend. A device whose mode is fs or block when the
// lease's is not, or the reverse, fails the lease, and it is released.
func (b *Broker) OnPrepared(id string, devs []lend.LentDevice) {
	b.mu.Lock()
	l := b.leases[id]
	if l == nil || releasingState(l.State) || len(devs) == 0 {
		b.mu.Unlock()
		return
	}
	d := devs[0]
	if mode := state.Mode(d.Mode); (mode == state.ModeFs) != (l.Asked.Mode == state.ModeFs) || (mode == state.ModeBlock) != (l.Asked.Mode == state.ModeBlock) {
		if apply(l, state.LeaseFailed, state.TriggerOnPrepared) {
			l.Error = fmt.Sprintf("companion prepared mode %s, lease is mode %s", d.Mode, l.Asked.Mode)
			b.saveLocked()
			klog.Errorf("lease broker: lease %s: %s", id, l.Error)
		}
		b.mu.Unlock()
		b.startRelease(id, "wrong mode", state.TriggerOnPrepared)
		return
	}
	defer b.mu.Unlock()
	if !apply(l, state.LeaseReady, state.TriggerOnPrepared) {
		return
	}
	l.Got, l.Lend = b.gotOf(l, &d)
	l.Error = ""
	b.saveLocked()
	g := l.Got
	klog.Infof("lease broker: lease %s: Ready (source %s, serial %s, mode %s, read-only %v, node %d, dax %q, block %q, access %q, fs %q, path %q, %d bytes)",
		l.ID, g.Source, g.Serial, l.Asked.Mode, readOnly(l), numaNodeOf(l), g.Dax, g.Block, accessOf(l), fsTypeOf(l), g.Path, g.Bytes)
}

// gotOf returns what the prepared device gives a lease and what the lease
// lends: the NUMA node of a numa lease, the bind of an fs lease in the
// filesystem directory of its lease claim. Called with b.mu held.
func (b *Broker) gotOf(l *state.Lease, d *lend.LentDevice) (*state.LeaseGot, *state.Lend) {
	g := &state.LeaseGot{Source: state.Source(d.Source), Serial: state.Serial(d.Serial), Bytes: d.Size}
	if persistent(state.Mode(d.Mode)) {
		// the attribute shared of the device, whatever the share
		g.SharedDevice = d.Shared
	} else {
		g.SharedDevice = l.Asked.SharedDevice || d.Shared
	}
	switch d.Mode {
	case api.ModeDax:
		g.Dax = d.DaxDevice
	case api.ModeFs:
		g.Access, g.FsType, g.Path = state.Access(d.Access), d.FsType, api.FsDir+"/"+l.Asked.Name
		fsDir := ""
		if lc := b.claims[l.Claim]; lc != nil {
			fsDir = lc.FsDir
		}
		if target := fsBindTarget(fsDir, l.Asked.Name); target != "" {
			return g, &state.Lend{BindTarget: target}
		}
	case api.ModeBlock:
		g.Block = d.BlockDevice
	default:
		if d.NumaNode >= 0 {
			return g, &state.Lend{NumaNode: state.NumaNodePtr(d.NumaNode)}
		}
	}
	return g, nil
}

// OnLendFailed fails the lease with the lend error (for example a
// container that is memory-steered, not started or gone) and releases it:
// the waiting request returns Failed with the message.
func (b *Broker) OnLendFailed(id string, err error) {
	b.mu.Lock()
	l := b.leases[id]
	if l == nil || releasingState(l.State) || l.State == state.LeaseFailed || !apply(l, state.LeaseFailed, state.TriggerOnLendFailed) {
		b.mu.Unlock()
		return
	}
	l.Error = err.Error()
	b.saveLocked()
	b.mu.Unlock()
	b.startRelease(id, "lend failed", state.TriggerOnLendFailed)
}

// OnReleasing is told that the companion claim of a lease is being
// unprepared. Unless the broker is releasing the lease, the companion was
// deleted or evicted behind its back: the lease fails (the requester has
// lost the memory) and the reconcile releases it.
func (b *Broker) OnReleasing(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.leases[id]
	if l == nil || releasingState(l.State) || !apply(l, state.LeaseFailed, state.TriggerOnReleasing) {
		return
	}
	l.Error = "companion claim unprepared (companion pod deleted or evicted)"
	b.saveLocked()
	klog.Warningf("lease broker: lease %s: %s", id, l.Error)
}
