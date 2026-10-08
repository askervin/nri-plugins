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

package controller

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/client"
)

// attKey identifies an attachment: server device and host names.
type attKey struct {
	device string
	host   string
}

// want is one allocation result of our driver and pool.
type want struct {
	claim  *resourceapi.ResourceClaim
	result resourceapi.DeviceRequestAllocationResult
	device string // server device name, "" if not in the pool
	node   string
	host   *api.Host // nil: the node is not a pool host
}

func (w *want) key() attKey {
	if w.host == nil {
		return attKey{device: w.device}
	}
	return attKey{device: w.device, host: w.host.Name}
}

func (w *want) String() string {
	return fmt.Sprintf("claim %s/%s device %s node %s", w.claim.Namespace, w.claim.Name, w.result.Device, w.node)
}

// failure is a failed attach.
type failure struct {
	reason  string
	message string
}

// Owner returns the attachment owner of a claim.
func (c *Controller) Owner(claimUID types.UID) string {
	return c.cfg.OwnerPrefix + "resourceclaim/" + string(claimUID)
}

// allocationNode returns the node of an allocation (bindsToNode:
// matchFields metadata.name In [node]).
func allocationNode(a *resourceapi.AllocationResult) string {
	ns := a.NodeSelector
	if ns == nil || len(ns.NodeSelectorTerms) == 0 {
		return ""
	}
	for _, f := range ns.NodeSelectorTerms[0].MatchFields {
		if f.Key == "metadata.name" && len(f.Values) > 0 {
			return f.Values[0]
		}
	}
	return ""
}

// reconcile computes desired attachments from the claims and actual ones
// from the server, attaches missing ones, writes the claim status, and
// detaches attachments that no claim wants any more.
func (c *Controller) reconcile(ctx context.Context) error {
	// 1. hosts
	hosts, err := c.pool.Hosts(ctx)
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	nodes, err := c.nodes.List(labels.Everything())
	if err != nil {
		return err
	}
	hm := mapHosts(hosts, nodes)
	if s := hm.String(); s != c.hostMapStr {
		c.logf("pool hosts of nodes: %s", s)
		c.hostMapStr = s
	}

	// 2. desired
	claims, err := c.claims.List(labels.Everything())
	if err != nil {
		return err
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].Namespace != claims[j].Namespace {
			return claims[i].Namespace < claims[j].Namespace
		}
		return claims[i].Name < claims[j].Name
	})
	var wants []*want
	desired := map[attKey][]*want{}
	for _, claim := range claims {
		if claim.Status.Allocation == nil {
			continue
		}
		node := allocationNode(claim.Status.Allocation)
		for _, r := range claim.Status.Allocation.Devices.Results {
			if r.Driver != c.cfg.DriverName || r.Pool != c.cfg.PoolName {
				continue
			}
			w := &want{claim: claim, result: r, node: node}
			if d, ok := c.devices[r.Device]; ok {
				w.device = d.Name
			}
			if h, ok := hm.nodeHost[node]; ok {
				w.host = &h
			}
			wants = append(wants, w)
			if w.device != "" && w.host != nil {
				desired[w.key()] = append(desired[w.key()], w)
			}
		}
	}

	// 3. actual
	atts, err := c.pool.Attachments(ctx, "", "")
	if err != nil {
		return fmt.Errorf("list attachments: %w", err)
	}
	actual := map[attKey]api.Attachment{}
	for _, a := range atts {
		if a.Adopted || !strings.HasPrefix(a.Owner, c.cfg.OwnerPrefix) {
			continue
		}
		if _, ours := hm.hostNode[a.Host]; !ours {
			continue
		}
		actual[attKey{a.Device, a.Host}] = a
	}

	// 4. attach
	failures := map[attKey]failure{}
	for _, k := range sortedKeys(desired) {
		if _, ok := actual[k]; ok {
			continue
		}
		w := desired[k][0]
		a, f := c.attach(ctx, w, k, actual, desired)
		switch {
		case f != nil:
			failures[k] = *f
		case a != nil:
			actual[k] = *a
		}
	}

	// 5. status
	for _, w := range wants {
		c.writeStatus(ctx, w, actual, failures)
	}

	// 6. detach
	seen := map[string]bool{}
	for _, k := range sortedKeys(actual) {
		a := actual[k]
		seen[a.ID] = true
		if _, ok := desired[k]; ok {
			delete(c.attLogged, a.ID)
			continue
		}
		c.detach(ctx, a, hm, claims)
	}
	for id := range c.attLogged {
		if !seen[id] {
			delete(c.attLogged, id)
		}
	}
	return nil
}

func sortedKeys[V any](m map[attKey]V) []attKey {
	ks := make([]attKey, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].device != ks[j].device {
			return ks[i].device < ks[j].device
		}
		return ks[i].host < ks[j].host
	})
	return ks
}

// attach attaches the device of a desired key. It returns the attachment,
// or a failure, or neither (attaching continues, or waiting for a detach).
func (c *Controller) attach(ctx context.Context, w *want, k attKey, actual map[attKey]api.Attachment, desired map[attKey][]*want) (*api.Attachment, *failure) {
	owner := c.Owner(w.claim.UID)
	actx, cancel := context.WithTimeout(ctx, c.cfg.AttachTimeout+10*time.Second)
	defer cancel()
	a, status, err := c.pool.Attach(actx, k.device, api.AttachRequest{
		Host:    k.host,
		Owner:   owner,
		Wait:    ptr.To(true),
		Timeout: c.cfg.AttachTimeout.String(),
	})
	if err == nil {
		switch status {
		case http.StatusAccepted:
			c.logf("attach %s to %s for %s: still attaching after %s", k.device, k.host, w, c.cfg.AttachTimeout)
		case http.StatusOK:
			c.logf("attach %s to %s for %s: already attached (%s, owner %q)", k.device, k.host, w, a.State, a.Owner)
		default:
			c.logf("attached %s to %s (node %s, slot %s, qemu device %s, owner %s) for %s/%s",
				k.device, k.host, w.node, a.Slot.Bus, a.QemuDeviceID, owner, w.claim.Namespace, w.claim.Name)
		}
		return a, nil
	}
	if ctx.Err() != nil {
		return nil, nil
	}
	f := &failure{reason: ReasonAttachError, message: fmt.Sprintf("attach %s to %s: %v", k.device, k.host, err)}
	switch {
	case actx.Err() != nil || strings.Contains(err.Error(), "deadline exceeded"):
		f.reason = ReasonTimeout
	case api.IsCode(err, api.CodeConflict):
		f.reason = ReasonConflict
		// An exclusive device that moves between our nodes: the old
		// attachment is detached in this reconcile, attach again in the next
		// one instead of failing the new allocation.
		for ok, oa := range actual {
			if ok.device == k.device && ok.host != k.host {
				if _, still := desired[ok]; !still {
					c.logf("attach %s to %s for %s: waiting for its detach from %s (%s)", k.device, k.host, w, ok.host, oa.State)
					return nil, nil
				}
			}
		}
	}
	c.logf("ERROR: %s for %s: %s", f.reason, w, f.message)
	return nil, f
}

// writeStatus writes Attached or AttachFailed into the claim status of a
// want when it is not there yet.
func (c *Controller) writeStatus(ctx context.Context, w *want, actual map[attKey]api.Attachment, failures map[attKey]failure) {
	var f *failure
	switch {
	case w.device == "":
		f = &failure{ReasonAttachError, fmt.Sprintf("device %s is not in pool %s", w.result.Device, c.cfg.PoolName)}
	case w.host == nil:
		f = &failure{ReasonNoHost, fmt.Sprintf("node %q is not a host of the pool", w.node)}
	default:
		if x, ok := failures[w.key()]; ok {
			f = &x
		}
	}
	if f != nil {
		if old := hasCondition(w.claim, w.result, c.condFailed()); old != nil && old.Message == f.message && old.Reason == f.reason {
			return
		}
		cond := metav1.Condition{Type: c.condFailed(), Status: metav1.ConditionTrue, Reason: f.reason, Message: f.message}
		c.updateStatus(ctx, w, cond, nil, corev1.EventTypeWarning, EventAttachFailed)
		return
	}
	a, ok := actual[w.key()]
	if !ok || a.State != api.AttachmentAttached {
		if ok {
			c.debugf("%s: attachment %s is %s", w, a.ID, a.State)
		}
		return
	}
	if hasCondition(w.claim, w.result, c.condAttached()) != nil {
		return
	}
	d := c.devices[w.result.Device]
	serial := a.Serial
	if serial == "" {
		serial = d.Serial
	}
	data := DeviceData{
		Serial:       strings.ToLower(serial),
		Shared:       d.Shared,
		Size:         d.Size,
		Host:         a.Host,
		HostUUID:     w.host.UUID,
		Attachment:   a.ID,
		QemuDeviceID: a.QemuDeviceID,
	}
	cond := metav1.Condition{
		Type:    c.condAttached(),
		Status:  metav1.ConditionTrue,
		Reason:  ReasonAttached,
		Message: fmt.Sprintf("%s attached to %s (slot %s)", w.result.Device, a.Host, a.Slot.Bus),
	}
	c.updateStatus(ctx, w, cond, data, corev1.EventTypeNormal, EventAttached)
}

func (c *Controller) updateStatus(ctx context.Context, w *want, cond metav1.Condition, data any, eventType, reason string) {
	written, err := c.setClaimDeviceStatus(ctx, w.claim, w.result, cond, data)
	if err != nil {
		c.logf("ERROR: status of %s: %v", w, err)
		return
	}
	if !written {
		c.debugf("status of %s: up to date or claim no longer allocated", w)
		return
	}
	c.logf("status of %s: %s=True reason %s: %s", w, cond.Type, cond.Reason, cond.Message)
	c.recorder.Event(w.claim, eventType, reason, cond.Message)
}

// detach detaches an attachment that no claim wants. Only attachments in
// state attached get a detach request: a "detaching" one is waited for by
// the server (the guest has not released the device yet), a "failed" one
// is left alone (D14).
func (c *Controller) detach(ctx context.Context, a api.Attachment, hm hostMap, claims []*resourceapi.ResourceClaim) {
	switch a.State {
	case api.AttachmentAttaching:
		c.debugf("detach %s: still attaching, later", a.ID)
		return
	case api.AttachmentDetaching:
		c.logf("detach %s: still detaching (has the guest released the device?)", a.ID)
		return
	case api.AttachmentFailed:
		if st := a.State + ": " + a.Error; c.attLogged[a.ID] != st {
			c.attLogged[a.ID] = st
			c.logf("ERROR: detach %s: attachment failed: %s; not retried (the guest kept the device: see README, release before detach)", a.ID, a.Error)
		}
		return
	}
	dctx, cancel := context.WithTimeout(ctx, c.cfg.DetachTimeout+10*time.Second)
	defer cancel()
	res, _, err := c.pool.Detach(dctx, a.Device, a.Host, client.DetachOptions{Timeout: c.cfg.DetachTimeout})
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		state := a.State
		if res != nil && res.State != "" {
			state = res.State
		}
		c.logf("ERROR: detach %s (owner %s): %v; attachment %s, retrying later", a.ID, a.Owner, err, state)
		return
	}
	node := hm.hostNode[a.Host]
	msg := fmt.Sprintf("%s detached from %s (node %s)", a.Device, a.Host, node)
	c.logf("detached %s from %s (node %s, owner %s)", a.Device, a.Host, node, a.Owner)
	delete(c.attLogged, a.ID)
	var obj runtime.Object
	uid := strings.TrimPrefix(a.Owner, c.cfg.OwnerPrefix+"resourceclaim/")
	for _, claim := range claims {
		if string(claim.UID) == uid {
			obj = claim
			break
		}
	}
	if obj == nil && node != "" {
		if n, err := c.nodes.Get(node); err == nil {
			obj = n
		}
	}
	if obj != nil {
		c.recorder.Event(obj, corev1.EventTypeNormal, EventDetached, msg)
	}
}
