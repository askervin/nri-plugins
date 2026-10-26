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

// Adoption records (05-review R5): what an on-line run adopted from its
// observations, written to mbt-steps.txt after the step as
//
//	#adopt N alt=J phase=SLOT:PHASE node=SLOT:VM steer=SLOT:on|off
//	        att=DEV@VM:yes|no stack=VM/hbB:K,K lease=SLOT:ID data=SLOT:TEXT
//
// (one line, items separated by spaces, TEXT query-escaped): the
// alternative of the settle that fitted and what the observation
// decided beyond it. `generate --from` replays them, so that its
// expectations follow the run, and replays ignore them (they observe
// again).

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// adoptPrefix starts an adoption record line.
const adoptPrefix = "#adopt "

// adoptionRecord describes how adopted differs from the prediction pred
// (the settled state of the step, alternatives in pred.Alts) given the
// alternative alt that fitted; "" if nothing.
func adoptionRecord(pred *State, alt int, adopted *State) string {
	base := pred
	if alt > 0 && alt <= len(pred.Alts) {
		base = pred.Alts[alt-1]
	}
	var items []string
	if alt > 0 {
		items = append(items, "alt="+strconv.Itoa(alt))
	}
	for i := range adopted.Slots {
		a, b := &adopted.Slots[i], &base.Slots[i]
		name := adopted.slot(i).Name
		if a.Phase != b.Phase {
			items = append(items, "phase="+name+":"+a.Phase.String())
		}
		if a.Node != b.Node && a.Node != VMAny {
			items = append(items, "node="+name+":"+a.Node.String())
		}
		if a.Restarts != b.Restarts || a.Slack != b.Slack {
			items = append(items, "restarts="+name+":"+strconv.Itoa(int(a.Restarts))+"+"+strconv.Itoa(int(a.Slack)))
		}
		if a.Steer != b.Steer && (a.Steer == SteerOn || a.Steer == SteerOff) {
			items = append(items, "steer="+name+":"+a.Steer.String())
		}
		if adopted.LeaseIDs[i] != base.LeaseIDs[i] && adopted.LeaseIDs[i] != "" {
			items = append(items, "lease="+name+":"+url.QueryEscape(adopted.LeaseIDs[i]))
		}
		if t := adopted.SlotData[i]; t != base.SlotData[i] && t.Known {
			items = append(items, "data="+name+":"+url.QueryEscape(t.Text))
		}
	}
	for d := DevID(0); d < nDevs; d++ {
		if t := adopted.Data[d]; t != base.Data[d] && t.Known {
			items = append(items, "data="+d.String()+":"+url.QueryEscape(t.Text))
		}
	}
	for p := Pool(0); p < nPools; p++ {
		for d := 0; d < 2; d++ {
			for v := VM(0); v < nVMs; v++ {
				x, y := adopted.Ctrl[p].Att[d][v], base.Ctrl[p].Att[d][v]
				if x != y && x != TriMaybe {
					val := "no"
					if x == TriYes {
						val = "yes"
					}
					items = append(items, "att="+devices[2*int(p)+d].Name+"@"+v.String()+":"+val)
				}
			}
		}
	}
	for p := Pool(0); p < nPools; p++ {
		if x := adopted.Ctrl[p].Slices; x != base.Ctrl[p].Slices && x != SlicesUnknown {
			items = append(items, "slices="+p.String()+":"+x.String())
		}
	}
	for d := DevID(0); d < nDevs; d++ {
		if base.held(Res(d)) && !adopted.held(Res(d)) {
			items = append(items, "held="+d.String()+":off")
		}
	}
	for si := 0; si < nStacks; si++ {
		if !adopted.Stacks[si].equal(&base.Stacks[si]) {
			var keys []string
			for _, k := range adopted.Stacks[si].keys() {
				keys = append(keys, k.String())
			}
			items = append(items, "stack="+stackName(si)+":"+strings.Join(keys, ","))
		}
	}
	return strings.Join(items, " ")
}

// applyAdoption applies a record to the state after a step: the
// alternative first (settle), then the items.
func applyAdoption(st *State, rec string) (*State, error) {
	fields := strings.Fields(rec)
	if len(fields) > 0 && strings.HasPrefix(fields[0], "alt=") {
		j, err := strconv.Atoi(strings.TrimPrefix(fields[0], "alt="))
		if err != nil || j < 0 || j > len(st.Alts) {
			return nil, fmt.Errorf("adoption %q: no alternative %s", rec, fields[0])
		}
		if j > 0 {
			st = st.Alts[j-1]
		}
		fields = fields[1:]
	}
	n := st.clone()
	for _, f := range fields {
		kind, rest, ok := strings.Cut(f, "=")
		if !ok {
			return nil, fmt.Errorf("adoption %q: invalid item %q", rec, f)
		}
		key, val, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, fmt.Errorf("adoption %q: invalid item %q", rec, f)
		}
		if err := n.applyItem(kind, key, val); err != nil {
			return nil, fmt.Errorf("adoption %q: %s: %w", rec, f, err)
		}
	}
	for p := Pool(0); p < nPools; p++ {
		if n.Ctrl[p].Up {
			n.deriveAtt(p)
		}
	}
	n.growFence()
	return n, nil
}

func (n *State) applyItem(kind, key, val string) error {
	slot := func() (int, error) {
		i := n.cfg.slotIndex(key)
		if i < 0 {
			return 0, fmt.Errorf("unknown slot %q", key)
		}
		return i, nil
	}
	switch kind {
	case "phase":
		i, err := slot()
		if err != nil {
			return err
		}
		ph, err := parsePhase(val)
		if err != nil {
			return err
		}
		n.Slots[i].Phase = ph
	case "node":
		i, err := slot()
		if err != nil {
			return err
		}
		v, err := parseVM(val)
		if err != nil {
			return err
		}
		n.Slots[i].Node = v
	case "restarts":
		i, err := slot()
		if err != nil {
			return err
		}
		r, sl, _ := strings.Cut(val, "+")
		nr, err1 := strconv.Atoi(r)
		ns, err2 := strconv.Atoi(sl)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid restarts %q", val)
		}
		n.Slots[i].Restarts, n.Slots[i].Slack = uint8(nr), uint8(ns)
	case "steer":
		i, err := slot()
		if err != nil {
			return err
		}
		switch val {
		case "on":
			n.Slots[i].Steer = SteerOn
		case "off":
			n.Slots[i].Steer = SteerOff
		default:
			return fmt.Errorf("invalid steering %q", val)
		}
	case "lease":
		i, err := slot()
		if err != nil {
			return err
		}
		id, err := url.QueryUnescape(val)
		if err != nil {
			return err
		}
		n.setLeaseID(i, id)
	case "data":
		text, err := url.QueryUnescape(val)
		if err != nil {
			return err
		}
		t := Token{Known: true, Text: text}
		if i := n.cfg.slotIndex(key); i >= 0 {
			n.setSlotData(i, t)
			return nil
		}
		for d := DevID(0); d < nDevs; d++ {
			if d.String() == key {
				n.Data[d] = t
				return nil
			}
		}
		return fmt.Errorf("unknown slot or device %q", key)
	case "att":
		d, v, err := parseDevAt(key)
		if err != nil {
			return err
		}
		p := devices[d].Pool
		t := TriNo
		if val == "yes" {
			t = TriYes
		}
		n.Ctrl[p].Att[int(d)-2*int(p)][v] = t
	case "slices":
		p, err := parsePool(key)
		if err != nil {
			return err
		}
		switch val {
		case "present":
			n.Ctrl[p].Slices = SlicesPresent
		case "absent":
			n.Ctrl[p].Slices = SlicesAbsent
		default:
			return fmt.Errorf("invalid slices %q", val)
		}
	case "held":
		for d := DevID(0); d < nDevs; d++ {
			if d.String() == key && val == "off" {
				n.Held &^= 1 << uint(d)
				n.HeldAt[d] = 0
				return nil
			}
		}
		return fmt.Errorf("invalid held %q:%q", key, val)
	case "stack":
		si := -1
		for x := 0; x < nStacks; x++ {
			if stackName(x) == key {
				si = x
			}
		}
		if si < 0 {
			return fmt.Errorf("unknown stack %q", key)
		}
		var st Stack
		if val != "" {
			for _, kn := range strings.Split(val, ",") {
				k, ok := parseRKey(kn)
				if !ok {
					return fmt.Errorf("invalid region %q", kn)
				}
				st.push(k)
			}
		}
		n.Stacks[si] = st
	default:
		return fmt.Errorf("unknown item %q", kind)
	}
	return nil
}

// openChoice tells what the model leaves open in a settled state that
// only an observation decides, "" if nothing (generate --from without
// adoption records stops there).
func (s *State) openChoice() string {
	if len(s.Alts) > 0 {
		return fmt.Sprintf("%d outcomes of races", len(s.Alts)+1)
	}
	for i := range s.Slots {
		ss := &s.Slots[i]
		switch {
		case ss.Phase == Running && ss.Node == VMAny:
			return "the node of " + s.slot(i).Name
		case ss.Phase == Either:
			return "the outcome of " + s.slot(i).Name
		case ss.Phase == Running && ss.Steer == SteerAny:
			return "the steering of " + s.slot(i).Name
		}
	}
	for p := Pool(0); p < nPools; p++ {
		for _, row := range s.Ctrl[p].Att {
			for _, t := range row {
				if t == TriMaybe {
					return "the attachments of pool " + p.String()
				}
			}
		}
	}
	return ""
}

// stepLine is a step of a steps file with its adoption record.
type stepLine struct {
	Action string
	Adopt  string
	Has    bool // a record was written for the step
}

// readSteps reads a steps file: actions, their adoption records, and the
// flags of its header (the second comment line, "# --profile ...").
func readSteps(data string) ([]stepLine, []string) {
	var out []stepLine
	var header []string
	n := 0
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, adoptPrefix):
			f := strings.SplitN(strings.TrimPrefix(line, adoptPrefix), " ", 2)
			if step, err := strconv.Atoi(f[0]); err == nil && step == n && n > 0 {
				out[n-1].Has = true
				if len(f) == 2 {
					out[n-1].Adopt = f[1]
				}
			}
		case strings.HasPrefix(line, "# --"):
			if header == nil {
				header = splitFlags(strings.TrimPrefix(line, "# "))
			}
		case strings.HasPrefix(line, "#"):
		default:
			out = append(out, stepLine{Action: line})
			n++
		}
	}
	return out, header
}

// splitFlags splits a flag line as the header writes it (values may be
// %q-quoted).
func splitFlags(s string) []string {
	var out []string
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			break
		}
		if s[0] == '"' {
			q, err := strconv.QuotedPrefix(s)
			if err == nil {
				v, _ := strconv.Unquote(q)
				out = append(out, v)
				s = s[len(q):]
				continue
			}
		}
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			out = append(out, s)
			break
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}
