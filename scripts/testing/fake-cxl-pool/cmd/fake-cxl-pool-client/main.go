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

// fake-cxl-pool-client is the command line client of fake-cxl-pool. It
// talks to fake-cxl-pool-server, and in a VM it also prepares and releases
// hotplugged CXL memory (the "guest" commands).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/containers/nri-plugins/pkg/cxl/memctl"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/api"
	"github.com/containers/nri-plugins/scripts/testing/fake-cxl-pool/pkg/client"
)

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitConflict = 3 // conflict or timeout: the device is still held
)

const usage = `Usage: fake-cxl-pool-client [--server URL] [-o table|json] COMMAND [ARGS]

Server URL default: $FAKE_CXL_POOL_SERVER, else ` + api.DefaultServerURL + `

Commands:
  status
  pools [NAME]
  hosts [NAME]
  whoami                                  resolve this VM (uuid, hostname) to a host
  rescan                                  rediscover qemu processes
  devices [NAME] [--shared] [--free] [--host H]
  create --size 256M [--shared] [--name N] [--pool P] [--serial 0x..] [--label k=v]...
  delete NAME [--force]
  attach DEVICE (--self | --host HOST) [--slot BUS] [--numa N] [--owner O] [--no-wait] [--timeout 30s] [--force]
  detach DEVICE (--self | --host HOST) [--timeout 30s] [--no-wait] [--owner O] [--force]
  attachments [--self | --host H] [--device D]
  allocate DEVICE --owner O [--note TEXT]
  release DEVICE [--owner O] [--force]
  events                                  stream server events (JSON lines)

Guest commands (run inside the VM, as root; DEVICE is a device name or a serial 0x...):
  guest wait DEVICE [--timeout 30s]       wait until the device appears, print memN
  guest memdev DEVICE                     print memN of the device
  guest region create DEVICE --mode devdax|ram [--decoder decoderX.Y]
  guest online DEVICE [--movable]         online the memory of the region (mode ram)
  guest info DEVICE                       print memdev, region, dax device, mode, node
  guest release DEVICE                    offline, destroy regions, disable memdev

Exit codes: 0 ok, 1 error, 2 usage, 3 conflict/timeout (device still held).
`

type cli struct {
	server  string
	output  string
	stdout  io.Writer
	stderr  io.Writer
	c       *client.Client
	verbose bool
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c := &cli{stdout: stdout, stderr: stderr}
	fs := c.flagSet("fake-cxl-pool-client")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return exitOK
		}
		fmt.Fprintf(stderr, "error: %v\n\n%s", err, usage)
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	err := c.dispatch(ctx, rest[0], rest[1:])
	return c.exitCode(err)
}

func (c *cli) exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(c.stderr, "error: %s\n\n%s", ue.msg, usage)
		return exitUsage
	}
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(c.stdout, usage)
		return exitOK
	}
	fmt.Fprintf(c.stderr, "error: %v\n", err)
	if api.IsCode(err, api.CodeConflict) || errors.Is(err, context.DeadlineExceeded) {
		return exitConflict
	}
	return exitError
}

func (c *cli) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.server, "server", c.server, "server URL")
	fs.StringVar(&c.output, "o", c.output, "output format: table or json")
	fs.BoolVar(&c.verbose, "v", c.verbose, "verbose")
	return fs
}

// parse parses flags and positional arguments in any order.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usagef("%v", err)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func (c *cli) client() *client.Client {
	if c.c == nil {
		c.c = client.New(c.server)
	}
	return c.c
}

func (c *cli) dispatch(ctx context.Context, cmd string, args []string) error {
	switch cmd {
	case "status":
		return c.cmdStatus(ctx, args)
	case "pools":
		return c.cmdPools(ctx, args)
	case "hosts":
		return c.cmdHosts(ctx, args)
	case "whoami":
		return c.cmdWhoami(ctx, args)
	case "rescan":
		return c.cmdRescan(ctx, args)
	case "devices":
		return c.cmdDevices(ctx, args)
	case "create":
		return c.cmdCreate(ctx, args)
	case "delete":
		return c.cmdDelete(ctx, args)
	case "attach":
		return c.cmdAttach(ctx, args)
	case "detach":
		return c.cmdDetach(ctx, args)
	case "attachments":
		return c.cmdAttachments(ctx, args)
	case "allocate":
		return c.cmdAllocate(ctx, args)
	case "release":
		return c.cmdRelease(ctx, args)
	case "events":
		return c.cmdEvents(ctx, args)
	case "guest":
		return c.cmdGuest(ctx, args)
	case "help", "-h", "--help":
		fmt.Fprint(c.stdout, usage)
		return nil
	}
	return usagef("unknown command %q", cmd)
}

func (c *cli) json() bool { return c.output == "json" }

func (c *cli) printJSON(v any) error {
	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (c *cli) table() *tabwriter.Writer {
	return tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (c *cli) cmdStatus(ctx context.Context, args []string) error {
	fs := c.flagSet("status")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return firstErr(err, usagef("status takes no arguments"))
	}
	st, err := c.client().Status(ctx)
	if err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(st)
	}
	w := c.table()
	fmt.Fprintf(w, "server:\t%s\n", c.client().BaseURL)
	fmt.Fprintf(w, "version:\t%s\n", st.Version)
	fmt.Fprintf(w, "uptime:\t%s\n", st.Uptime)
	fmt.Fprintf(w, "hosts:\t%d\n", st.Hosts)
	fmt.Fprintf(w, "devices:\t%d\n", st.Devices)
	fmt.Fprintf(w, "attachments:\t%d\n", st.Attachments)
	fmt.Fprintf(w, "discovery:\t%v\n", st.Qemu.Discovery)
	fmt.Fprintf(w, "state file:\t%s\n", dash(st.StateFile))
	for h, v := range st.Qemu.Versions {
		fmt.Fprintf(w, "qemu %s:\t%s\n", h, v)
	}
	return w.Flush()
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func (c *cli) cmdPools(ctx context.Context, args []string) error {
	fs := c.flagSet("pools")
	pos, err := parse(fs, args)
	if err != nil || len(pos) > 1 {
		return firstErr(err, usagef("pools [NAME]"))
	}
	var ps []api.Pool
	if len(pos) == 1 {
		p, err := c.client().Pool(ctx, pos[0])
		if err != nil {
			return err
		}
		ps = []api.Pool{*p}
	} else if ps, err = c.client().Pools(ctx); err != nil {
		return err
	}
	if c.json() {
		if len(pos) == 1 {
			return c.printJSON(ps[0])
		}
		return c.printJSON(ps)
	}
	w := c.table()
	fmt.Fprintln(w, "NAME\tDIR\tCAPACITY\tUSED\tFREE\tSHARABLE")
	for _, p := range ps {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%v\n", p.Name, p.Dir, api.FormatSize(p.Capacity), api.FormatSize(p.Used), api.FormatSize(p.Free), p.Sharable)
	}
	return w.Flush()
}

func freeSlots(h api.Host) int {
	n := 0
	for _, s := range h.Slots {
		if s.Device == "" && s.Attachment == "" && s.ReservedFor == "" {
			n++
		}
	}
	return n
}

func (c *cli) cmdHosts(ctx context.Context, args []string) error {
	fs := c.flagSet("hosts")
	pos, err := parse(fs, args)
	if err != nil || len(pos) > 1 {
		return firstErr(err, usagef("hosts [NAME]"))
	}
	if len(pos) == 1 {
		h, err := c.client().Host(ctx, pos[0])
		if err != nil {
			return err
		}
		return c.printHost(*h)
	}
	hs, err := c.client().Hosts(ctx)
	if err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(hs)
	}
	w := c.table()
	fmt.Fprintln(w, "NAME\tSTATE\tCONTROL\tPID\tQEMU\tUUID\tFREE-SLOTS\tATTACHMENTS\tLOCAL-DEVICES")
	for _, h := range hs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%d/%d\t%d\t%d\n", h.Name, h.State, dash(h.Control), h.PID,
			dash(h.QemuVersion), dash(h.UUID), freeSlots(h), len(h.Slots), len(h.Attachments), len(h.LocalDevices))
	}
	return w.Flush()
}

func (c *cli) printHost(h api.Host) error {
	if c.json() {
		return c.printJSON(h)
	}
	w := c.table()
	fmt.Fprintf(w, "name:\t%s\n", h.Name)
	fmt.Fprintf(w, "uuid:\t%s\n", dash(h.UUID))
	fmt.Fprintf(w, "state:\t%s\n", h.State)
	fmt.Fprintf(w, "pid:\t%d\n", h.PID)
	ctl := h.Control
	switch h.Control {
	case "qmp":
		ctl += " " + h.QMP
	case "hmp":
		ctl += " " + h.HMP
	}
	fmt.Fprintf(w, "control:\t%s\n", dash(ctl))
	fmt.Fprintf(w, "qemu:\t%s\n", dash(h.QemuVersion))
	fmt.Fprintf(w, "source:\t%s\n", h.Source)
	if h.Error != "" {
		fmt.Fprintf(w, "error:\t%s\n", h.Error)
	}
	fmt.Fprintf(w, "local devices:\t%s\n", dash(strings.Join(h.LocalDevices, " ")))
	w.Flush()
	fmt.Fprintln(c.stdout, "\nhost bridges:")
	w = c.table()
	fmt.Fprintln(w, "ID\tNUMA\tFMW-SIZE\tATTACHED")
	for _, hb := range h.HostBridges {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", hb.ID, hb.NumaNode, api.FormatSize(hb.FMWSize), api.FormatSize(hb.AttachedBytes))
	}
	w.Flush()
	fmt.Fprintln(c.stdout, "\nslots:")
	w = c.table()
	fmt.Fprintln(w, "BUS\tKIND\tHOST-BRIDGE\tNUMA\tDEVICE\tATTACHMENT\tRESERVED-FOR")
	for _, s := range h.Slots {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n", s.Bus, s.Kind, s.HostBridge, s.NumaNode, dash(s.Device), dash(s.Attachment), dash(s.ReservedFor))
	}
	w.Flush()
	if len(h.Attachments) > 0 {
		fmt.Fprintln(c.stdout, "\nattachments:")
		return c.printAttachments(h.Attachments)
	}
	return nil
}

func (c *cli) cmdWhoami(ctx context.Context, args []string) error {
	fs := c.flagSet("whoami")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return firstErr(err, usagef("whoami takes no arguments"))
	}
	hostname, uuid := client.SelfIdentity()
	h, err := c.client().Resolve(ctx, hostname, uuid)
	if err != nil {
		return fmt.Errorf("resolve hostname %q uuid %q: %w", hostname, uuid, err)
	}
	return c.printHost(*h)
}

func (c *cli) cmdRescan(ctx context.Context, args []string) error {
	fs := c.flagSet("rescan")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return firstErr(err, usagef("rescan takes no arguments"))
	}
	if _, err := c.client().Rescan(ctx); err != nil {
		return err
	}
	return c.cmdHosts(ctx, nil)
}

func (c *cli) cmdDevices(ctx context.Context, args []string) error {
	fs := c.flagSet("devices")
	shared := fs.Bool("shared", false, "only shared devices")
	free := fs.Bool("free", false, "only free devices")
	host := fs.String("host", "", "only devices attached to or local to the host")
	pos, err := parse(fs, args)
	if err != nil || len(pos) > 1 {
		return firstErr(err, usagef("devices [NAME] [--shared] [--free] [--host H]"))
	}
	if len(pos) == 1 {
		d, err := c.client().Device(ctx, pos[0])
		if err != nil {
			return err
		}
		return c.printDevice(*d)
	}
	o := client.DeviceListOptions{Host: *host}
	if *shared {
		o.Shared = shared
	}
	if *free {
		o.State = api.DeviceFree
	}
	ds, err := c.client().Devices(ctx, o)
	if err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(ds)
	}
	return c.printDevices(ds)
}

func attachedTo(d api.Device) string {
	var hs []string
	for _, a := range d.Attachments {
		s := a.Host
		if a.State != api.AttachmentAttached {
			s += "(" + a.State + ")"
		}
		hs = append(hs, s)
	}
	return strings.Join(hs, ",")
}

func (c *cli) printDevices(ds []api.Device) error {
	w := c.table()
	fmt.Fprintln(w, "NAME\tSERIAL\tSIZE\tSHARED\tSCOPE\tSTATE\tATTACHED-TO\tOWNER")
	for _, d := range ds {
		owner := ""
		if d.Allocation != nil {
			owner = d.Allocation.Owner
		}
		scope := d.Scope
		if d.Scope == api.ScopeLocal {
			lh := d.LocalHost
			if len(d.LocalHosts) > 1 {
				lh = strings.Join(d.LocalHosts, ",")
			}
			scope += ":" + lh
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\t%s\t%s\t%s\n", d.Name, d.Serial, api.FormatSize(d.Size), d.Shared, scope, d.State, dash(attachedTo(d)), dash(owner))
	}
	return w.Flush()
}

func (c *cli) printDevice(d api.Device) error {
	if c.json() {
		return c.printJSON(d)
	}
	w := c.table()
	fmt.Fprintf(w, "name:\t%s\n", d.Name)
	fmt.Fprintf(w, "serial:\t%s\n", d.Serial)
	fmt.Fprintf(w, "size:\t%s\n", api.FormatSize(d.Size))
	fmt.Fprintf(w, "shared:\t%v\n", d.Shared)
	fmt.Fprintf(w, "backend:\t%s %s\n", d.Backend, d.Path)
	fmt.Fprintf(w, "pool:\t%s\n", dash(d.Pool))
	scope := d.Scope
	if d.Scope == api.ScopeLocal {
		scope += " (" + strings.Join(append([]string{d.LocalHost}, d.LocalHosts...)[min(1, len(d.LocalHosts)):], ",") + ")"
	}
	fmt.Fprintf(w, "scope:\t%s\n", scope)
	fmt.Fprintf(w, "state:\t%s\n", d.State)
	if d.Allocation != nil {
		fmt.Fprintf(w, "owner:\t%s (since %s) %s\n", d.Allocation.Owner, d.Allocation.Since.Format(time.RFC3339), d.Allocation.Note)
	}
	for k, v := range d.Labels {
		fmt.Fprintf(w, "label:\t%s=%s\n", k, v)
	}
	w.Flush()
	if len(d.Attachments) > 0 {
		fmt.Fprintln(c.stdout, "\nattachments:")
		return c.printAttachments(d.Attachments)
	}
	return nil
}

func (c *cli) printAttachments(as []api.Attachment) error {
	w := c.table()
	fmt.Fprintln(w, "ID\tSLOT\tNUMA\tQEMU-DEVICE\tQEMU-OBJECT\tSERIAL\tSTATE\tERROR")
	for _, a := range as {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Slot.Bus, a.Slot.NumaNode, a.QemuDeviceID, a.QemuObjectID, a.Serial, a.State, dash(a.Error))
	}
	return w.Flush()
}

func (c *cli) printAttachment(a *api.Attachment) error {
	if c.json() {
		return c.printJSON(a)
	}
	return c.printAttachments([]api.Attachment{*a})
}

type labelFlags map[string]string

func (l labelFlags) String() string { return "" }
func (l labelFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("label must be KEY=VALUE")
	}
	l[k] = val
	return nil
}

func (c *cli) cmdCreate(ctx context.Context, args []string) error {
	fs := c.flagSet("create")
	size := fs.String("size", "", "device size, e.g. 256M")
	shared := fs.Bool("shared", false, "shared device")
	name := fs.String("name", "", "device name (default: generated)")
	poolName := fs.String("pool", "", "pool name")
	serial := fs.String("serial", "", "serial number (default: allocated)")
	labels := labelFlags{}
	fs.Var(labels, "label", "KEY=VALUE label (repeatable)")
	pos, err := parse(fs, args)
	if err != nil || len(pos) > 0 || *size == "" {
		return firstErr(err, usagef("create --size SIZE [--shared] [--name N] [--pool P] [--serial S]"))
	}
	sz, err := api.ParseSize(*size)
	if err != nil {
		return usagef("%v", err)
	}
	req := api.DeviceCreate{Name: *name, Size: api.Size(sz), Shared: *shared, Pool: *poolName, Serial: *serial}
	if len(labels) > 0 {
		req.Labels = labels
	}
	d, err := c.client().CreateDevice(ctx, req)
	if err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(d)
	}
	return c.printDevices([]api.Device{*d})
}

func (c *cli) cmdDelete(ctx context.Context, args []string) error {
	fs := c.flagSet("delete")
	force := fs.Bool("force", false, "detach first")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		return firstErr(err, usagef("delete NAME [--force]"))
	}
	if err := c.client().DeleteDevice(ctx, pos[0], *force); err != nil {
		return err
	}
	if !c.json() {
		fmt.Fprintf(c.stdout, "deleted %s\n", pos[0])
	}
	return nil
}

// hostArg returns the host of --host or --self.
func (c *cli) hostArg(ctx context.Context, host string, self bool) (string, error) {
	if self && host != "" {
		return "", usagef("give either --self or --host")
	}
	if host != "" {
		return host, nil
	}
	if !self {
		return "", usagef("--self or --host HOST is required")
	}
	h, err := c.client().Self(ctx)
	if err != nil {
		hostname, uuid := client.SelfIdentity()
		return "", fmt.Errorf("resolve this host (hostname %q uuid %q): %w", hostname, uuid, err)
	}
	return h.Name, nil
}

func (c *cli) cmdAttach(ctx context.Context, args []string) error {
	fs := c.flagSet("attach")
	self := fs.Bool("self", false, "attach to this VM")
	host := fs.String("host", "", "target host (name or uuid)")
	slot := fs.String("slot", "", "qemu bus of the slot")
	numa := fs.Int("numa", -1, "prefer a slot on this NUMA node")
	owner := fs.String("owner", "", "allocation owner")
	noWait := fs.Bool("no-wait", false, "do not wait for qemu")
	timeout := fs.String("timeout", "", "qemu timeout (default 30s)")
	force := fs.Bool("force", false, "ignore the allocation owner")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		return firstErr(err, usagef("attach DEVICE (--self | --host HOST) [--slot BUS] [--numa N] [--owner O] [--no-wait]"))
	}
	h, err := c.hostArg(ctx, *host, *self)
	if err != nil {
		return err
	}
	req := api.AttachRequest{Host: h, Slot: *slot, Owner: *owner, Timeout: *timeout, Force: *force}
	if *numa >= 0 {
		req.NumaNode = numa
	}
	if *noWait {
		f := false
		req.Wait = &f
	}
	a, _, err := c.client().Attach(ctx, pos[0], req)
	if err != nil {
		return err
	}
	return c.printAttachment(a)
}

func (c *cli) cmdDetach(ctx context.Context, args []string) error {
	fs := c.flagSet("detach")
	self := fs.Bool("self", false, "detach from this VM")
	host := fs.String("host", "", "host (name or uuid)")
	timeout := fs.Duration("timeout", 0, "how long to wait for the guest to release the device (default: server's detachTimeout)")
	noWait := fs.Bool("no-wait", false, "do not wait for qemu to delete the device")
	owner := fs.String("owner", "", "allocation owner")
	force := fs.Bool("force", false, "ignore the allocation owner; forget a failed attachment")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		return firstErr(err, usagef("detach DEVICE (--self | --host HOST) [--timeout 30s] [--no-wait]"))
	}
	h, err := c.hostArg(ctx, *host, *self)
	if err != nil {
		return err
	}
	a, _, err := c.client().Detach(ctx, pos[0], h, client.DetachOptions{NoWait: *noWait, Timeout: *timeout, Owner: *owner, Force: *force})
	if err != nil {
		if a.ID != "" && !c.json() {
			c.printAttachments([]api.Attachment{*a})
		}
		return err
	}
	return c.printAttachment(a)
}

func (c *cli) cmdAttachments(ctx context.Context, args []string) error {
	fs := c.flagSet("attachments")
	self := fs.Bool("self", false, "attachments of this VM")
	host := fs.String("host", "", "host (name or uuid)")
	device := fs.String("device", "", "device")
	pos, err := parse(fs, args)
	if err != nil || len(pos) > 0 {
		return firstErr(err, usagef("attachments [--self | --host H] [--device D]"))
	}
	h := *host
	if *self {
		if h, err = c.hostArg(ctx, *host, true); err != nil {
			return err
		}
	}
	as, err := c.client().Attachments(ctx, h, *device)
	if err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(as)
	}
	return c.printAttachments(as)
}

func (c *cli) cmdAllocate(ctx context.Context, args []string) error {
	fs := c.flagSet("allocate")
	owner := fs.String("owner", "", "owner")
	note := fs.String("note", "", "note")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 || *owner == "" {
		return firstErr(err, usagef("allocate DEVICE --owner O [--note TEXT]"))
	}
	a, err := c.client().Allocate(ctx, pos[0], *owner, *note)
	if err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(a)
	}
	fmt.Fprintf(c.stdout, "%s allocated to %s\n", pos[0], a.Owner)
	return nil
}

func (c *cli) cmdRelease(ctx context.Context, args []string) error {
	fs := c.flagSet("release")
	owner := fs.String("owner", "", "owner (checked if given)")
	force := fs.Bool("force", false, "release even if owned by someone else")
	pos, err := parse(fs, args)
	if err != nil || len(pos) != 1 {
		return firstErr(err, usagef("release DEVICE [--owner O] [--force]"))
	}
	if err := c.client().Release(ctx, pos[0], *owner, *force); err != nil {
		return err
	}
	if !c.json() {
		fmt.Fprintf(c.stdout, "%s released\n", pos[0])
	}
	return nil
}

func (c *cli) cmdEvents(ctx context.Context, args []string) error {
	fs := c.flagSet("events")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return firstErr(err, usagef("events takes no arguments"))
	}
	err := c.client().Events(ctx, func(ev client.Event) error {
		b, _ := json.Marshal(ev)
		_, err := fmt.Fprintln(c.stdout, string(b))
		return err
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// deviceSerial returns the serial of a device name, or parses a serial.
func (c *cli) deviceSerial(ctx context.Context, dev string) (uint64, error) {
	if strings.HasPrefix(dev, "0x") || strings.HasPrefix(dev, "0X") {
		return api.ParseSerial(dev)
	}
	d, err := c.client().Device(ctx, dev)
	if err != nil {
		return 0, err
	}
	return api.ParseSerial(d.Serial)
}

func (c *cli) newGuest() *memctl.Manager {
	g := memctl.New()
	if c.verbose {
		g.Logf = func(format string, args ...any) { fmt.Fprintf(c.stderr, format+"\n", args...) }
	}
	return g
}

func (c *cli) guestMemdev(ctx context.Context, g *memctl.Manager, dev string) (string, error) {
	sn, err := c.deviceSerial(ctx, dev)
	if err != nil {
		return "", err
	}
	return g.FindMemdev(sn)
}

func (c *cli) printRegionInfo(ri *memctl.RegionInfo) error {
	if c.json() {
		return c.printJSON(ri)
	}
	w := c.table()
	fmt.Fprintln(w, "MEMDEV\tREGION\tDAX\tDRIVER\tMODE\tNODE\tDEVICE\tBLOCKS")
	blocks := ""
	if n := len(ri.Blocks); n > 0 {
		blocks = fmt.Sprintf("memory%d..memory%d", ri.Blocks[0], ri.Blocks[n-1])
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", ri.Memdev, ri.Region, dash(ri.Dax), dash(ri.Driver), dash(ri.Mode), ri.Node, dash(ri.Device), dash(blocks))
	return w.Flush()
}

func (c *cli) cmdGuest(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usagef("guest wait|memdev|region|online|info|release ...")
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "-h", "-help", "--help", "help":
		fmt.Fprint(c.stdout, usage)
		return nil
	}
	g := c.newGuest()
	switch sub {
	case "wait":
		fs := c.flagSet("guest wait")
		timeout := fs.Duration("timeout", 30*time.Second, "timeout")
		pos, err := parse(fs, args)
		if err != nil || len(pos) != 1 {
			return firstErr(err, usagef("guest wait DEVICE [--timeout 30s]"))
		}
		sn, err := c.deviceSerial(ctx, pos[0])
		if err != nil {
			return err
		}
		wctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		m, err := g.WaitMemdev(wctx, sn)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, m)
		return nil
	case "memdev":
		fs := c.flagSet("guest memdev")
		pos, err := parse(fs, args)
		if err != nil || len(pos) != 1 {
			return firstErr(err, usagef("guest memdev DEVICE"))
		}
		m, err := c.guestMemdev(ctx, g, pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, m)
		return nil
	case "region":
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			fmt.Fprint(c.stdout, usage)
			return nil
		}
		if len(args) == 0 || args[0] != "create" {
			return usagef("guest region create DEVICE --mode devdax|ram [--decoder decoderX.Y]")
		}
		fs := c.flagSet("guest region create")
		mode := fs.String("mode", "", "devdax or ram")
		decoder := fs.String("decoder", "", "root decoder (default: the one of the device's host bridge)")
		timeout := fs.Duration("timeout", 30*time.Second, "timeout")
		pos, err := parse(fs, args[1:])
		if err != nil || len(pos) != 1 || (*mode != memctl.ModeDevDax && *mode != memctl.ModeRAM) {
			return firstErr(err, usagef("guest region create DEVICE --mode devdax|ram [--decoder decoderX.Y]"))
		}
		m, err := c.guestMemdev(ctx, g, pos[0])
		if err != nil {
			return err
		}
		rctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		ri, err := g.CreateRegion(rctx, m, *mode, *decoder)
		if err != nil {
			return err
		}
		return c.printRegionInfo(ri)
	case "online":
		fs := c.flagSet("guest online")
		movable := fs.Bool("movable", false, "online_movable")
		pos, err := parse(fs, args)
		if err != nil || len(pos) != 1 {
			return firstErr(err, usagef("guest online DEVICE [--movable]"))
		}
		m, err := c.guestMemdev(ctx, g, pos[0])
		if err != nil {
			return err
		}
		ri, err := g.Online(m, *movable)
		if err != nil {
			return err
		}
		return c.printRegionInfo(ri)
	case "info":
		fs := c.flagSet("guest info")
		pos, err := parse(fs, args)
		if err != nil || len(pos) != 1 {
			return firstErr(err, usagef("guest info DEVICE"))
		}
		m, err := c.guestMemdev(ctx, g, pos[0])
		if err != nil {
			return err
		}
		ri, err := g.Info(m)
		if err != nil {
			ri = &memctl.RegionInfo{Memdev: m, Node: -1}
		}
		return c.printRegionInfo(ri)
	case "release":
		fs := c.flagSet("guest release")
		pos, err := parse(fs, args)
		if err != nil || len(pos) != 1 {
			return firstErr(err, usagef("guest release DEVICE"))
		}
		m, err := c.guestMemdev(ctx, g, pos[0])
		if errors.Is(err, memctl.ErrNotFound) {
			if !c.json() {
				fmt.Fprintf(c.stdout, "%s: not present, nothing to release\n", pos[0])
			}
			return nil
		}
		if err != nil {
			return err
		}
		if err := g.Release(ctx, m); err != nil {
			return err
		}
		if !c.json() {
			fmt.Fprintf(c.stdout, "%s: released\n", m)
		}
		return nil
	}
	return usagef("unknown guest command %q", sub)
}
