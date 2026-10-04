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

package qemu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultQMPIdleTimeout is how long an idle QMP connection is kept open by
// default. The server uses a persistent connection (IdleTimeout 0) on a
// socket reserved for it (qmp.sock), so that no DEVICE_DELETED event is
// missed.
const DefaultQMPIdleTimeout = 200 * time.Millisecond

// QMP is a Monitor that talks QMP over a unix socket. One connection
// demultiplexes responses (by "id") and events. The connection is opened on
// demand. If IdleTimeout > 0, it is closed when it has been idle that long,
// so that other clients of the same socket (a qemu QMP socket serves one
// client at a time) are not blocked for long; if IdleTimeout <= 0 it is kept
// open and reopened after errors.
type QMP struct {
	Path         string
	IdleTimeout  time.Duration
	PollInterval time.Duration
	Log          Logf

	mu        sync.Mutex
	closed    bool // Close is final: no redial afterwards
	conn      *qmpConn
	users     int
	idleTimer *time.Timer
	deleted   map[string]time.Time // DEVICE_DELETED seen, by device id
	unplugErr map[string]string    // DEVICE_UNPLUG_GUEST_ERROR seen
	waiters   map[string][]chan struct{}
}

// NewQMP returns a QMP monitor for the socket path.
func NewQMP(path string, log Logf) *QMP {
	return &QMP{
		Path:         path,
		IdleTimeout:  DefaultQMPIdleTimeout,
		PollInterval: 2 * time.Second,
		Log:          log,
		deleted:      map[string]time.Time{},
		unplugErr:    map[string]string{},
		waiters:      map[string][]chan struct{}{},
	}
}

// Protocol implements Monitor.
func (q *QMP) Protocol() string { return ProtoQMP }

type qmpMessage struct {
	QMP    json.RawMessage `json:"QMP,omitempty"`
	Return json.RawMessage `json:"return,omitempty"`
	Error  *struct {
		Class string `json:"class"`
		Desc  string `json:"desc"`
	} `json:"error,omitempty"`
	ID    json.RawMessage `json:"id,omitempty"`
	Event string          `json:"event,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

type qmpConn struct {
	c        net.Conn
	wmu      sync.Mutex
	mu       sync.Mutex
	pending  map[string]chan *qmpMessage
	nextID   uint64
	greeting chan *qmpMessage
	done     chan struct{}
	err      error
}

func (c *qmpConn) readLoop(onEvent func(*qmpMessage)) {
	dec := json.NewDecoder(c.c)
	gotGreeting := false
	for {
		m := &qmpMessage{}
		if err := dec.Decode(m); err != nil {
			c.mu.Lock()
			c.err = err
			c.mu.Unlock()
			close(c.done)
			return
		}
		switch {
		case m.QMP != nil && !gotGreeting:
			gotGreeting = true
			c.greeting <- m
		case m.Event != "":
			onEvent(m)
		case m.ID != nil:
			var id string
			if err := json.Unmarshal(m.ID, &id); err != nil {
				id = string(m.ID)
			}
			c.mu.Lock()
			ch := c.pending[id]
			delete(c.pending, id)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}
}

func (c *qmpConn) execute(ctx context.Context, cmd string, args any) (json.RawMessage, error) {
	c.mu.Lock()
	c.nextID++
	id := "fcp-" + strconv.FormatUint(c.nextID, 10)
	ch := make(chan *qmpMessage, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	req := map[string]any{"execute": cmd, "id": id}
	if args != nil {
		req["arguments"] = args
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	c.wmu.Lock()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.c.SetWriteDeadline(dl)
	}
	_, err = c.c.Write(append(b, '\n'))
	c.wmu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("qmp write: %w", err)
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, &Error{Class: m.Error.Class, Desc: m.Error.Desc, Command: cmd}
		}
		return m.Return, nil
	case <-c.done:
		return nil, fmt.Errorf("qmp connection closed: %v", c.err)
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (q *QMP) dial(ctx context.Context) (*qmpConn, error) {
	nc, err := dialUnix(ctx, q.Path)
	if err != nil {
		return nil, fmt.Errorf("qmp connect %s: %w", q.Path, err)
	}
	c := &qmpConn{
		c:        nc,
		pending:  map[string]chan *qmpMessage{},
		greeting: make(chan *qmpMessage, 1),
		done:     make(chan struct{}),
	}
	go c.readLoop(q.onEvent)
	select {
	case <-c.greeting:
	case <-c.done:
		nc.Close()
		return nil, fmt.Errorf("qmp %s: no greeting: %v", q.Path, c.err)
	case <-ctx.Done():
		nc.Close()
		return nil, fmt.Errorf("qmp %s: no greeting: %w (is another client connected?)", q.Path, ctx.Err())
	}
	if _, err := c.execute(ctx, "qmp_capabilities", nil); err != nil {
		nc.Close()
		return nil, fmt.Errorf("qmp %s: capabilities negotiation: %w", q.Path, err)
	}
	return c, nil
}

func (q *QMP) onEvent(m *qmpMessage) {
	var data struct {
		Device string `json:"device"`
		Path   string `json:"path"`
	}
	_ = json.Unmarshal(m.Data, &data)
	q.Log.printf("qmp %s: event %s %s", q.Path, m.Event, string(m.Data))
	id := data.Device
	if id == "" {
		id = strings.TrimPrefix(data.Path, "/machine/peripheral/")
	}
	switch m.Event {
	case "DEVICE_DELETED":
		q.mu.Lock()
		q.deleted[id] = time.Now()
		ws := q.waiters[id]
		delete(q.waiters, id)
		q.mu.Unlock()
		for _, w := range ws {
			close(w)
		}
	case "DEVICE_UNPLUG_GUEST_ERROR":
		q.mu.Lock()
		q.unplugErr[id] = string(m.Data)
		q.mu.Unlock()
	}
}

// acquire returns a connected qmpConn and a release function.
func (q *QMP) acquire(ctx context.Context) (*qmpConn, func(), error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil, nil, ErrClosed
	}
	if q.idleTimer != nil {
		q.idleTimer.Stop()
		q.idleTimer = nil
	}
	if q.conn != nil {
		select {
		case <-q.conn.done:
			q.conn.c.Close()
			q.conn = nil
		default:
		}
	}
	if q.conn == nil {
		c, err := q.dial(ctx)
		if err != nil {
			if q.users == 0 {
				q.armIdleLocked()
			}
			return nil, nil, err
		}
		q.conn = c
	}
	q.users++
	c := q.conn
	var once sync.Once
	return c, func() {
		once.Do(func() {
			q.mu.Lock()
			defer q.mu.Unlock()
			q.users--
			if q.users == 0 {
				q.armIdleLocked()
			}
		})
	}, nil
}

func (q *QMP) armIdleLocked() {
	if q.conn == nil || q.IdleTimeout <= 0 {
		return
	}
	c := q.conn
	q.idleTimer = time.AfterFunc(q.IdleTimeout, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.users == 0 && q.conn == c {
			c.c.Close()
			q.conn = nil
		}
	})
}

// Execute runs a QMP command and unmarshals its return value into result
// (unless result is nil).
func (q *QMP) Execute(ctx context.Context, cmd string, args any, result any) error {
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	c, release, err := q.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	ret, err := c.execute(ctx, cmd, args)
	if cmd != "human-monitor-command" && !strings.HasPrefix(cmd, "qom-") && !strings.HasPrefix(cmd, "query-") {
		a, _ := json.Marshal(args)
		if err != nil {
			q.Log.printf("qmp %s: %s %s: error: %v", q.Path, cmd, a, err)
		} else {
			q.Log.printf("qmp %s: %s %s: %s", q.Path, cmd, a, string(ret))
		}
	}
	if err != nil {
		return err
	}
	if result != nil && len(ret) > 0 {
		return json.Unmarshal(ret, result)
	}
	return nil
}

// HumanMonitorCommand runs an HMP command over QMP.
func (q *QMP) HumanMonitorCommand(ctx context.Context, line string) (string, error) {
	var out string
	if err := q.Execute(ctx, "human-monitor-command", map[string]any{"command-line": line}, &out); err != nil {
		return "", err
	}
	out = strings.ReplaceAll(out, "\r", "")
	for _, l := range strings.Split(out, "\n") {
		if desc, ok := strings.CutPrefix(l, "Error: "); ok {
			return out, &Error{Desc: desc, Command: line}
		}
	}
	return out, nil
}

// Version implements Monitor.
func (q *QMP) Version(ctx context.Context) (string, error) {
	var v struct {
		Qemu struct {
			Major, Minor, Micro int
		} `json:"qemu"`
		Package string `json:"package"`
	}
	if err := q.Execute(ctx, "query-version", nil, &v); err != nil {
		return "", err
	}
	return NormalizeVersion(fmt.Sprintf("%d.%d.%d %s", v.Qemu.Major, v.Qemu.Minor, v.Qemu.Micro, v.Package)), nil
}

// QMPObjectAddArgs returns the arguments of QMP object-add for the backend.
func QMPObjectAddArgs(b MemoryBackend) map[string]any {
	args := map[string]any{"qom-type": b.QomType, "id": b.ID, "size": b.Size}
	if b.Share {
		args["share"] = true
	}
	if b.QomType == MemoryBackendFile {
		args["mem-path"] = b.MemPath
	}
	return args
}

// QMPDeviceAddArgs returns the arguments of QMP device_add for the device.
// The sn property is a uint64 qdev property: QMP wants a JSON number.
func QMPDeviceAddArgs(d CXLType3) map[string]any {
	return map[string]any{
		"driver":          "cxl-type3",
		"bus":             d.Bus,
		"volatile-memdev": d.VolatileMemdev,
		"id":              d.ID,
		"sn":              d.Serial,
	}
}

// ObjectAdd implements Monitor.
func (q *QMP) ObjectAdd(ctx context.Context, b MemoryBackend) error {
	return q.Execute(ctx, "object-add", QMPObjectAddArgs(b), nil)
}

// ObjectDel implements Monitor.
func (q *QMP) ObjectDel(ctx context.Context, id string) error {
	return q.Execute(ctx, "object-del", map[string]any{"id": id}, nil)
}

// DeviceAdd implements Monitor.
func (q *QMP) DeviceAdd(ctx context.Context, d CXLType3) error {
	q.mu.Lock()
	delete(q.deleted, d.ID)
	delete(q.unplugErr, d.ID)
	q.mu.Unlock()
	err := q.Execute(ctx, "device_add", QMPDeviceAddArgs(d), nil)
	var qe *Error
	if errors.As(err, &qe) && strings.Contains(qe.Desc, "'sn'") {
		// Fallback in case a qemu version wants the serial as a string.
		args := QMPDeviceAddArgs(d)
		args["sn"] = fmt.Sprintf("0x%x", d.Serial)
		err = q.Execute(ctx, "device_add", args, nil)
	}
	return err
}

// DeviceDel implements Monitor.
func (q *QMP) DeviceDel(ctx context.Context, id string) error {
	return q.Execute(ctx, "device_del", map[string]any{"id": id}, nil)
}

// QueryMemdevs implements Monitor.
func (q *QMP) QueryMemdevs(ctx context.Context) ([]Memdev, error) {
	var mds []Memdev
	if err := q.Execute(ctx, "query-memdev", nil, &mds); err != nil {
		return nil, err
	}
	return mds, nil
}

// QueryTree implements Monitor. It reads the CXL topology from QOM, and
// falls back to parsing "info qtree" over human-monitor-command.
func (q *QMP) QueryTree(ctx context.Context) (*Tree, error) {
	t, err := q.queryTreeQOM(ctx)
	if err == nil {
		return t, nil
	}
	q.Log.printf("qmp %s: QOM tree query failed, using info qtree: %v", q.Path, err)
	out, err := q.HumanMonitorCommand(ctx, "info qtree")
	if err != nil {
		return nil, err
	}
	return ParseQtree(out), nil
}

// QomGet implements Monitor.
func (q *QMP) QomGet(ctx context.Context, path, property string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := q.Execute(ctx, "qom-get", map[string]any{"path": path, "property": property}, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

type qomItem struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

var cxlDrivers = map[string]bool{"pxb-cxl": true, "cxl-rp": true, "cxl-upstream": true, "cxl-downstream": true, "cxl-type3": true}

// queryTreeQOM builds the Tree from qom-list /machine/peripheral and the
// parent_bus, sn, volatile-memdev and numa_node properties. The bus a port
// provides has the port's id, the bus of a pxb-cxl has the pxb-cxl's id.
func (q *QMP) queryTreeQOM(ctx context.Context) (*Tree, error) {
	driver := map[string]string{} // device path -> driver
	for _, dir := range []string{"/machine/peripheral", "/machine/peripheral-anon"} {
		var items []qomItem
		if err := q.Execute(ctx, "qom-list", map[string]any{"path": dir}, &items); err != nil {
			if dir == "/machine/peripheral" {
				return nil, err
			}
			continue
		}
		for _, it := range items {
			if drv, ok := strings.CutPrefix(it.Type, "child<"); ok && cxlDrivers[strings.TrimSuffix(drv, ">")] {
				driver[dir+"/"+it.Name] = strings.TrimSuffix(drv, ">")
			}
		}
	}
	getString := func(path, prop string) (string, error) {
		var s string
		err := q.Execute(ctx, "qom-get", map[string]any{"path": path, "property": prop}, &s)
		return s, err
	}
	id := func(path string) string {
		if strings.HasPrefix(path, "/machine/peripheral/") {
			return strings.TrimPrefix(path, "/machine/peripheral/")
		}
		return ""
	}
	parent := map[string]string{} // device id or path -> parent bus name
	paths := make([]string, 0, len(driver))
	for p := range driver {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	t := &Tree{}
	for _, p := range paths {
		drv := driver[p]
		if drv == "pxb-cxl" {
			hb := TreeHostBridge{ID: id(p), NumaNode: -1}
			var n int
			if err := q.Execute(ctx, "qom-get", map[string]any{"path": p, "property": "numa_node"}, &n); err == nil {
				hb.NumaNode = numaOrUnknown(n)
			}
			t.HostBridges = append(t.HostBridges, hb)
			continue
		}
		pb, err := getString(p, "parent_bus")
		if err != nil {
			return nil, err
		}
		parent[p] = pb[strings.LastIndex(pb, "/")+1:]
	}
	isHB := map[string]bool{}
	for _, hb := range t.HostBridges {
		isHB[hb.ID] = true
	}
	hostBridge := func(p string) string {
		bus := parent[p]
		for i := 0; i < 16 && bus != ""; i++ {
			if isHB[bus] {
				return bus
			}
			bus = parent["/machine/peripheral/"+bus]
		}
		return ""
	}
	for _, p := range paths {
		drv := driver[p]
		switch drv {
		case "cxl-downstream", "cxl-rp":
			port := Port{Bus: id(p), Kind: PortDownstream, HostBridge: hostBridge(p)}
			if drv == "cxl-rp" {
				port.Kind = PortRootPort
			}
			if port.Bus == "" || port.HostBridge == "" {
				continue
			}
			for _, c := range paths {
				if parent[c] == port.Bus && driver[c] != "pxb-cxl" {
					port.Children = append(port.Children, TreeDevice{Driver: driver[c], ID: id(c)})
				}
			}
			t.Ports = append(t.Ports, port)
		case "cxl-type3":
			d := Type3Device{ID: id(p), Bus: parent[p]}
			var sn uint64
			if err := q.Execute(ctx, "qom-get", map[string]any{"path": p, "property": "sn"}, &sn); err == nil {
				d.Serial, d.HasSerial = sn, true
			}
			if v, err := getString(p, "volatile-memdev"); err == nil {
				d.VolatileMemdev = strings.TrimPrefix(v, "/objects/")
			}
			if d.ID != "" {
				t.Type3 = append(t.Type3, d)
			}
		}
	}
	return t, nil
}

// DeviceExists returns true if /machine/peripheral/<id> exists.
func (q *QMP) DeviceExists(ctx context.Context, id string) (bool, error) {
	q.mu.Lock()
	_, deleted := q.deleted[id]
	q.mu.Unlock()
	if deleted {
		return false, nil
	}
	var typ string
	err := q.Execute(ctx, "qom-get", map[string]any{"path": "/machine/peripheral/" + id, "property": "type"}, &typ)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// BackendMapped implements Monitor.
func (q *QMP) BackendMapped(ctx context.Context, objID string) (bool, error) {
	out, err := q.HumanMonitorCommand(ctx, "info mtree")
	if err != nil {
		return false, err
	}
	return BackendMappedIn(out, objID), nil
}

// DeletedEventSeen returns true if DEVICE_DELETED of the device has been
// received since it was added.
func (q *QMP) DeletedEventSeen(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, ok := q.deleted[id]
	return ok
}

// UnplugError returns the data of a DEVICE_UNPLUG_GUEST_ERROR event seen
// for the device, "" if none.
func (q *QMP) UnplugError(id string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.unplugErr[id]
}

// WaitDeviceDeleted implements Monitor. It keeps the connection open and
// returns when DEVICE_DELETED for the device arrives, or when a periodic
// check finds the device gone.
func (q *QMP) WaitDeviceDeleted(ctx context.Context, id string) error {
	c, release, err := q.acquire(ctx)
	if errors.Is(err, ErrClosed) {
		return err
	}
	if err != nil {
		// cannot listen to events: fall back to polling
		return pollDeviceDeleted(ctx, id, q.PollInterval, q.DeviceExists)
	}
	defer release()
	_ = c
	ch := make(chan struct{})
	q.mu.Lock()
	q.waiters[id] = append(q.waiters[id], ch)
	q.mu.Unlock()
	defer func() {
		q.mu.Lock()
		ws := q.waiters[id]
		for i, w := range ws {
			if w == ch {
				q.waiters[id] = append(ws[:i], ws[i+1:]...)
				break
			}
		}
		if len(q.waiters[id]) == 0 {
			delete(q.waiters, id)
		}
		q.mu.Unlock()
	}()
	interval := q.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		if ok, err := q.DeviceExists(ctx, id); err == nil && !ok {
			return nil
		}
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

// Close implements Monitor. It is final: a closed monitor never connects
// again, so that a goroutine that still holds it cannot take the socket from
// the monitor that replaces it.
func (q *QMP) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	if q.idleTimer != nil {
		q.idleTimer.Stop()
		q.idleTimer = nil
	}
	if q.conn != nil {
		q.conn.c.Close()
		q.conn = nil
	}
	return nil
}
