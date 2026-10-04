#!/usr/bin/env python3
"""Minimal QMP / HMP client for prototyping (stdlib only).

Usage:
  qmp.py SOCK exec CMD [JSON_ARGS]          run a QMP command, print the reply
  qmp.py SOCK hmp 'HMP COMMAND LINE'         run an HMP command via QMP
                                             (human-monitor-command), print text
  qmp.py SOCK exec-wait CMD JSON_ARGS EVENT [TIMEOUT]
                                             run a command, then wait for EVENT
                                             (e.g. DEVICE_DELETED) on the same
                                             connection; print reply and event
  qmp.py SOCK events [TIMEOUT]              print events until TIMEOUT seconds
  qmp.py SOCK slots                         list cxl-downstream/cxl-rp slots and
                                             the cxl-type3 device on each

Every QMP connection must do the capabilities handshake; events are delivered
only to the connections that are open when they happen.
"""
import json
import socket
import sys
import time


class QMP:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.buf = b""
        self.events = []
        self.greeting = self._recv()
        self.cmd("qmp_capabilities")

    def _recv(self, timeout=None):
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            data = self.sock.recv(65536)
            if not data:
                raise EOFError("QMP socket closed")
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def cmd(self, name, args=None):
        req = {"execute": name}
        if args:
            req["arguments"] = args
        self.sock.sendall(json.dumps(req).encode() + b"\n")
        while True:
            msg = self._recv()
            if "event" in msg:
                self.events.append(msg)
                continue
            return msg

    def wait_event(self, name, timeout):
        deadline = time.time() + timeout
        for ev in self.events:
            if ev["event"] == name:
                self.events.remove(ev)
                return ev
        while True:
            left = deadline - time.time()
            if left <= 0:
                return None
            try:
                msg = self._recv(timeout=left)
            except socket.timeout:
                return None
            if msg.get("event") == name:
                return msg
            if "event" in msg:
                self.events.append(msg)

    def hmp(self, line):
        r = self.cmd("human-monitor-command", {"command-line": line})
        if "error" in r:
            raise RuntimeError(r["error"])
        return r["return"]


def slots(q):
    """Parse "info qtree -b" into (bus, kind, device id or None)."""
    out = []
    txt = q.hmp("info qtree -b")
    lines = txt.splitlines()
    # Bus lines look like:  bus: cxlsw_ds0_usrp0hb0  /  type PCIE
    # device lines:         dev: cxl-type3, id "cxl_shared0"
    # Collect, for every cxl-downstream/cxl-rp device, the bus it provides and
    # the devices directly on that bus.
    stack = []  # (indent, kind, id)
    port_bus = {}
    cur_port = None
    for ln in lines:
        ind = len(ln) - len(ln.lstrip())
        s = ln.strip()
        while stack and stack[-1][0] >= ind:
            stack.pop()
        if s.startswith("dev: "):
            kind = s[5:].split(",")[0]
            did = s.split('"')[1] if '"' in s else ""
            stack.append((ind, "dev", kind, did))
        elif s.startswith("bus: "):
            bus = s[5:].strip()
            parent = next((e for e in reversed(stack) if e[1] == "dev"), None)
            stack.append((ind, "bus", bus, parent))
            if parent and parent[2] in ("cxl-downstream", "cxl-rp"):
                port_bus[bus] = (parent[2], [])
        if s.startswith("dev: "):
            # direct parent bus
            pb = next((e for e in reversed(stack[:-1]) if e[1] == "bus"), None)
            if pb and pb[2] in port_bus:
                port_bus[pb[2]][1].append((stack[-1][2], stack[-1][3]))
    for bus, (kind, devs) in port_bus.items():
        out.append((bus, kind, devs))
    return out


def main():
    path, op = sys.argv[1], sys.argv[2]
    q = QMP(path)
    if op == "exec":
        args = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None
        print(json.dumps(q.cmd(sys.argv[3], args), indent=1))
    elif op == "hmp":
        print(q.hmp(sys.argv[3]), end="")
    elif op == "exec-wait":
        args = json.loads(sys.argv[4]) if sys.argv[4] else None
        ev, tmo = sys.argv[5], float(sys.argv[6]) if len(sys.argv) > 6 else 30
        t0 = time.time()
        print(json.dumps(q.cmd(sys.argv[3], args)))
        e = q.wait_event(ev, tmo)
        print(json.dumps(e) if e else "TIMEOUT waiting for %s after %.1fs" % (ev, time.time() - t0))
        print("elapsed %.2fs" % (time.time() - t0))
        if not e:
            sys.exit(2)
    elif op == "events":
        tmo = float(sys.argv[3]) if len(sys.argv) > 3 else 30
        deadline = time.time() + tmo
        while time.time() < deadline:
            try:
                print(json.dumps(q._recv(timeout=deadline - time.time())), flush=True)
            except socket.timeout:
                break
    elif op == "slots":
        for bus, kind, devs in slots(q):
            print(bus, kind, " ".join("%s:%s" % d for d in devs) or "-")
    else:
        sys.exit("unknown op %s" % op)


if __name__ == "__main__":
    main()
