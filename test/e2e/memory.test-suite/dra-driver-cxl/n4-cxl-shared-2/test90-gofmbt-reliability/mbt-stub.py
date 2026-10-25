#!/usr/bin/env python3
"""A stand-in for mbt-cxl, the generator of test90-gofmbt-reliability.

It speaks the protocol of plan-13 (04-contract.txt 5) with a fixed list of
steps instead of a model, and accepts every action. A settle is "ok" once
the cluster is quiet: no pod being deleted, every pod Running and
Ready or unschedulable (companions of leases may be Pending), what a crash or a
driver-kill killed restarted, no attachment in a transient state, every driver pod
Ready and ready by its log (A15) without panics, every VM observed with
no container missing (A11), the local memdev in every node's slice, the
controllers active (or down after a ctrl-kill). It exercises
the executor (code.var.sh, mbt.source.sh, mbt-observe.py) without the
model, and is a smoke test of the cluster: MBT_STUB=1 ./run_tests.sh ...

Usage:
  mbt-stub.py online [--stub-steps FILE | --replay FILE]
                     [--settle-timeout SECONDS] [--out DIR] [--FLAG VALUE...]
      The on-line generator: send the steps, answer done with ok and
      observe with wait or ok, or fail after the settle timeout (default
      180 s, also --settle-timeout=180s). Other flags of mbt-cxl are
      accepted and ignored. Writes DIR/mbt-steps.txt (DIR: --out, else
      $MBT_OUT, else .).
  mbt-stub.py generate [--stub-steps FILE]
      Print a code.gen.sh of the steps (mbt-step, and mbt-expect after
      every settle).
  mbt-stub.py check --step N --expect FILE --observed FILE
      Print ok (exit 0) or wait MESSAGE (exit 3) for the observed line
      (done N STATUS JSON: always ok; observe N JSON: quiet or not).

The steps: --replay FILE (an mbt-steps.txt), --stub-steps FILE, else
$MBT_STUB_STEPS (a file), else the built-in list below, one action per
line ("#" comments).
"""

import json
import os
import sys
import time

STEPS = """
create xnuma-a@vm1#0
create xdax-b@vm0#0
create sdax-c@vm0#0
create ldax@vm0#0
create lease@vm2#0
create plain@vm2#0
settle
write xdax-b@vm0#0
write sdax-c@vm0#0
write ldax@vm0#0
create sdax-c@vm2#0
create sro-c@vm1#0
create lnuma@vm2#0
create lsteer@vm2#0
settle
read sdax-c@vm2#0
read sro-c@vm1#0
# a read-only claim: the write fails
write sro-c@vm1#0
read ldax@vm0#0
lease-get lease@vm2#0 numa
settle
lease-put lease@vm2#0
settle
crash ldax@vm0#0
crash xnuma-a@vm1#0
settle
read ldax@vm0#0
driver-kill vm0
settle
driver-restart vm1
settle
ctrl-kill b
settle
ctrl-start b
settle
ctrl-restart c
settle
server-restart a
settle
kubelet-restart vm1
settle
containerd-restart vm0
settle
driver-restart vm0
settle
lease-get lease@vm2#0 dax
create sexcl-a@vm2#0
create lnuma@vm0#0
create xdax-c@any#0
settle
read xdax-b@vm0#0
delete xnuma-a@vm1#0
delete xdax-b@vm0#0
delete sdax-c@vm0#0
delete ldax@vm0#0
delete lease@vm2#0
delete plain@vm2#0
delete sdax-c@vm2#0
delete sro-c@vm1#0
delete lnuma@vm2#0
delete lsteer@vm2#0
delete sexcl-a@vm2#0
delete lnuma@vm0#0
delete xdax-c@any#0
settle
"""

TRANSIENT_OK = ("attached",)


def log(*args):
    print("mbt-stub:", *args, file=sys.stderr, flush=True)


def options(argv):
    """--flag value and --flag=value pairs -> dict; bare --flag -> True."""
    opts, i = {}, 0
    while i < len(argv):
        a = argv[i]
        if not a.startswith("--"):
            sys.exit("mbt-stub: unexpected argument %r" % a)
        key, sep, val = a[2:].partition("=")
        if not sep:
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                val = argv[i + 1]
                i += 1
            else:
                val = True
        opts[key] = val
        i += 1
    return opts


def seconds(text, default):
    if text in (None, True, ""):
        return default
    text = str(text)
    for suffix, mult in (("ms", 0.001), ("s", 1), ("m", 60), ("h", 3600)):
        if text.endswith(suffix) and text[:-len(suffix)].replace(".", "", 1).isdigit():
            return float(text[:-len(suffix)]) * mult
    return float(text)


def steps(opts):
    path = opts.get("replay") or opts.get("stub-steps") or os.environ.get("MBT_STUB_STEPS")
    text = open(path).read() if path else STEPS
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


def unquiet(obs, controllers=None, restarts=None):
    """Why the observation obs is not quiet, [] if it is. restarts: slot or
    "driver VM" -> the restart count it must exceed (after a crash or a
    driver-kill)."""
    why = []
    for key, before in sorted((restarts or {}).items()):
        if key.startswith("driver "):
            d = (obs.get("drivers") or {}).get(key.split()[1]) or {}
            now = d.get("restarts", 0)
        else:
            now = next((p.get("restarts", 0) for p in obs.get("pods") or [] if p.get("slot") == key), 0)
        if now <= before:
            why.append("%s: %d restarts, waiting for more than %d" % (key, now, before))
    if obs.get("pods") is None:
        why.append("no pods in the observation")
    for p in obs.get("pods") or []:
        if p.get("deleting"):
            why.append("%s deleting" % p["slot"])
        elif p.get("phase") == "Pending" and p.get("unschedulable"):
            continue  # no node can have it: Pending by design
        elif p.get("phase") != "Running" or not p.get("ready"):
            why.append("%s %s%s" % (p["slot"], p.get("phase"), " " + p["waiting"] if p.get("waiting") else ""))
    # A companion may stay Pending: a lease that cannot be Ready.
    for c in obs.get("companions") or []:
        if c.get("deleting"):
            why.append("companion %s deleting" % c["name"])
    for pool, atts in sorted((obs.get("attachments") or {}).items()):
        if atts is None:
            why.append("no attachments of pool %s" % pool)
            continue
        for a in atts:
            if a.get("state") not in TRANSIENT_OK:
                why.append("%s@%s %s" % (a.get("device"), a.get("host"), a.get("state")))
    drivers = obs.get("drivers") or {}
    slices = obs.get("slices") or {}
    for vm in ("vm0", "vm1", "vm2"):
        d = drivers.get(vm)
        if not d or not d.get("ready"):
            why.append("driver of %s not ready" % vm)
        v = (obs.get("vms") or {}).get(vm)
        if v is None:
            why.append("no observation of %s" % vm)
            continue
        for m in v.get("missing") or []:
            why.append("%s: %s/%s %s" % (vm, m.get("pod"), m.get("container"), m.get("reason")))
        log = v.get("driverLog")
        if not log or not log.get("container"):
            why.append("%s: no running driver container" % vm)
        else:
            if not log.get("lendsRestored") or not log.get("sockets"):
                why.append("%s: driver %s not ready (lends restored %s, sockets %s)" % (
                    vm, (log.get("container") or "")[:13], log.get("lendsRestored"), log.get("sockets")))
            if log.get("panics"):
                why.append("%s: driver %s logged %d panics: %s" % (
                    vm, (log.get("container") or "")[:13], log["panics"], (log.get("errors") or [""])[0]))
        if not any(dev.get("name") == "memdev-c100e2e1" for dev in slices.get(vm) or []):
            why.append("%s: memdev-c100e2e1 not in its cxl.nri.io slice" % vm)
    if controllers is not None:
        got = obs.get("controllers") or {}
        pool_slices = obs.get("poolSlices")
        for p, active in sorted(controllers.items()):
            if (got.get(p) == "active") != active:
                why.append("controller %s %s" % (p, got.get(p)))
            # A18: an active controller has published its pool.
            if active and pool_slices is not None and not pool_slices.get(p):
                why.append("pool %s has no slices" % p)
    return why


def online(opts):
    out_dir = opts.get("out") or os.environ.get("MBT_OUT") or "."
    timeout = seconds(opts.get("settle-timeout"), 180)
    todo = steps(opts)
    controllers = {"a": True, "b": True, "c": True}
    path = os.path.join(out_dir, "mbt-steps.txt")
    with open(path, "w") as f:
        f.write("# mbt-stub.py online, %d steps, flags %s\n" % (len(todo), json.dumps(opts, sort_keys=True)))
    log("%d steps, settle timeout %.0f s, steps in %s" % (len(todo), timeout, path))

    def recv():
        line = sys.stdin.readline()
        if not line:
            log("end of input")
            sys.exit(1)
        return line.rstrip("\n")

    seen = {}      # slot or "driver VM" -> restarts at the last quiet observation
    restarts = {}  # what must restart before the next settle is quiet
    for n, action in enumerate(todo, 1):
        words = action.split()
        if words[0] == "ctrl-kill":
            controllers[words[1]] = False
        elif words[0] in ("ctrl-start", "ctrl-restart"):
            controllers[words[1]] = True
        elif words[0] == "crash":
            restarts[words[1]] = seen.get(words[1], 0)
        elif words[0] == "driver-kill":
            restarts["driver " + words[1]] = seen.get("driver " + words[1], 0)
        print("step %d %s" % (n, action), flush=True)
        with open(path, "a") as f:
            f.write(action + "\n")
        if words[0] != "settle":
            line = recv()
            parts = line.split(" ", 3)
            if parts[:2] != ["done", str(n)]:
                log("step %d: expected done, got %r" % (n, line[:300]))
                sys.exit(1)
            log("step %d %s: status %s %s" % (n, action, parts[2], parts[3][:300] if len(parts) > 3 else ""))
            print("ok %d" % n, flush=True)
            continue
        t0 = time.monotonic()
        while True:
            line = recv()
            parts = line.split(" ", 2)
            if parts[:2] != ["observe", str(n)]:
                log("step %d: expected observe, got %r" % (n, line[:300]))
                sys.exit(1)
            obs = json.loads(parts[2])
            why = unquiet(obs, controllers, restarts)
            if obs.get("errors"):
                log("step %d poll %s: errors %s" % (n, obs.get("poll"), obs["errors"]))
            if not why:
                restarts = {}
                seen = {p["slot"]: p.get("restarts", 0) for p in obs.get("pods") or []}
                seen.update(("driver " + vm, d.get("restarts", 0)) for vm, d in (obs.get("drivers") or {}).items())
                log("step %d: quiet after %.1f s, poll %s" % (n, time.monotonic() - t0, obs.get("poll")))
                print("ok %d" % n, flush=True)
                break
            msg = "; ".join(why)
            if time.monotonic() - t0 > timeout:
                with open(os.path.join(out_dir, "mbt-fail.txt"), "w") as f:
                    f.write("step %d settle: not quiet in %.0f s: %s\n" % (n, timeout, msg))
                print("fail %d not quiet in %.0f s: %s" % (n, timeout, msg), flush=True)
                recv_rest()
                return
            print("wait %d %s" % (n, msg), flush=True)
    print("end mbt-stub: %d steps done" % len(todo), flush=True)
    recv_rest()


def recv_rest():
    """Wait until the executor closes the pipe."""
    while sys.stdin.readline():
        pass


def generate(opts):
    todo = steps(opts)
    print("# code.gen.sh of mbt-stub.py: %d steps" % len(todo))
    for n, action in enumerate(todo, 1):
        print("mbt-step %d %s" % (n, action))
        if action == "settle":
            print("mbt-expect %d <<'EOF'\n{\"stub\": true}\nEOF" % n)


def check(opts):
    with open(opts["observed"]) as f:
        line = f.read().strip()
    parts = line.split(" ", 2)
    if parts[0] == "done":
        print("ok")
        return 0
    obs = json.loads(parts[2])
    why = unquiet(obs)
    if why:
        print("wait " + "; ".join(why))
        return 3
    print("ok")
    return 0


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, opts = sys.argv[1], options(sys.argv[2:])
    if cmd == "online":
        online(opts)
    elif cmd == "generate":
        generate(opts)
    elif cmd == "check":
        sys.exit(check(opts))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
