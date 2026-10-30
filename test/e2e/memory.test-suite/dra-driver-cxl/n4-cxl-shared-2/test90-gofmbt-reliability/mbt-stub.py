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
  mbt-stub.py online [--stub-steps FILE | --replay FILE] [--stub-list all|volatile|persistent|reboot]
                     [--reboot guest|qemu] [--settle-timeout SECONDS] [--out DIR] [--FLAG VALUE...]
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
$MBT_STUB_STEPS (a file), else the built-in lists below (--stub-list or
$MBT_STUB_LIST: volatile, persistent, or all, the default: both; reboot,
the node-reboot list of the variant of --reboot, the MBT_REBOOT of the
run, guest or qemu: A41-A44), one action per line ("#" comments).

A step line may end with " => CHECK,CHECK..." (the stub's own checks, not
sent to the executor). For an action: status=N, status!=N, text=VALUE (the
"text" of its done JSON; $W0 and $W1 are the tokens last written to
c-pmem0 and c-pmem1 by a pwrite that succeeded: "mbt-<step>", "" after
junk), fired (the last armed driver-kill-at fired), killat=REASON (its done
line reports the watcher done with a reason starting with REASON),
boot=VM (node-reboot: its "boot" is a boot id, not the one VM had at the
last quiet settle). A failed check fails the
step. For a settle: detached=DEV (no attachment of DEV in any pool),
pdev=DEV:FIELD=VALUE (a field of pdevs DEV, VALUE $W0/$W1 too): the
settle waits for them; companions=ready (every companion pod Running and
Ready); pmem=none (no pmem region in any VM); restarts=VM:N (the driver
pod of VM has N restarts); until=fired ends the settle as soon as a
driver-kill-at fired, quiet or not (to act before kubelet retries the
Prepare); mems=SLOT:NODES (the cpuset.mems.effective of the container
main of the pod of SLOT is NODES, e.g. 0-3); devices=VM (every dax or
pmem device node in a container of VM, the "devices" of A44, is the
device of that name in the VM's cxlDevices with the same major:minor: no
stale device node); rebooted=VM (after a node-reboot of VM: its bootID is
the "boot" of that step, every slot pod on VM that was there at the last
quiet settle and the driver pod of VM have one restart more than then,
not more). Every quiet settle logs the
cpuset.mems and cpuset.mems.effective of every container and the fencing
mode of every driver (A36) to stderr (mbt-cxl.log). Every settle also waits until the pdevs of a device
written by a pwrite that succeeded have its token (token, raw, erofs), a
pbad pod is Refused (Pending with a Warning event that its block claim of
a share is refused), what a driver-kill-at watcher killed has restarted,
and no VM logged a kernel BUG/Oops/WARNING (kernel.badTotal).
"""

import json
import os
import re
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
# dnuma (A39): one container with a local numa slice (node 2) and
# c-pooled0 in numa (node 3); write and read are for dax kinds only
create dnuma@vm0#0
settle => mems=dnuma@vm0#0:0-3
write dnuma@vm0#0 => status=2
read dnuma@vm0#0 => status=2
crash dnuma@vm0#0
settle => mems=dnuma@vm0#0:0-3
delete dnuma@vm0#0
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

# The persistent devices (A22-A27): every new verb and kind. The device's
# regions on a VM's hb1 decoder stack are released in the reverse order
# of their creation (no holes, A9); a writer runs only while no share is
# held. Each driver-kill-at marker hits one persistent Prepare.
PSTEPS = """
# 1. the writers of the fresh devices: c-pmem0 block on vm0 (its fsdax
# namespace created), c-pmem1 block on vm2
create pwr-c@vm0#0
create xpb-c@vm2#0
create plse@vm1#0
create plse@vm2#0
settle
pread pwr-c@vm0#0 => status=0,text=
pwrite pwr-c@vm0#0 img => status=0
pwrite xpb-c@vm2#0 img => status=0
pread pwr-c@vm0#0 => status=0,text=$W0
pread xpb-c@vm2#0 => status=0,text=$W1
# hold is for fs kinds only
hold pwr-c@vm0#0 => status=2
settle => pdev=c-pmem0:lsa=labels,pdev=c-pmem1:lsa=labels
delete pwr-c@vm0#0
delete xpb-c@vm2#0
settle => detached=c-pmem1
# the exclusive device's erofs, direct, on vm0
create xpf-c@vm0#0
settle
pread xpf-c@vm0#0 => status=0,text=$W1
pwrite xpf-c@vm0#0 img => status!=0
delete xpf-c@vm0#0
settle
# 2. readers of c-pmem0: direct (vm1), cached (vm2), read-only block (vm0),
# a refused block claim of a share (vm1), fs leases direct and cached
create pfsd-c@vm1#0
create pfsc-c@vm2#0
create pbro-c@vm0#0
create pbad-c@vm1#0
settle
pread pfsd-c@vm1#0 => status=0,text=$W0
pread pfsc-c@vm2#0 => status=0,text=$W0
pread pbro-c@vm0#0 => status=0,text=$W0
pwrite pbro-c@vm0#0 img => status!=0
pwrite pfsd-c@vm1#0 junk => status!=0
pread pbad-c@vm1#0 => status!=0
lease-get plse@vm2#0 pfd => status=0
lease-get plse@vm1#0 pfc => status=0
settle
pread plse@vm2#0 => status=0,text=$W0
pread plse@vm1#0 => status=0,text=$W0
pwrite plse@vm2#0 img => status!=0
# a hold during lease-put: the release waits, the lease stays Releasing
# and readable until unhold
hold plse@vm2#0 => status=0
lease-put plse@vm2#0 => status!=0
pread plse@vm2#0 => status=0,text=$W0
unhold plse@vm2#0 => status=0
settle
# a hold of a claim reader, ended by a crash; the bind comes back
hold pfsd-c@vm1#0 => status=0
crash pfsd-c@vm1#0
settle
pread pfsd-c@vm1#0 => status=0,text=$W0
# a read-only block lease; its fd refuses writes
lease-put plse@vm1#0 => status=0
lease-get plse@vm1#0 pbr => status=0
settle
pread plse@vm1#0 => status=0,text=$W0
pwrite plse@vm1#0 img => status!=0
lease-put plse@vm1#0 => status=0
delete pfsd-c@vm1#0
delete pfsc-c@vm2#0
delete pbro-c@vm0#0
delete pbad-c@vm1#0
settle
# 3. a block writer lease (the whole device), then pwipe: fresh again
lease-get plse@vm2#0 pbw => status=0
settle
pwrite plse@vm2#0 img => status=0
pread plse@vm2#0 => status=0,text=$W0
lease-put plse@vm2#0 => status=0
settle => detached=c-pmem0,pdev=c-pmem0:token=$W0
pwipe c c-pmem0 => status=0
pwipe c c-pmem9 => status=2
settle => pdev=c-pmem0:lsa=zero,pdev=c-pmem0:pfn=false
# a new writer creates the namespace again
create pwr-c@vm1#0
settle => pdev=c-pmem0:lsa=labels
pwrite pwr-c@vm1#0 img => status=0
delete pwr-c@vm1#0
settle => detached=c-pmem0,pmem=none
# 4. driver-kill-at: each marker of a persistent Prepare
driver-kill-at vm1 region => status=0
create pfsd-c@vm1#0
settle
driver-kill-at vm0 ns => status=0
create pbro-c@vm0#0
settle
driver-kill-at vm1 mount => status=0
create pfsc-c@vm1#0
settle
driver-kill-at vm2 bind => status=0
lease-get plse@vm2#0 pfd
# kubelet retries the companion's Prepare: a release before that would
# leak its region (S1, 04-status-EXEC 14)
settle => companions=ready
pread pfsd-c@vm1#0 => status=0,text=$W0
pread pbro-c@vm0#0 => status=0,text=$W0
pread pfsc-c@vm1#0 => status=0,text=$W0
pread plse@vm2#0
# the requester of a Ready fs lease crashes: its new container sees the bind
crash plse@vm2#0
settle
pread plse@vm2#0
lease-put plse@vm2#0
delete pfsd-c@vm1#0
delete pbro-c@vm0#0
delete pfsc-c@vm1#0
delete plse@vm1#0
delete plse@vm2#0
settle => detached=c-pmem0,pmem=none
"""

# Node reboots (A41-A44): a pod of each family on vm1 (pool numa, a
# persistent device, a local dax slice, a lease of local numa memory, no
# claim), then a reboot of vm1 of the run's variant: every pod back with
# one restart, the device nodes of the new boot in the containers. Today
# (a driver without the fix of plan-13 bug-15) the containers get the
# device nodes of the old boot: the settle after the reboot fails on
# devices=vm1, as it should.
REBOOT_STEPS = {
    "guest": """
# guest: systemctl reboot, qemu keeps its devices (needs the qemu fix of
# bug-17); a block writer of c-pmem0 on vm1
create xnuma-c@vm1#0
create pwr-c@vm1#0
create ldax@vm1#0
create lease@vm1#0
create plain@vm1#0
settle => devices=vm1
pwrite pwr-c@vm1#0 img => status=0
write ldax@vm1#0 => status=0
lease-get lease@vm1#0 numa => status=0
settle => devices=vm1
node-reboot vm2 => status=2
node-reboot vm1 => status=0,boot=vm1
settle => rebooted=vm1,devices=vm1
pread pwr-c@vm1#0 => status=0,text=$W0
read ldax@vm1#0 => status=0,text=
delete xnuma-c@vm1#0
delete pwr-c@vm1#0
delete ldax@vm1#0
delete lease@vm1#0
delete plain@vm1#0
settle => detached=c-pmem0,pmem=none
""",
    "qemu": """
# qemu: the qemu process of vm1 restarts, every device attached again (the
# local memdev by the executor); an erofs reader of c-pmem0 direct on vm1
create pwr-c@vm1#0
settle
pwrite pwr-c@vm1#0 img => status=0
delete pwr-c@vm1#0
settle => detached=c-pmem0
create xnuma-c@vm1#0
create pfsd-c@vm1#0
create ldax@vm1#0
create lease@vm1#0
create plain@vm1#0
settle => devices=vm1
pread pfsd-c@vm1#0 => status=0,text=$W0
write ldax@vm1#0 => status=0
lease-get lease@vm1#0 numa => status=0
settle => devices=vm1
node-reboot vm2 => status=2
node-reboot vm1 => status=0,boot=vm1
settle => rebooted=vm1,devices=vm1
pread pfsd-c@vm1#0 => status=0,text=$W0
read ldax@vm1#0 => status=0,text=
delete xnuma-c@vm1#0
delete pfsd-c@vm1#0
delete ldax@vm1#0
delete lease@vm1#0
delete plain@vm1#0
settle => detached=c-pmem0,pmem=none
""",
}

TRANSIENT_OK = ("attached",)
# A pbad claim (a share with mode block, writable): the driver refuses its
# Prepare with this (D/pool_persistent.go, Doc/usage.md).
PBAD_REFUSAL = "writable only exclusively"


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
    """The steps: (action, checks) pairs."""
    path = opts.get("replay") or opts.get("stub-steps") or os.environ.get("MBT_STUB_STEPS")
    if path:
        text = open(path).read()
    else:
        which = opts.get("stub-list") or os.environ.get("MBT_STUB_LIST") or "all"
        if which == "reboot":
            text = REBOOT_STEPS.get(opts.get("reboot"))
            if text is None:
                sys.exit("mbt-stub: --stub-list reboot needs --reboot guest or qemu (MBT_REBOOT), not %r" % opts.get("reboot"))
        else:
            text = {"volatile": STEPS, "persistent": PSTEPS, "all": STEPS + PSTEPS}.get(which)
        if text is None:
            sys.exit("mbt-stub: --stub-list %r: volatile, persistent, all or reboot" % which)
    out = []
    for l in text.splitlines():
        l = l.strip()
        if not l or l.startswith("#"):
            continue
        action, _, checks = l.partition(" => ")
        out.append((action.strip(), [c.strip() for c in checks.split(",") if c.strip()]))
    return out


def device_of(action, lease_modes):
    """The persistent device that a pwrite writes: c-pmem0 for pwr-c and a
    plse with a pbw lease, c-pmem1 for xpb-c, else None."""
    words = action.split()
    slot = words[1] if len(words) > 1 else ""
    kind = slot.split("@")[0]
    if kind == "pwr-c" or (kind == "plse" and lease_modes.get(slot) == "pbw"):
        return "c-pmem0"
    if kind == "xpb-c":
        return "c-pmem1"
    return None


def subst(value, tokens):
    return value.replace("$W0", tokens.get("c-pmem0", "")).replace("$W1", tokens.get("c-pmem1", ""))


def check_done(checks, status, result, tokens, fired, boot_seen=None):
    """What is wrong with a done line by the checks of its step.
    boot_seen: VM -> its boot id at the last quiet settle."""
    why = []
    for c in checks:
        if c.startswith("boot="):
            vm = c[len("boot="):]
            got, old = (result or {}).get("boot"), (boot_seen or {}).get(vm)
            if not got or got == old:
                why.append("boot %r, want a new boot id of %s (it had %s)" % (got, vm, old))
            continue
        if c == "fired":
            if not fired:
                why.append("no driver-kill-at fired")
            continue
        if c.startswith("killat="):
            # killat=REASON: the done line reports the watcher done, with a
            # reason that starts with REASON (fired false unless "fired")
            k = (result or {}).get("killAt") or {}
            want = c[len("killat="):]
            if not k.get("done") or not str(k.get("reason") or "").startswith(want) or \
                    bool(k.get("fired")) != (want == "fired"):
                why.append("killAt %s, want done, reason %s" % (json.dumps(k, sort_keys=True)[:200], want))
            continue
        key, op, want = c.partition("!=") if "!=" in c else c.partition("=")
        want = subst(want, tokens)
        if key == "status":
            ok = (str(status) == want) if op == "=" else (str(status) != want)
            if not ok:
                why.append("status %s, want %s%s" % (status, "" if op == "=" else "not ", want))
        elif key == "text":
            got = (result or {}).get("text")
            if got != want:
                why.append("text %r, want %r" % (got, want))
        else:
            why.append("unknown check %r" % c)
    return why


def settle_checks(obs, checks, tokens, written, ctx=None):
    """Why the settle checks of a step and the pdevs of the written
    devices do not hold yet. ctx: "boots" (VM -> the boot of its last
    node-reboot), "seen" (slot or "driver VM" -> restarts at the last
    quiet settle)."""
    ctx = ctx or {}
    why = []
    pdevs = obs.get("pdevs") or {}
    for dev, tok in sorted(written.items()):
        p = pdevs.get(dev)
        want = {"token": tok or None, "raw": tok, "erofs": bool(tok)}
        if p is None or any(p.get(k) != v for k, v in want.items()):
            why.append("pdevs %s: %s, want %s" % (dev, p and {k: p.get(k) for k in want}, want))
    for c in checks:
        key, _, val = c.partition("=")
        if key == "detached":
            for pool, atts in sorted((obs.get("attachments") or {}).items()):
                for a in atts or []:
                    if a.get("device") == val:
                        why.append("%s attached to %s (%s)" % (val, a.get("host"), a.get("state")))
        elif key == "until":
            continue
        elif key == "restarts":
            # restarts=VM:N: the driver pod of VM has N restarts
            vm, _, n = val.partition(":")
            got = ((obs.get("drivers") or {}).get(vm) or {}).get("restarts")
            if str(got) != n:
                why.append("driver %s: %s restarts, want %s" % (vm, got, n))
        elif key == "pmem":
            # pmem=none: no CXL region of mode pmem in any VM (a leaked one
            # stays without targets after its memdev is detached)
            for vm, v in sorted((obs.get("vms") or {}).items()):
                for r in (v or {}).get("pmem") or []:
                    why.append("%s: pmem %s (serials %s, nd %s)" % (vm, r.get("region"), r.get("serials"), r.get("ndRegion")))
        elif key == "companions":
            # every companion pod Running and Ready (a lease whose
            # companion's Prepare was retried after a driver kill)
            for c in obs.get("companions") or []:
                if c.get("phase") != "Running" or not c.get("ready"):
                    why.append("companion %s %s%s" % (c.get("name"), c.get("phase"), "" if c.get("ready") else " not ready"))
        elif key == "mems":
            # mems=SLOT:NODES: cpuset.mems.effective of its container main
            slot, _, want = val.partition(":")
            got = mems_of(obs, slot)
            if got != want:
                why.append("%s: cpuset.mems.effective %s, want %s" % (slot, got, want))
        elif key == "devices":
            why.extend(stale_devices(obs, val))
        elif key == "rebooted":
            why.extend(not_rebooted(obs, val, ctx))
        elif key == "pdev":
            dev, _, fv = val.partition(":")
            field, _, want = fv.partition("=")
            want = subst(want, tokens)
            got = (pdevs.get(dev) or {}).get(field)
            if str(got).lower() != want.lower() and not (got is None and want == ""):
                why.append("pdevs %s %s %r, want %r" % (dev, field, got, want))
        else:
            why.append("unknown settle check %r" % c)
    return why


DEV_NAME = re.compile(r"^(dax\d+\.\d+|pmem\d+)$")


def stale_devices(obs, vm):
    """devices=VM: the dax and pmem device nodes in the containers of VM
    that are not the VM's device of that name (A44)."""
    v = (obs.get("vms") or {}).get(vm)
    if not v:
        return ["%s: not observed" % vm]
    if v.get("cxlDevices") is None or v.get("containers") is None:
        return ["%s: cxlDevices or containers not observed" % vm]
    cur = {d.get("name"): d for d in v["cxlDevices"]}
    why = []
    for c in v["containers"]:
        for d in c.get("devices") or []:
            name = (d.get("path") or "").rsplit("/", 1)[-1]
            if not DEV_NAME.match(name):
                continue
            have = cur.get(name)
            if have is None:
                why.append("%s: %s/%s has %s %s, the VM has no %s" % (vm, c.get("pod"), c.get("name"), d.get("path"), d.get("dev"), name))
            elif have.get("dev") != d.get("dev"):
                why.append("%s: %s/%s has %s %s, the VM's %s is %s (serial %s)" % (
                    vm, c.get("pod"), c.get("name"), d.get("path"), d.get("dev"), name, have.get("dev"), have.get("serial")))
    return why


def not_rebooted(obs, vm, ctx):
    """rebooted=VM: why VM does not look rebooted yet: its boot id, one
    restart more of the slot pods on it and of its driver pod."""
    why = []
    want = (ctx.get("boots") or {}).get(vm)
    got = ((obs.get("vms") or {}).get(vm) or {}).get("bootID")
    if not want or got != want:
        why.append("%s: boot id %s, want %s (the boot of node-reboot)" % (vm, got, want))
    seen = ctx.get("seen") or {}
    for p in obs.get("pods") or []:
        if p.get("node") != vm or p.get("deleting") or p.get("slot") not in seen:
            continue
        if p.get("restarts", 0) != seen[p["slot"]] + 1:
            why.append("%s: %d restarts, want %d (one for the reboot)" % (p["slot"], p.get("restarts", 0), seen[p["slot"]] + 1))
    key = "driver " + vm
    got = ((obs.get("drivers") or {}).get(vm) or {}).get("restarts", 0)
    if key in seen and got != seen[key] + 1:
        why.append("driver %s: %d restarts, want %d" % (vm, got, seen[key] + 1))
    return why


def log_devices(n, obs):
    """Log the boot id and the CXL devices of every VM and the dax and pmem
    device nodes of every container (the evidence of A44)."""
    for vm, v in sorted((obs.get("vms") or {}).items()):
        if not v:
            continue
        devs = " ".join("%s=%s/%s" % (d.get("name"), d.get("dev"), d.get("serial")) for d in v.get("cxlDevices") or [])
        log("step %d devices %s: boot %s, cxlDevices %s" % (n, vm, v.get("bootID"), devs or "-"))
        for c in v.get("containers") or []:
            nodes = " ".join("%s=%s" % (d.get("path"), d.get("dev")) for d in c.get("devices") or []
                             if DEV_NAME.match((d.get("path") or "").rsplit("/", 1)[-1]))
            if nodes:
                log("step %d devices %s: %s/%s %s (%s)" % (n, vm, c.get("pod"), c.get("name"), nodes, c.get("devicesFrom")))


def mems_of(obs, slot, container="main"):
    """The cpuset.mems.effective of the container of the pod of slot that
    is not being deleted, None if it is not observed."""
    pod = next((p for p in obs.get("pods") or [] if p.get("slot") == slot and not p.get("deleting")), None)
    if not pod or not pod.get("node"):
        return None
    for c in ((obs.get("vms") or {}).get(pod["node"]) or {}).get("containers") or []:
        if c.get("pod") == pod.get("name") and c.get("name") == container:
            return c.get("mems_effective")
    return None


def log_mems(n, obs):
    """Log the fencing mode of every driver and the cpusets of every
    container (the evidence of A38)."""
    for vm, v in sorted((obs.get("vms") or {}).items()):
        if not v:
            continue
        nodes = ",".join("%s:%dMi" % (k, (d.get("memtotal") or 0) >> 20) for k, d in sorted((v.get("nodes") or {}).items()))
        log("step %d mems %s: fencing %s, nodes %s" % (n, vm, (v.get("driverLog") or {}).get("fencing"), nodes))
        for c in v.get("containers") or []:
            log("step %d mems %s: %s/%s mems %s effective %s memory.high %s" % (
                n, vm, c.get("pod"), c.get("name"), c.get("mems"), c.get("mems_effective"), c.get("memory_high")))


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
        elif (p.get("slot") or "").startswith("pbad-") and p.get("phase") == "Pending":
            # Refused (A25): its Prepare fails at every retry.
            if not any(PBAD_REFUSAL in (e.get("message") or "") for e in p.get("events") or []):
                why.append("%s Pending, not refused yet" % p["slot"])
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
        k = v.get("kernel")
        if k is None:
            why.append("%s: no kernel part" % vm)
        elif k.get("badTotal"):
            why.append("%s: kernel: %d BUG/Oops/WARNING lines: %s" % (vm, k["badTotal"], (k.get("badFirst") or [""])[0]))
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

    def fail(n, msg):
        with open(os.path.join(out_dir, "mbt-fail.txt"), "w") as f:
            f.write("step %d: %s\n" % (n, msg))
        print("fail %d %s" % (n, msg), flush=True)
        recv_rest()

    seen = {}         # slot or "driver VM" -> restarts at the last quiet observation
    restarts = {}     # what must restart before the next settle is quiet
    tokens = {}       # persistent device -> the token last written ($W0, $W1)
    written = {}      # persistent device -> the token its pdevs must show
    lease_modes = {}  # plse slot -> the mode of its lease
    killat = {"vm": None, "fired": False}
    boots = {}        # VM -> the boot id of its last node-reboot
    boot_seen = {}    # VM -> its boot id at the last quiet settle

    def killat_seen(state):
        # A23: a driver-kill-at that fired restarts the driver of its VM.
        if not killat["vm"] or not isinstance(state, dict) or state.get("done") is False:
            return
        log("driver-kill-at %s: %s" % (killat["vm"], json.dumps(state, sort_keys=True)[:300]))
        if state.get("fired"):
            key = "driver " + killat["vm"]
            restarts[key] = seen.get(key, 0)
            killat["fired"] = True
        killat["vm"] = None

    for n, (action, checks) in enumerate(todo, 1):
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
            status = int(parts[2]) if len(parts) > 2 and parts[2].lstrip("-").isdigit() else None
            try:
                result = json.loads(parts[3]) if len(parts) > 3 else {}
            except ValueError:
                result = {}
            log("step %d %s: status %s %s" % (n, action, parts[2], parts[3][:300] if len(parts) > 3 else ""))
            if words[0] == "driver-kill-at" and status == 0:
                killat.update(vm=words[1], fired=False)
            else:
                killat_seen(result.get("killAt"))
            if status == 0:
                if words[0] == "pwrite":
                    dev = device_of(action, lease_modes)
                    if dev:
                        tokens[dev] = written[dev] = "mbt-%d" % n if words[2] == "img" else ""
                elif words[0] == "pwipe":
                    tokens[words[2]] = ""
                    written.pop(words[2], None)
                elif words[0] == "lease-get" and words[1].startswith("plse@"):
                    lease_modes[words[1]] = words[2]
                elif words[0] == "node-reboot" and result.get("boot"):
                    boots[words[1]] = result["boot"]
            if words[0] in ("lease-put", "delete"):
                lease_modes.pop(words[1], None)
            why = check_done(checks, status, result, tokens, killat["fired"], boot_seen)
            if why:
                fail(n, "%s: %s" % (action, "; ".join(why)))
                return
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
            killat_seen(obs.get("killAt"))
            if "until=fired" in checks:
                # Not a settle: on as soon as the watcher has fired (to act
                # in the window before kubelet retries the Prepare).
                why = [] if killat["fired"] else ["driver-kill-at has not fired"]
                if not why:
                    log("step %d: driver-kill-at fired, poll %s" % (n, obs.get("poll")))
                    print("ok %d" % n, flush=True)
                    break
            else:
                why = unquiet(obs, controllers, restarts) + settle_checks(obs, checks, tokens, written,
                                                                          {"boots": boots, "seen": seen})
            if obs.get("errors"):
                log("step %d poll %s: errors %s" % (n, obs.get("poll"), obs["errors"]))
            if not why:
                restarts = {}
                seen = {p["slot"]: p.get("restarts", 0) for p in obs.get("pods") or []}
                seen.update(("driver " + vm, d.get("restarts", 0)) for vm, d in (obs.get("drivers") or {}).items())
                boot_seen.update((vm, v.get("bootID")) for vm, v in (obs.get("vms") or {}).items() if v)
                log("step %d: quiet after %.1f s, poll %s" % (n, time.monotonic() - t0, obs.get("poll")))
                log_mems(n, obs)
                log_devices(n, obs)
                print("ok %d" % n, flush=True)
                break
            msg = "; ".join(why)
            if time.monotonic() - t0 > timeout:
                log_devices(n, obs)
                fail(n, "settle: not quiet in %.0f s: %s" % (timeout, msg))
                return
            print("wait %d %s" % (n, msg), flush=True)
    print("end mbt-stub: %d steps done" % len(todo), flush=True)
    recv_rest()


def recv_rest():
    """Wait until the executor closes the pipe."""
    while sys.stdin.readline():
        pass


def generate(opts):
    todo = [a for a, _ in steps(opts)]
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
