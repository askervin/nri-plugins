#!/usr/bin/env python3
"""The step runner of the presenter terminal (T1).

Usage: steps.py local|pool|pool-shared-fs [N | N- | --auto] [--no-color]

Each step prints its caption and its command as typed, waits for a key
(Enter run, s skip, z zoom, q quit), runs the command in VM2 (in
/root/demo, with the kubeconfig of the demo namespace), and prints a one
or two line result and how long it took. "N" runs step N, "N-" the steps
from N on, nothing all of them; "--auto" runs all of them with short
pauses (DEMO_AUTO_PAUSE seconds, default 2) and prints the timings. The
full output of every step goes to run/steps.log, the timings of --auto to
run/timings.txt.
"""
import json
import os
import re
import subprocess
import sys
import time

import common as c

READERS = ["reader-a", "reader-b", "reader-c"]
CASES = ("local", "pool", "pool-shared-fs")


class Step:
    def __init__(self, caption, command, check=None, expect_fail=False):
        self.caption = caption
        self.command = command
        self.check = check
        self.expect_fail = expect_fail


def steps(case, serial):
    """Return the steps of CASE (03-demo-design sections 5 and 6, 12-fs-demo-design B3), the device SERIAL in the commands."""
    S = serial
    if case == "pool-shared-fs":
        return fs_steps(S)
    where = "vm1" if case == "pool" else "vm2"
    return [
        Step("a writer starts on %s; it has no CXL memory yet" % where,
             "kubectl apply -f %s/writer.yaml" % case, check_running(["writer"])),
        Step("the writer asks for the whole device, exclusively",
             "kubectl exec writer -- cxl-request request --serial %s --mode dax" % S, check_lease),
        Step("the writer writes a line into the device",
             'kubectl exec writer -- /demo/write "Hello from the writer, $(date +%T)"', check_last_line),
        Step("three readers start" + (": two on vm2, one on vm1" if case == "pool" else ""),
             "kubectl apply -f %s/readers.yaml" % case, check_running(READERS)),
        Step("readers ask for a read-only share: they must wait",
             "for r in reader-a reader-b reader-c; do kubectl exec $r -- cxl-request request --serial %s --shared --read-only --wait 0s; done" % S,
             check_leases),
        Step("the writer is done and releases the device",
             "kubectl exec writer -- cxl-request release --all", check_readers_get_it),
        Step("each reader reads the line and keeps it mapped",
             "for r in reader-a reader-b reader-c; do kubectl exec $r -- /demo/read; kubectl exec $r -- /demo/hold; done",
             check_reads),
        Step("a reader tries to write: the kernel refuses",
             'kubectl exec reader-a -- /demo/write "overwrite"', check_last_line, expect_fail=True),
        Step("everything goes away", "kubectl delete -f %s/" % case, check_gone),
    ]


def fs_steps(S):
    """Return the steps F1-F9 of pool-shared-fs, the device serial S in the commands."""
    case = "pool-shared-fs"
    fs = "/run/cxl/fs/hello"
    return [
        Step("a writer starts on vm1; it has no CXL memory yet",
             "kubectl apply -f %s/writer.yaml" % case, check_running(["writer"])),
        Step("the writer asks for the device as a block device",
             "kubectl exec writer -- cxl-request request --serial %s --mode block" % S, check_lease),
        Step("the writer makes a file system with hello.txt",
             'kubectl exec writer -- /demo/mkfs "Hello from the writer, $(date +%T)"', check_last_line),
        Step("three readers start: two on vm2, one on vm1",
             "kubectl apply -f %s/readers.yaml" % case, check_running(READERS)),
        Step("readers ask for the file system: they must wait",
             "for r in reader-a reader-b reader-c; do kubectl exec $r -- cxl-request request --serial %s --shared --read-only --mode fs --name hello --wait 0s; done" % S,
             check_leases),
        Step("the writer is done and releases the device",
             "kubectl exec writer -- cxl-request release --all", check_readers_get_it),
        Step("each reader reads hello.txt from its mount",
             "for r in reader-a reader-b reader-c; do kubectl exec $r -- cat %s/hello.txt; done" % fs, check_cat),
        Step("a reader tries to write: read-only file system",
             "kubectl exec reader-a -- sh -c 'echo overwrite > %s/hello.txt'" % fs, check_last_line, expect_fail=True),
        Step("everything goes away", "kubectl delete -f %s/" % case, check_gone),
    ]


def step_letter(case):
    """Return the letter of the step numbers of CASE: F for pool-shared-fs, L for the others."""
    return "F" if case == "pool-shared-fs" else "L"


###
### Checks: what the step did, in one or two lines
###

def k8s(state, kinds="pods,claims"):
    return (c.run_probe(state["VM2_DIR"], ["--k8s", kinds, "--ns", state["NS"]], timeout=8) or {}).get("k8s") or {}


def wait_for(state, cond, timeout):
    """Return (value, seconds) of the first true COND(k8s objects) within TIMEOUT, (None, seconds) else."""
    t0 = time.time()
    while True:
        try:
            v = cond(k8s(state))
        except RuntimeError:
            v = None
        if v or time.time() - t0 > timeout:
            return v, time.time() - t0
        time.sleep(1)


def check_running(names):
    def check(state, out, rc):
        def cond(k):
            pods = {c.meta(p)["name"]: p for p in c.items(k.get("pods"), "Pod")}
            if all((pods.get(n, {}).get("status") or {}).get("phase") == "Running" for n in names):
                return ", ".join("%s %s" % (n, c.short_node(pods[n]["spec"].get("nodeName"), state)) for n in names)
            return None
        v, t = wait_for(state, cond, 180)
        if not v:
            return ["not Running after %.0f s" % t] + last_lines(out, 1)
        return ["Running: " + v, "(%.1f s until Running)" % t]
    return check


def responses(out):
    found = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                found.append(json.loads(line))
            except ValueError:
                pass
    return found


def lease_words(r):
    if r.get("error"):
        return "refused: " + r["error"]
    words = [r.get("lease", "?"), r.get("state", "?")]
    if r.get("mode"):
        words.append(r["mode"])
    words.append("ro" if r.get("readOnly") else "rw")
    if r.get("state") == "Ready":
        words.append("(share)" if r.get("shared") else "(exclusive)")
    # "-> lease " goes before the words in T1.
    if r.get("mode") == "fs" and r.get("access") and len(" ".join(words + ["(%s)" % r["access"]])) + 9 <= c.WIDTH:
        words.append("(%s)" % r["access"])
    return " ".join(words)


def check_lease(state, out, rc):
    rs = responses(out)
    if not rs:
        return last_lines(out, 2)
    r = rs[-1]
    second = next(("%s %s" % (k, r[k]) for k in ("dax", "block", "path") if r.get(k)), None)
    return ["lease " + lease_words(r)] + ([second] if second else [])


def check_leases(state, out, rc):
    rs = responses(out)
    if not rs:
        return last_lines(out, 2)
    words = ["%s %s" % (n, lease_words(r).split(" ")[1] if not r.get("error") else "refused")
             for n, r in zip(READERS, rs)]
    return c.wrap_list("", words, indent=0)[:2]


def check_last_line(state, out, rc):
    return last_lines(out, 1)


def check_readers_get_it(state, out, rc):
    rs = responses(out)
    if rs and rs[-1].get("leases") is not None:
        first = ["released: " + (", ".join("%s %s" % (l.get("lease", "?"), l.get("state", "?"))
                                          for l in rs[-1]["leases"]) or "no leases")]
    elif rs:
        first = ["release: " + lease_words(rs[-1])]
    else:
        first = last_lines(out, 1)

    def cond(k):
        # A companion pod runs once its claim is allocated and prepared
        # (for the pool: attached too): the lease is Ready then.
        comps = [p for p in c.items(k.get("pods"), "Pod") if c.lease_id(p) and c.requester(p) in READERS]
        if len(comps) >= len(READERS) and all((p.get("status") or {}).get("phase") == "Running" for p in comps):
            return True
        return None
    v, t = wait_for(state, cond, 180)
    return first + ["readers' leases Ready after %.1f s" % t if v else "readers still waiting after %.0f s" % t]


def check_reads(state, out, rc):
    reads = [l for l in out.splitlines() if l.startswith("read at 0:")]
    holds = [l for l in out.splitlines() if l.startswith("holding")]
    if not reads:
        return last_lines(out, 2)
    same = len(set(reads)) == 1
    return ["%d readers %s" % (len(reads), reads[0] if same else "read different bytes!"),
            "%d hold a read-only mapping" % len(holds)]


def check_cat(state, out, rc):
    texts = last_lines(out, len(READERS))
    if len(texts) == len(READERS) and len(set(texts)) == 1:
        return ['%d readers read: "%s"' % (len(texts), texts[0])]
    return ["readers read different texts!"] + texts[-1:]


def check_gone(state, out, rc):
    def cond(k):
        return not c.items(k.get("pods"), "Pod") and not [cl for cl in c.items(k.get("claims")) if c.lease_id(cl)]
    v, t = wait_for(state, cond, 180)
    return ["pods and leases gone after %.1f s" % t if v else "still there after %.0f s" % t]


def last_lines(out, n):
    """Return the last N lines of OUT that say something (not kubectl's exit code note)."""
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("command terminated with exit code")]
    return lines[-n:] if lines else ["(no output)"]


###
### Running
###

def result_lines(result, rows=3):
    """Return the ROWS terminal lines of the RESULT lines: "-> " first, a long one continued after its last fitting ": " or space."""
    out = []
    for line in result:
        prefix = "-> "
        while line and len(out) < rows:
            room = c.WIDTH - len(prefix)
            if len(line) <= room:
                out.append(prefix + line)
                break
            cut = line.rfind(": ", 0, room)
            cut = cut + 1 if cut > 0 else line.rfind(" ", 0, room + 1)
            if cut <= 0:
                cut = room
            out.append(prefix + line[:cut].rstrip())
            line, prefix = line[cut:].lstrip(), "   "
    return [c.cut(l) for l in out[:rows]]


def wrap_command(cmd):
    """Return the command as typed, "$ " first, wrapped at 50 columns."""
    out, cur = [], "$"
    for w in cmd.split():
        if len(cur) + 1 + len(w) > c.WIDTH and cur.strip() != "$":
            out.append(cur)
            cur = "   "
        cur += " " + w
    out.append(cur)
    return out


def host_tz():
    """Return " TZ=<zone>" of the host for the VM's shell (its clock prints UTC otherwise)."""
    tz = os.environ.get("TZ")
    if not tz:
        link = os.path.realpath("/etc/localtime")
        tz = link.split("zoneinfo/", 1)[1] if "zoneinfo/" in link else ""
    return " TZ=%s" % tz if re.fullmatch(r"[A-Za-z0-9_+/-]+", tz or "") else ""


def getkey():
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def log(text):
    os.makedirs(c.STATE_DIR, exist_ok=True)
    with open(os.path.join(c.STATE_DIR, "steps.log"), "a") as f:
        f.write(text)


def run_step(state, case, n, step, auto, color, total):
    sys.stdout.write("\033[H\033[2J")
    hdr = c.title("PRESENTER %s %s%d/%d" % (case, step_letter(case), n, total))
    lines = [hdr] + c.wrap_list("", step.caption.split(" "), indent=2, sep="") + wrap_command(step.command)
    for i, l in enumerate(lines):
        print((c.BOLD + l + c.RESET) if color and i == 0 else l)
    while True:
        if auto:
            time.sleep(float(os.environ.get("DEMO_AUTO_PAUSE", "2")))
            key = "\n"
        else:
            sys.stdout.write("Enter run, s skip, z zoom, q quit ")
            sys.stdout.flush()
            key = getkey()
            sys.stdout.write("\r\033[K")
        if key in ("q", "Q"):
            return "quit", 0
        if key in ("s", "S"):
            print("skipped")
            return "skip", 0
        if key in ("z", "Z"):
            sys.stdout.write("zoom: ")
            sys.stdout.flush()
            args = sys.stdin.readline().split()
            if args:
                subprocess.call([os.path.join(c.BIN_DIR, "demo"), "zoom"] + args)
            print("\n".join(lines[-3:]))
            continue
        if key in ("\n", "\r"):
            break
    t0 = time.time()
    script = "cd /root/demo && export KUBECONFIG=/root/demo/kubeconfig%s\n%s\n" % (host_tz(), step.command)
    rc, out = c.run_vm(state["VM2_DIR"], script, timeout=300)
    t_cmd = time.time() - t0
    log("=== %s %s %s%d rc=%d %.1fs\n$ %s\n%s\n" % (time.strftime("%H:%M:%S"), case, step_letter(case), n, rc, t_cmd, step.command, out))
    try:
        result = step.check(state, out, rc) if step.check else last_lines(out, 2)
    except Exception as e:   # a broken check must not stop the talk
        result = ["(check failed: %s)" % e] + last_lines(out, 1)
    t_all = time.time() - t0
    ok = (rc != 0) if step.expect_fail else (rc == 0)
    if not ok and not step.expect_fail:
        result = ["exit %d: " % rc + (last_lines(out, 1)[0])] + result[:1]
    for l in result_lines(result):
        print(c.colorize(l) if color else l)
    sys.stdout.write("   %.1f s (command %.1f s)" % (t_all, t_cmd))
    sys.stdout.flush()
    log("result: %s (%.1f s)\n" % (" | ".join(result), t_all))
    return "ok" if ok else "fail", t_all


def main():
    args = sys.argv[1:]
    if not args or args[0] not in CASES:
        sys.exit(__doc__)
    case = args[0]
    state = c.load_state()
    if state is None:
        sys.exit("demo not set up: demo setup %s" % case)
    if state.get("DEMO_CASE") != case:
        sys.exit("the demo is set up for %s, not %s: demo teardown; demo setup %s" % (state.get("DEMO_CASE"), case, case))
    color = c.use_color(args)
    auto = "--auto" in args
    all_steps = steps(case, state["SERIAL"])
    first, last = 1, len(all_steps)
    sel = next((a for a in args[1:] if re.fullmatch(r"\d+-?", a)), None)
    if sel:
        first = int(sel.rstrip("-"))
        last = len(all_steps) if sel.endswith("-") else first
    if not 1 <= first <= len(all_steps):
        sys.exit("steps 1-%d" % len(all_steps))
    timings = []
    for n in range(first, last + 1):
        what, t = run_step(state, case, n, all_steps[n - 1], auto, color, len(all_steps))
        timings.append((n, what, t))
        if what == "quit":
            break
        if auto:
            print()
            time.sleep(float(os.environ.get("DEMO_AUTO_PAUSE", "2")) + 1)
        elif n < last:
            sys.stdout.write("; Enter: next ")
            sys.stdout.flush()
            if getkey() in ("q", "Q"):
                break
        else:
            print()
    if auto:
        summary = "%s %s: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), case,
                                 " ".join("%s%d=%.1fs%s" % (step_letter(case), n, t, "" if w == "ok" else "(%s)" % w)
                                          for n, w, t in timings))
        print(summary)
        with open(os.path.join(c.STATE_DIR, "timings.txt"), "a") as f:
            f.write(summary + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
        sys.exit(130)
