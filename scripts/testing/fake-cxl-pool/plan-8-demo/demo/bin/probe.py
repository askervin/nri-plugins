#!/usr/bin/env python3
"""Probe of the demo views: one call per node per refresh.

Runs as root in a VM: "ssh ... node sudo python3 - ARGS < probe.py".
Prints one JSON object with the sections that ARGS ask for:

  --k8s KINDS    Kubernetes objects through kubectl (comma list):
                 pods, claims (namespace --ns), slices, drivers (the driver
                 pods in kube-system), allclaims (all namespaces)
  --ns NS        the namespace of the demo
  --node         CXL in the kernel: memdevs (serial, size), regions (mode,
                 size, memdevs, dax devices with size and driver), and the
                 processes that map a dax device (/proc/PID/maps), with the
                 pod uid of their cgroup
  --bytes SERIAL the first --len bytes (default 256) of the dax device of
                 the region of the memdev SERIAL, mapped read-only
  --root DIR     prefix of /sys, /proc and /dev (tests)

Errors of a section go to "errors"; the probe itself exits 0.
"""
import json
import mmap
import os
import re
import subprocess
import sys
import threading

ROOT = ""
KUBECTL_TIMEOUT = 3.0
DRIVER_LABEL = "app.kubernetes.io/name=nri-dra-driver-cxl"
POD_UID = re.compile(r"pod([0-9a-f]{8}[_-][0-9a-f]{4}[_-][0-9a-f]{4}[_-][0-9a-f]{4}[_-][0-9a-f]{12})")


def path(p):
    return ROOT + p


def read(p, default=None):
    try:
        with open(path(p)) as f:
            return f.read().strip()
    except OSError:
        return default


def int_any(s):
    try:
        return int(str(s).strip(), 0)
    except (TypeError, ValueError):
        return None


def listdir(p):
    try:
        return sorted(os.listdir(path(p)))
    except OSError:
        return []


def link_name(p):
    try:
        return os.path.basename(os.readlink(path(p)))
    except OSError:
        return None


def kubectl(args, out, key, errors):
    env = dict(os.environ)
    if os.path.exists("/root/.kube/config"):
        env["KUBECONFIG"] = "/root/.kube/config"
    env["PATH"] = env.get("PATH", "") + ":/usr/local/bin:/usr/bin:/bin"
    try:
        p = subprocess.run(["kubectl"] + args + ["-o", "json"], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=KUBECTL_TIMEOUT, env=env)
        if p.returncode != 0:
            errors.append("kubectl %s: %s" % (" ".join(args), p.stderr.decode(errors="replace").strip()[:200]))
            return
        out[key] = json.loads(p.stdout.decode(errors="replace"))
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        errors.append("kubectl %s: %s" % (" ".join(args), e))


def k8s(kinds, ns, errors):
    """Return the objects of KINDS from one kubectl call: kubectl's start costs more than the objects."""
    known = {"pods", "claims", "allclaims", "slices", "drivers"}
    for kind in kinds:
        if kind not in known:
            errors.append("unknown kind %s" % kind)
    kinds = [k for k in kinds if k in known]
    if not kinds:
        return {}
    resources = sorted({{"pods": "pods", "drivers": "pods", "claims": "resourceclaims", "allclaims": "resourceclaims",
                         "slices": "resourceslices"}[k] for k in kinds})
    scope = ["-n", ns] if set(kinds) <= {"pods", "claims"} else ["-A"]
    got = {}
    kubectl(["get", ",".join(resources)] + scope, got, "all", errors)
    if "all" not in got:
        return {}
    its = got["all"].get("items") or []

    def pick(cond):
        return {"apiVersion": "v1", "kind": "List", "items": [o for o in its if cond(o)]}

    def ns_of(o):
        return (o.get("metadata") or {}).get("namespace")
    driver = DRIVER_LABEL.split("=", 1)
    out = {}
    for kind in kinds:
        if kind == "pods":
            out[kind] = pick(lambda o: o.get("kind") == "Pod" and ns_of(o) == ns)
        elif kind == "drivers":
            out[kind] = pick(lambda o: o.get("kind") == "Pod" and ns_of(o) == "kube-system" and
                             ((o.get("metadata") or {}).get("labels") or {}).get(driver[0]) == driver[1])
        elif kind == "claims":
            out[kind] = pick(lambda o: o.get("kind") == "ResourceClaim" and ns_of(o) == ns)
        elif kind == "allclaims":
            out[kind] = pick(lambda o: o.get("kind") == "ResourceClaim")
        else:
            out[kind] = pick(lambda o: o.get("kind") == "ResourceSlice")
    return out


def memdevs():
    """Return the memdevs and a map endpoint id -> memdev name."""
    devs, endpoints = [], {}
    base = "/sys/bus/cxl/devices"
    for name in listdir(base):
        if re.fullmatch(r"mem\d+", name):
            devs.append({
                "name": name,
                "serial": "0x%x" % (int_any(read("%s/%s/serial" % (base, name))) or 0),
                "size": int_any(read("%s/%s/ram/size" % (base, name), "0")) or 0,
                "numaNode": int_any(read("%s/%s/numa_node" % (base, name))),
            })
        m = re.fullmatch(r"endpoint(\d+)", name)
        if m:
            up = link_name("%s/%s/uport" % (base, name))
            if up:
                endpoints[m.group(1)] = up
    return devs, endpoints


def regions(endpoints, devs):
    base = "/sys/bus/cxl/devices"
    out = []
    for name in listdir(base):
        if not re.fullmatch(r"region\d+", name):
            continue
        r = {"name": name, "mode": read("%s/%s/mode" % (base, name)),
             "size": int_any(read("%s/%s/size" % (base, name), "0")) or 0,
             "memdevs": [], "dax": []}
        i = 0
        while True:
            target = read("%s/%s/target%d" % (base, name, i))
            if target is None:
                break
            m = re.fullmatch(r"decoder(\d+)\.\d+", target)
            if m and m.group(1) in endpoints:
                r["memdevs"].append(endpoints[m.group(1)])
            i += 1
        if not r["memdevs"] and i == 1 and len(devs) == 1:
            r["memdevs"].append(devs[0]["name"])
        rnum = name[len("region"):]
        dax_dir = "%s/%s/dax_region%s" % (base, name, rnum)
        for d in listdir(dax_dir):
            if re.fullmatch(r"dax\d+\.\d+", d):
                r["dax"].append({
                    "name": d,
                    "size": int_any(read("%s/%s/size" % (dax_dir, d), "0")) or 0,
                    "driver": link_name("/sys/bus/dax/devices/%s/driver" % d),
                    "targetNode": int_any(read("%s/%s/target_node" % (dax_dir, d))),
                })
        out.append(r)
    return out


def mappers():
    """Return the processes of pods that map a dax device."""
    out = []
    me = str(os.getpid())
    for pid in listdir("/proc"):
        if not pid.isdigit() or pid == me:
            continue
        cg = read("/proc/%s/cgroup" % pid, "")
        m = POD_UID.search(cg or "")
        if not m:
            continue
        try:
            with open(path("/proc/%s/maps" % pid)) as f:
                maps = f.read()
        except OSError:
            continue
        seen = {}
        for line in maps.splitlines():
            parts = line.split()
            if len(parts) >= 6 and re.fullmatch(r"/dev/dax\d+\.\d+", parts[5]):
                dev = parts[5][len("/dev/"):]
                perms = parts[1]
                if "w" in perms or dev not in seen:
                    seen[dev] = perms
        for dev, perms in seen.items():
            out.append({"pid": int(pid), "comm": read("/proc/%s/comm" % pid, "?"),
                        "podUID": m.group(1).replace("_", "-"), "dax": dev, "perms": perms})
    return out


def node(errors):
    try:
        devs, endpoints = memdevs()
        return {"hostname": read("/proc/sys/kernel/hostname", ""), "memdevs": devs,
                "regions": regions(endpoints, devs), "mappers": mappers()}
    except Exception as e:   # the views show it, the probe must not die
        errors.append("node: %r" % e)
        return None


def read_bytes(serial, length, errors):
    serial = int_any(serial)
    devs, endpoints = memdevs()
    names = [d["name"] for d in devs if int_any(d["serial"]) == serial]
    if not names:
        return {"error": "no memdev with serial 0x%x" % (serial or 0)}
    for r in regions(endpoints, devs):
        if names[0] in r["memdevs"] and r["dax"]:
            dax = r["dax"][0]
            try:
                fd = os.open(path("/dev/" + dax["name"]), os.O_RDONLY)
                try:
                    size = os.fstat(fd).st_size or (2 << 20)
                    m = mmap.mmap(fd, min(2 << 20, size), mmap.MAP_SHARED, mmap.PROT_READ)
                    data = bytes(m[:length])
                    m.close()
                finally:
                    os.close(fd)
            except OSError as e:
                return {"memdev": names[0], "region": r["name"], "dax": dax["name"], "error": str(e)}
            return {"memdev": names[0], "region": r["name"], "dax": dax["name"], "hex": data.hex()}
    return {"memdev": names[0], "error": "no dax device"}


def main():
    global ROOT
    args = sys.argv[1:]
    opts = {"--k8s": None, "--ns": "default", "--bytes": None, "--len": "256", "--root": ""}
    flags = set()
    i = 0
    while i < len(args):
        a = args[i]
        if a in opts and i + 1 < len(args):
            opts[a] = args[i + 1]
            i += 2
        elif a == "--node":
            flags.add(a)
            i += 1
        else:
            sys.exit("probe.py: unknown argument %s" % a)
    ROOT = opts["--root"]
    errors, out = [], {}
    threads = []
    if opts["--k8s"]:
        def run_k8s():
            out["k8s"] = k8s([k for k in opts["--k8s"].split(",") if k], opts["--ns"], errors)
        t = threading.Thread(target=run_k8s)
        t.start()
        threads.append(t)
    if "--node" in flags:
        out["node"] = node(errors)
    if opts["--bytes"]:
        try:
            out["bytes"] = read_bytes(opts["--bytes"], int(opts["--len"]), errors)
        except Exception as e:
            errors.append("bytes: %r" % e)
    for t in threads:
        t.join()
    out["errors"] = errors
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
