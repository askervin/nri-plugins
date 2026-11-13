#!/usr/bin/env python3
"""Write a sample of the views from the running demo: testdata/<NAME>/.

Usage: record-sample.py NAME

Collects now what the views T2, T3, T4 and T6 collect (views.collect) and
writes it the way the hand-made samples are (make-samples.py): vm2.json
(the Kubernetes objects and the node), vm1.json and vm0.json (the
nodes), pool.json (the pool server's device and its file system), and
state.env, the state of demo setup with the VM directories under
/nonexistent (a sample never reaches a VM) and without the pids and logs
of the host.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin"))
import common   # noqa: E402
import views    # noqa: E402

STATE_KEYS = ("DEMO_CASE", "DEMO_FSTYPE", "VM2_DIR", "VM1_DIR", "VM0_DIR", "VM2_NODE", "VM1_NODE", "VM0_NODE", "NS", "SERIAL",
              "POOL_DEVICE", "POOL_URL", "DEMO_LLM_MODEL", "DEMO_LLM_ACCESS", "DEMO_LLM_LATENCY", "LLM_MODEL_FILE",
              "LLM_DEVICE_SIZE")


def main():
    if len(sys.argv) != 2 or not sys.argv[1].replace("-", "").isalnum():
        sys.exit(__doc__)
    state = common.load_state()
    if state is None:
        sys.exit("demo not set up")
    out = {}
    for view in ("t2", "t3", "t4", "t6"):
        for key, doc in views.collect(view, state).items():
            if key == "partial":
                continue
            have = out.setdefault(key, {})
            for k, v in doc.items():
                if k == "k8s":
                    have.setdefault("k8s", {}).update(v)
                elif k != "errors":
                    have[k] = v
    sdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), sys.argv[1])
    os.makedirs(sdir, exist_ok=True)
    for key, doc in out.items():
        with open(os.path.join(sdir, key + ".json"), "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
    with open(os.path.join(sdir, "state.env"), "w") as f:
        f.write("# state of demo setup %s, recorded from a live demo (record-sample.py)\n" % state.get("DEMO_CASE"))
        for k in STATE_KEYS:
            if state.get(k) is None:
                continue
            v = state[k]
            if k.endswith("_DIR"):
                v = "/nonexistent/" + os.path.basename(v)
            f.write("%s=%s\n" % (k, v))
    print("record-sample: %s: %s" % (sdir, " ".join(sorted(out))))


if __name__ == "__main__":
    main()
