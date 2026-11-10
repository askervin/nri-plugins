#!/usr/bin/env python3
"""The observations of the fixture pairs of mbt-observe.py.

Usage: observe-pairs.py MBT_OBSERVE DIR...

For each DIR, a fixture pair of the driver's document state.json and the
five views of it (preparedClaims.json, preparedClaimsInfo.json,
preparedPoolClaims.json, localDevices.json, leases.json), print one JSON
line {"dir": DIR, "views": OBS, "state": OBS, "errors": [...]}. OBS has
the parts "state" and "poolClaims" of a VM observation: in "views" as
the observer read them from the five views, reduced to the fields that
the model decodes; in "state" as MBT_OBSERVE derives them from
DIR/state.json; "errors" are the errors of MBT_OBSERVE.

Python 3 standard library only.
"""

import importlib.util
import json
import os
import sys

sys.dont_write_bytecode = True

# the fields of a use of a local memdev, a pool device and a lend in the
# observation
USE_KEYS = ("request", "region", "mode", "size", "dax")
POOL_DEVICE_KEYS = ("mode", "readOnly", "persistent", "blockDevice", "access", "path", "nodeMount", "loopDevice")
LEND_KEYS = ("lease", "pod", "container", "fsDir", "name", "mounts")


def load(path):
    """The module of the observer in path."""
    spec = importlib.util.spec_from_file_location("mbt_observe", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(path):
    """The JSON of path, None if it does not exist."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def serial_text(value):
    """0x<lower-case hex> of a serial: a number, or hex text."""
    if isinstance(value, int):
        return "0x%x" % value
    text = str(value).strip().lower()
    try:
        return "0x%x" % int(text, 16)
    except ValueError:
        return text


def keys(obj):
    return None if obj is None else sorted(obj)


def local_devices(obj):
    if obj is None:
        return None
    out = {"bootID": obj.get("bootID"), "devices": []}
    for d in obj.get("devices") or []:
        serial = d.get("serial")
        if serial is None and d.get("serialHex"):
            serial = int(str(d["serialHex"]), 16)
        claims = {}
        for uid, uses in (d.get("claims") or {}).items():
            claims[uid] = None if uses is None else [{k: u.get(k) for k in USE_KEYS} for u in uses]
        out["devices"].append({
            "serial": serial_text(serial) if serial is not None else None,
            "region": d.get("region") or "",
            "claims": claims,
        })
    return out


def leases(obj):
    if obj is None:
        return None
    claims = {uid: {"uid": c.get("uid")} for uid, c in (obj.get("claims") or {}).items()}
    out = {}
    for lid, l in (obj.get("leases") or {}).items():
        out[lid] = {"id": l.get("id"), "mode": l.get("mode"), "state": l.get("state"), "node": l.get("node"),
                    "pod": {"name": (l.get("pod") or {}).get("name")}}
    return {"claims": claims, "leases": out}


def pool_claims(obj):
    if obj is None:
        return {}
    out = {}
    for uid, pc in sorted(obj.items()):
        pc = pc or {}
        devs = []
        for d in pc.get("devices") or []:
            e = {k: d.get(k) for k in POOL_DEVICE_KEYS}
            e["serial"] = serial_text(d["serial"]) if d.get("serial") is not None else None
            devs.append(e)
        lend = pc.get("lend")
        if lend is not None:
            lend = {k: lend.get(k) for k in LEND_KEYS}
        out[uid] = {"claimName": pc.get("claimName"), "devices": devs, "lend": lend}
    return out


def from_views(d):
    """The parts as the observer read them from the views in d."""
    def view(name):
        return read(os.path.join(d, name))
    return {
        "state": {
            "prepared": keys(view("preparedClaims.json")),
            "info": keys(view("preparedClaimsInfo.json")),
            "pool": keys(view("preparedPoolClaims.json")),
            "localDevices": local_devices(view("localDevices.json")),
            "leases": leases(view("leases.json")),
        },
        "poolClaims": pool_claims(view("preparedPoolClaims.json")),
    }


def from_state(obs, d, errors):
    """The parts as the observer obs derives them from d/state.json."""
    obs.STATE_FILE = os.path.join(d, "state.json")
    doc, doc_read = obs.state_document(errors)
    return {
        "state": obs.driver_state(doc, errors),
        "poolClaims": obs.pool_claims(doc) if doc_read else None,
    }


def main():
    obs = load(sys.argv[1])
    for d in sys.argv[2:]:
        errors = []
        line = {"dir": d, "views": from_views(d), "state": from_state(obs, d, errors), "errors": errors}
        print(json.dumps(line, sort_keys=True))


if __name__ == "__main__":
    main()
