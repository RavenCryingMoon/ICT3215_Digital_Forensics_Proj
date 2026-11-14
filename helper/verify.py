#!/usr/bin/env python3
# verify.py — compare Cartographer's dumped map contents against planter ground truth.
#
# This is a test harness, not part of the recovery code.
#
# Usage:
#   1. Capture the planter's ground truth while it runs:
#        sudo ./plant_maps | tee truth.txt      (Ctrl+C after you've acquired the image)
#   2. Acquire the image and dump it with the plugin into an output dir:
#        vol.py -s ../symbols -f ../image.lime -o ../out linux.bpf_listmaps.MapList --dump
#   3. Verify:
#        python3 verify.py truth.txt ../out
#
# Exit code 0 if every planted map matched, 1 otherwise — so it also works in CI.

import ast
import glob
import json
import os
import re
import sys


def parse_truth(path):
    """Return {id: {"name": str, "entries": {key_hex: value_hex}, "empty": bool}}."""
    truth = {}
    head = re.compile(r"map=(\S+)\s+id=(\d+)")
    for raw in open(path):
        line = raw.strip()
        if not line.startswith("TRUTH"):
            continue
        h = head.search(line)
        if not h:
            continue
        name, mid = h.group(1), int(h.group(2))
        rec = truth.setdefault(mid, {"name": name, "entries": {}, "empty": False})
        if "(empty)" in line:
            rec["empty"] = True
            continue
        k = re.search(r"key=([0-9a-fA-F]+)", line)
        v = re.search(r"value=([0-9a-fA-F]+)", line)
        if k and v:
            rec["entries"][k.group(1).lower()] = v.group(1).lower()
    return truth


def _norm(s):
    """Turn a dumped repr into something comparable: bytes -> hex, int -> str.

    Per-CPU maps dump their value as a dict {cpu: bytes}; that comes back as
    {cpu: value_hex} so every CPU copy can be checked individually.
    """
    s = s.strip()
    try:
        val = ast.literal_eval(s)       # handles b'...' byte-strings and {cpu: b'...'}
        if isinstance(val, bytes):
            return val.hex()
        if isinstance(val, int):        # array indices come out as plain ints
            return str(val)
        if isinstance(val, dict):       # per-CPU: {cpu: bytes} -> {cpu: value_hex}
            return {k: (v.hex() if isinstance(v, bytes) else str(v))
                    for k, v in val.items()}
    except (ValueError, SyntaxError):
        pass
    return s


def parse_dump(path):
    """Return {normalized_key: value_hex} for one .map_<offset>_<id> file."""
    with open(path) as f:
        data = json.load(f)
    return {_norm(k): _norm(v) for k, v in data.items()}


def dump_id(path):
    m = re.search(r"_(\d+)$", os.path.basename(path))
    return int(m.group(1)) if m else None


def _matches(rv, val_hex):
    """Does one recovered value equal the planted value?

    For a per-CPU map rv is a dict {cpu: value_hex}; it matches only if every
    CPU copy equals the planted value.
    """
    if rv is None:
        return False
    if isinstance(rv, dict):
        return len(rv) > 0 and all(h == val_hex for h in rv.values())
    return rv == val_hex


def found(recovered, key_hex, val_hex):
    """Does the recovered dict contain this planted (key, value)?"""
    # hash family: key stored as raw bytes, compared as hex
    if _matches(recovered.get(key_hex), val_hex):
        return True
    # array: dumped key is the index; the planter recorded it as a little-endian u32
    try:
        idx = int.from_bytes(bytes.fromhex(key_hex), "little")
        if _matches(recovered.get(str(idx)), val_hex):
            return True
    except ValueError:
        pass
    return False


def main():
    if len(sys.argv) != 3:
        print("usage: verify.py TRUTH.txt OUTDIR")
        sys.exit(2)

    truth = parse_truth(sys.argv[1])
    outdir = sys.argv[2]

    dumps = {}
    for path in glob.glob(os.path.join(outdir, ".map_*")) + glob.glob(
        os.path.join(outdir, "*map_*")
    ):
        mid = dump_id(path)
        if mid is not None:
            dumps[mid] = parse_dump(path)

    print(f"{'ID':>4}  {'NAME':<16} {'EXPECTED':>8} {'MATCHED':>7}  RESULT")
    all_ok = True
    for mid in sorted(truth):
        t = truth[mid]
        recovered = dumps.get(mid, {})
        if t["empty"]:
            ok = (len(recovered) == 0)
            exp_disp, matched_disp = "(empty)", "-"
        else:
            exp = t["entries"]
            matched = sum(1 for k, v in exp.items() if found(recovered, k, v))
            ok = (matched == len(exp))
            exp_disp, matched_disp = str(len(exp)), str(matched)
        all_ok = all_ok and ok
        print(f"{mid:>4}  {t['name']:<16} {exp_disp:>8} {matched_disp:>7}  "
              f"{'PASS' if ok else 'FAIL'}")

    print()
    print("ALL PLANTED MAPS RECOVERED" if all_ok else "SOME MAPS FAILED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
