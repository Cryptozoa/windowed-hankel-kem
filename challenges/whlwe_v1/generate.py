#!/usr/bin/env python3
"""
Generate the Windowed Hankel LWE challenge instances (run once, by the maintainer).

  python3 generate.py --new-master PATH   create a fresh 32-byte master seed at PATH (outside the repository,
                                          mode 0600), then generate the instances
  python3 generate.py --master PATH       generate the instances from an existing master seed
  python3 generate.py --master PATH --check   regenerate everything in memory and compare with the
                                          published files (consistency check; writes nothing)

The master seed never enters the repository; only its commitment (index.json) does. Existing instance
files are never overwritten.
"""

import argparse
import json
import os
import secrets
import sys

import numpy as np

import whlwe_challenge as wc


def read_master(path: str) -> bytes:
    with open(path) as f:
        master = bytes.fromhex(f.read().strip())
    if len(master) != 32:
        sys.exit("master seed must be 32 bytes (64 hex characters)")
    return master


def build(master: bytes):
    out = []
    for n in wc.SIZES:
        m = wc.samples(n)
        for kind in wc.KINDS:
            inst = wc.name(n, kind)
            seed = wc.public_seed(inst)
            A = wc.public_matrix(n, m, kind, seed)
            s, e = wc.secret_and_error(master, inst, n, m)
            b = (A @ s + e) % wc.Q
            out.append({
                "challenge": wc.VERSION, "name": inst, "kind": kind, "n": n, "m": m, "q": wc.Q,
                "secret_distribution": "CBD_2", "error_distribution": "CBD_2",
                "public_seed": seed.hex(),
                "b": [int(x) for x in b],
                "secret_commitment": wc.commitment(inst, s),
            })
    return out


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--new-master")
    g.add_argument("--master")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    repo = os.path.abspath(os.path.join(wc.HERE, "..", ".."))
    path = os.path.abspath(args.new_master or args.master)
    if path.startswith(repo + os.sep):
        sys.exit("refusing to keep the master seed inside the repository")
    if args.new_master:
        if os.path.exists(path):
            sys.exit(f"{path} exists; refusing to overwrite a master seed")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_bytes(32).hex() + "\n")
        print(f"new master seed written to {path} (mode 0600)")
    master = read_master(path)
    instances = build(master)
    index = {"challenge": wc.VERSION, "q": wc.Q, "sizes": list(wc.SIZES), "kinds": list(wc.KINDS),
             "master_commitment": wc.master_commitment(master),
             "instances": [i["name"] for i in instances]}

    if args.check:
        bad = 0
        for inst in instances:
            pub = wc.load(inst["name"])
            bad += pub != inst
        pub_index = json.load(open(os.path.join(wc.HERE, "index.json")))
        bad += pub_index != index
        print(f"{len(instances)} instances and index regenerated: {'all match' if not bad else f'{bad} differ'}")
        sys.exit(1 if bad else 0)

    os.makedirs(wc.INSTANCE_DIR, exist_ok=True)
    for inst in instances:
        p = os.path.join(wc.INSTANCE_DIR, inst["name"] + ".json")
        if os.path.exists(p):
            sys.exit(f"{p} exists; refusing to overwrite")
    for inst in instances:
        with open(os.path.join(wc.INSTANCE_DIR, inst["name"] + ".json"), "x") as f:
            json.dump(inst, f, indent=1)
            f.write("\n")
    with open(os.path.join(wc.HERE, "index.json"), "x") as f:
        json.dump(index, f, indent=1)
        f.write("\n")
    # self-check: the true secrets pass, perturbed ones do not
    for inst in instances:
        s, _ = wc.secret_and_error(master, inst["name"], inst["n"], inst["m"])
        assert wc.check(inst, s)["ok"]
        t = s.copy()
        t[0] = (t[0] + 1) if t[0] < 2 else (t[0] - 1)
        assert not wc.check(inst, t)["ok"]
    print(f"{len(instances)} instances written to {wc.INSTANCE_DIR}; master commitment {index['master_commitment']}")


if __name__ == "__main__":
    main()
