#!/usr/bin/env python3
"""
Known-answer tests for the candidate Category 3 and 5 sets, WH-936 and WH-1208 (paper, Appendix D).

Same format and deterministic SHAKE-256 DRBG construction as WINDOWED_HANKEL_640_RESEARCH_v2 (custom
fixtures, not NIST DRBG vectors), with the set name in the DRBG seed. Vectors are produced by the
parameterized reference hankel_kem/generic.py: keygen(seed[:32]), encaps(pk, entropy).

  python3 PQCgenKAT_hankel_sets.py generate   writes WINDOWED_HANKEL_{936,1208}_v1.{req,rsp}
                                              (refuses to overwrite existing files)
  python3 PQCgenKAT_hankel_sets.py validate   checks every vector against the generic reference
                                              and, when built, the native implementation
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from hankel_kem import generic as g  # noqa: E402

OUT_DIR = os.path.join(os.path.dirname(__file__), "test_vectors")
SETS = {"WH-936": "WINDOWED_HANKEL_936_v1", "WH-1208": "WINDOWED_HANKEL_1208_v1"}
NUM_VECTORS = 15


class DeterministicDRBG:
    """Custom deterministic SHAKE-256 stream (as in PQCgenKAT_hankel.py)."""

    def __init__(self, entropy_seed: bytes):
        self.state = bytearray(entropy_seed)
        self.counter = 0

    def random_bytes(self, num_bytes: int) -> bytes:
        h = hashlib.shake_256(self.state + self.counter.to_bytes(8, "big"))
        self.counter += 1
        return h.digest(num_bytes)


def generate():
    for name, prefix in SETS.items():
        p = g.PROFILES[name]
        req_path, rsp_path = (os.path.join(OUT_DIR, prefix + ext) for ext in (".req", ".rsp"))
        if os.path.exists(req_path) or os.path.exists(rsp_path):
            raise FileExistsError(f"{prefix} fixtures already exist; not overwriting")
        drbg = DeterministicDRBG(bytes(range(48)) + b"_hankel_kat_seed_v1_" + name.encode())
        header = (f"# Windowed-Hankel {name} candidate set v1\n"
                  f"# Custom SHAKE deterministic fixtures; not official NIST vectors\n"
                  f"# n={p.n}, W={p.w}, q={p.q}, eta={p.eta}, domain string {p.domain.decode()!r}\n"
                  f"# Wire Sizes: PK={p.pk_bytes} Bytes, CT={p.ct_bytes} Bytes, SK={p.sk_bytes} Bytes\n\n")
        with open(req_path, "x") as req, open(rsp_path, "x") as rsp:
            req.write(header)
            rsp.write(header)
            for count in range(NUM_VECTORS):
                seed, entropy = drbg.random_bytes(48), drbg.random_bytes(32)
                pk, sk = g.keygen(p, seed[:32])
                ct, ss = g.encaps(p, pk, entropy)
                assert g.decaps(p, ct, sk) == ss
                req.write(f"count = {count}\nseed = {seed.hex().upper()}\nentropy = {entropy.hex().upper()}\n"
                          "pk =\nsk =\nct =\nss =\n\n")
                rsp.write(f"count = {count}\nseed = {seed.hex().upper()}\nentropy = {entropy.hex().upper()}\n"
                          f"pk = {pk.hex().upper()}\nsk = {sk.hex().upper()}\nct = {ct.hex().upper()}\n"
                          f"ss = {ss.hex().upper()}\n\n")
        print(f"[OK] {prefix}: {NUM_VECTORS} vectors")


def parse(path):
    vectors, cur = [], {}
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        cur[k] = v
        if k == "ss":
            vectors.append(cur)
            cur = {}
    return vectors


def validate() -> bool:
    try:
        from hankel_kem import native
    except Exception:  # pragma: no cover
        native = None
    ok = True
    for name, prefix in SETS.items():
        p = g.PROFILES[name]
        vectors = parse(os.path.join(OUT_DIR, prefix + ".rsp"))
        impls = [("reference", lambda s: g.keygen(p, s), lambda pk, e: g.encaps(p, pk, e),
                  lambda c, sk: g.decaps(p, c, sk))]
        if native is not None and native.available(name):
            impls.append(("native", lambda s: native.keygen(s, name), lambda pk, e: native.encaps(pk, e, name),
                          lambda c, sk: native.decaps(c, sk, name)))
        for label, kg, enc, dec in impls:
            good = 0
            for v in vectors:
                seed, ent = bytes.fromhex(v["seed"]), bytes.fromhex(v["entropy"])
                pk, sk = kg(seed[:32])
                ct, ss = enc(pk, ent)
                match = (pk.hex().upper(), sk.hex().upper(), ct.hex().upper(), ss.hex().upper()) == \
                        (v["pk"], v["sk"], v["ct"], v["ss"]) and dec(ct, sk) == ss
                good += match
            ok &= good == len(vectors) == NUM_VECTORS
            print(f"[{'PASS' if good == len(vectors) else 'FAIL'}] {prefix} ({label}): {good}/{len(vectors)} vectors bit-exact")
    return ok


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "validate"
    if mode == "generate":
        generate()
    else:
        sys.exit(0 if validate() else 1)
