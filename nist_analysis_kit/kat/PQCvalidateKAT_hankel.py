#!/usr/bin/env python3
"""
Local Known Answer Test (KAT) Validator for Windowed Hankel LWE KEM
======================================================================
Validates versioned research .rsp response files:
  1. Validates bit-exact reproducibility of pk and sk from seed.
  2. Executes decapsulation on each vector to confirm exact shared secret ss.
  3. Checks encapsulation when the fixture supplies entropy.
  4. Validates implicit rejection on tampered ciphertext.
These custom fixtures do not establish NIST compliance or security strength.

Usage:
    python3 nist_analysis_kit/kat/PQCvalidateKAT_hankel.py [rsp_file ...]

With no arguments the current research fixtures (RESEARCH_v2) are validated. Each file given on
the command line is validated in turn; the exit status is non-zero if any file fails.
"""

import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from hankel_kem_wrapper import hankel_kem_keygen, hankel_kem_encaps, hankel_kem_decaps

DEFAULT_RSP_PATH = os.path.join(os.path.dirname(__file__), "test_vectors", "WINDOWED_HANKEL_640_RESEARCH_v2.rsp")

# Fixture files retained for provenance that the current implementation is not expected to reproduce.
HISTORICAL_FIXTURES = {
    "WINDOWED_HANKEL_640_NIST1.rsp": (
        "historical fixture generated before the e2 error term was added to v = K_bob + Encode(m) + e2; "
        "its ciphertexts and shared secrets are expected to differ from the current implementation "
        "(keys still match). Retained for provenance only."
    ),
}


def fixture_name(filepath: str) -> str:
    """Profile name from the first header comment of an .rsp file (falls back to the file name)."""
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                return line.lstrip("#").strip()
            if line:
                break
    return os.path.basename(filepath)

def parse_rsp_file(filepath: str):
    vectors = []
    current = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                current[k] = v
                if k == "ss":
                    vectors.append(current)
                    current = {}
    if current:
        raise ValueError(f"Incomplete record at end of KAT file {filepath}: {list(current.keys())}")
    return vectors


def validate_kat_hankel(rsp_path: str = None) -> bool:
    if rsp_path is None:
        rsp_path = DEFAULT_RSP_PATH

    if not os.path.exists(rsp_path):
        print(f"[!] KAT response file not found: {rsp_path}")
        return False

    alg_name = fixture_name(rsp_path)
    vectors = parse_rsp_file(rsp_path)
    print(f"[*] Validating {len(vectors)} local KAT vectors for {alg_name}")
    print(f"    file: {rsp_path}")
    note = HISTORICAL_FIXTURES.get(os.path.basename(rsp_path))
    if note:
        print(f"    note: {note}")

    all_passed = True

    for i, vec in enumerate(vectors):
        count = int(vec["count"])
        seed = bytes.fromhex(vec["seed"])
        pk_expected = bytes.fromhex(vec["pk"])
        sk_expected = bytes.fromhex(vec["sk"])
        ct_expected = bytes.fromhex(vec["ct"])
        ss_expected = bytes.fromhex(vec["ss"])

        # 1. Deterministic KeyGen reproducibility
        seed_key = seed[:32]
        pk_re, sk_re = hankel_kem_keygen(seed=seed_key)
        if pk_re != pk_expected or sk_re != sk_expected:
            print(f"    [FAIL] Vector {count}: KeyGen reproducibility mismatch!")
            all_passed = False
            continue

        if "entropy" in vec:
            ct_re, ss_re = hankel_kem_encaps(pk_re, entropy=bytes.fromhex(vec["entropy"]))
            if ct_re != ct_expected or ss_re != ss_expected:
                print(f"    [FAIL] Vector {count}: Encapsulation reproducibility mismatch!")
                all_passed = False
                continue

        # 2. Decapsulation correctness
        ss_dec = hankel_kem_decaps(ct_expected, sk_expected)
        if ss_dec != ss_expected:
            print(f"    [FAIL] Vector {count}: Decapsulation shared secret mismatch!")
            all_passed = False
            continue

        # 3. Active tamper verification (Implicit Rejection)
        ct_tampered = bytearray(ct_expected)
        ct_tampered[25] ^= 0x01
        ss_reject = hankel_kem_decaps(bytes(ct_tampered), sk_expected)
        if ss_reject == ss_expected or len(ss_reject) != 32:
            print(f"    [FAIL] Vector {count}: Tampered ciphertext failed implicit rejection!")
            all_passed = False
            continue

        if (count + 1) % 5 == 0 or (count + 1) == len(vectors):
            print(f"    [+] Verified KAT vector {count + 1}/{len(vectors)} [Bit-Exact + Implicit Reject Verified]")

    if all_passed:
        print(f"\n[PASS] All {len(vectors)} local KAT vectors for {alg_name} match!")
        return True
    else:
        print(f"\n[FAIL] One or more local KAT vectors failed verification for {alg_name}!")
        return False


if __name__ == "__main__":
    paths = sys.argv[1:] or [DEFAULT_RSP_PATH]
    results = [validate_kat_hankel(p) for p in paths]
    sys.exit(0 if all(results) else 1)
