#!/usr/bin/env python3
"""
Local Known Answer Test (KAT) Generator for Windowed Hankel LWE KEM
======================================================================
Generates versioned research .req and .rsp compatibility fixtures.
The custom SHAKE generator does not establish NIST compliance or security.

Mathematical Parameters:
  - Modulus q = 4096 (2^12)
  - Lattice Dimension n = 640
  - Window Size W = 128 (4-PAM -> 256-bit key)
  - Public Key: 1,196 Bytes (1.17 KB)
  - Ciphertext: 1,356 Bytes (1.32 KB)
  - Total Handshake: 2,552 Bytes (2.49 KB)
"""

import os
import sys
import hashlib

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from hankel_kem_wrapper import hankel_kem_keygen, hankel_kem_encaps, hankel_kem_decaps


class DeterministicDRBG:
    """Custom deterministic SHAKE-256 stream for reproducible local fixtures."""
    def __init__(self, entropy_seed: bytes = bytes(range(48))):
        self.state = bytearray(entropy_seed)
        self.counter = 0

    def random_bytes(self, num_bytes: int) -> bytes:
        h = hashlib.shake_256(self.state + self.counter.to_bytes(8, "big"))
        self.counter += 1
        return h.digest(num_bytes)


def generate_kat_hankel(num_vectors: int = 15, output_dir: str = None):
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), "test_vectors")
    os.makedirs(output_dir, exist_ok=True)

    file_prefix = "WINDOWED_HANKEL_640_RESEARCH_v2"
    alg_name = "Windowed-Hankel-LWE-640 research profile v2"

    req_path = os.path.join(output_dir, f"{file_prefix}.req")
    rsp_path = os.path.join(output_dir, f"{file_prefix}.rsp")
    if os.path.exists(req_path) or os.path.exists(rsp_path):
        raise FileExistsError("Fixture files already exist; choose a new output directory to preserve them")

    drbg = DeterministicDRBG(bytes(range(48)) + b"_hankel_kat_seed_v1")

    print(f"[*] Generating {num_vectors} local KAT vectors for {alg_name}...")

    with open(req_path, "x") as req_file, open(rsp_path, "x") as rsp_file:
        header = (
            f"# {alg_name}\n"
            f"# Custom SHAKE deterministic fixtures; not official NIST vectors\n"
            f"# Lattice Dimension n=640, W=128, q=4096, eta=2\n"
            f"# Primitive: Truncated Aperiodic Windowed Hankel LWE (Ring-Free)\n"
            f"# Wire Sizes: PK=1,196 Bytes, CT=1,356 Bytes, Total=2,552 Bytes (2.49 KB)\n\n"
        )
        req_file.write(header)
        rsp_file.write(header)

        for count in range(num_vectors):
            seed = drbg.random_bytes(48)
            msg_enc = drbg.random_bytes(32)

            # Write .req entry
            req_file.write(f"count = {count}\n")
            req_file.write(f"seed = {seed.hex().upper()}\n")
            req_file.write(f"entropy = {msg_enc.hex().upper()}\n")
            req_file.write("pk =\n")
            req_file.write("sk =\n")
            req_file.write("ct =\n")
            req_file.write("ss =\n\n")

            # Deterministic KeyGen
            seed_key = seed[:32]
            pk, sk = hankel_kem_keygen(seed=seed_key)

            # Deterministic Encapsulation
            ct, ss = hankel_kem_encaps(pk, entropy=msg_enc)

            # Verification Decapsulation
            ss_dec = hankel_kem_decaps(ct, sk)
            assert ss_dec == ss, f"KAT verification mismatch in {alg_name} vector {count}!"

            # Write .rsp entry
            rsp_file.write(f"count = {count}\n")
            rsp_file.write(f"seed = {seed.hex().upper()}\n")
            rsp_file.write(f"entropy = {msg_enc.hex().upper()}\n")
            rsp_file.write(f"pk = {pk.hex().upper()}\n")
            rsp_file.write(f"sk = {sk.hex().upper()}\n")
            rsp_file.write(f"ct = {ct.hex().upper()}\n")
            rsp_file.write(f"ss = {ss.hex().upper()}\n\n")

            print(f"    [+] Completed KAT vector {count + 1}/{num_vectors}")

    print(f"\n[PASS] Successfully generated local KAT files:")
    print(f"    - Request File  : {req_path}")
    print(f"    - Response File : {rsp_path}")


if __name__ == "__main__":
    generate_kat_hankel(num_vectors=15)
