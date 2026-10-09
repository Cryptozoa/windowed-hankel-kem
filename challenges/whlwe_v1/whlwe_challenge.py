"""
Windowed Hankel LWE challenge, version 1: shared definitions (see README.md).

Every instance is b = A s + e mod q with q = 4096 and s, e drawn from CBD_2, where A is either the Hankel
matrix H_m(a) (A[i][j] = a[i + j]) or, for the uniform twin, a uniform m x n matrix. The public matrix is
derived from the instance name alone, so that nobody can choose it; the secret and error come from a
private master seed and are committed to by a hash.
"""

import hashlib
import json
import math
import os

import numpy as np

VERSION = "WHLWE-challenge-v1"
Q = 4096
SIZES = (64, 96, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640)
KINDS = ("hankel", "uniform")
HERE = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(HERE, "instances")


def samples(n: int) -> int:
    """m = 1.2 n, the ratio of the KEM's public key (768 / 640)."""
    return round(1.2 * n)


def name(n: int, kind: str) -> str:
    return f"whlwe-v1-n{n:04d}-{kind}"


def shake(data: bytes, nbytes: int) -> bytes:
    return hashlib.shake_256(data).digest(nbytes)


def public_seed(inst: str) -> bytes:
    return hashlib.sha256(f"{VERSION}/public/{inst}".encode()).digest()


def public_matrix(n: int, m: int, kind: str, seed: bytes) -> np.ndarray:
    """SHAKE256(seed) read as little-endian 16-bit words mod q: n + m - 1 entries a (Hankel, A[i][j] = a[i + j])
    or m n entries in row-major order (uniform)."""
    count = n + m - 1 if kind == "hankel" else m * n
    words = np.frombuffer(shake(seed, 2 * count), dtype="<u2").astype(np.int64) % Q
    if kind == "hankel":
        return np.array([[words[i + j] for j in range(n)] for i in range(m)], dtype=np.int64)
    return words.reshape(m, n)


def cbd2(buf: bytes) -> np.ndarray:
    """One CBD_2 sample per byte, from its four low bits (as in the KEM)."""
    b = np.frombuffer(buf, dtype=np.uint8).astype(np.int64)
    return ((b & 1) + ((b >> 1) & 1)) - (((b >> 2) & 1) + ((b >> 3) & 1))


def secret_and_error(master: bytes, inst: str, n: int, m: int):
    noise = cbd2(shake(master + f"{VERSION}/secret/{inst}".encode(), n + m))
    return noise[:n], noise[n:]


def commitment(inst: str, s) -> str:
    """SHA-256 of the domain string, the instance name and s as signed bytes."""
    data = f"{VERSION}/commit/{inst}/".encode() + bytes(int(x) & 0xFF for x in s)
    return hashlib.sha256(data).hexdigest()


def master_commitment(master: bytes) -> str:
    return hashlib.sha256(f"{VERSION}/master/".encode() + master).hexdigest()


def load(inst_or_path: str) -> dict:
    path = inst_or_path if inst_or_path.endswith(".json") else os.path.join(INSTANCE_DIR, inst_or_path + ".json")
    with open(path) as f:
        return json.load(f)


def check(instance: dict, s) -> dict:
    """Check a candidate secret: the residual b - A s mod q (centered) and the commitment."""
    n, m = instance["n"], instance["m"]
    s = np.array([int(x) for x in s], dtype=np.int64)
    if s.shape != (n,):
        return {"ok": False, "reason": f"expected {n} coordinates, got {s.shape[0]}"}
    A = public_matrix(n, m, instance["kind"], bytes.fromhex(instance["public_seed"]))
    r = (np.array(instance["b"], dtype=np.int64) - A @ s) % Q
    r = np.where(r >= Q // 2, r - Q, r)
    small = bool(np.all(np.abs(r) <= 2) and np.all(np.abs(s) <= 2))
    committed = commitment(instance["name"], s) == instance["secret_commitment"]
    return {"ok": committed, "matches_commitment": committed, "residual_in_cbd2_range": small,
            "residual_norm": float(math.sqrt(float(r @ r)))}
