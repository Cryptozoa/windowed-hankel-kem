"""Small local benchmark for selectable Hankel research backends.

Verification precedes measurement. Timed calls contain no verification, tracing,
or allocation diagnostics. Results describe this machine and fixture only; they
do not assess security, decryption-failure probability, or constant-time behavior.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import sys
import time

import numpy as np

import hankel_kem_core as core
import hankel_kem_wrapper as wire


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return number


def handshake(backend, seed, entropy):
    pk, sk = wire.hankel_kem_keygen(seed, backend=backend)
    ct, sender = wire.hankel_kem_encaps(pk, entropy, backend=backend)
    receiver = wire.hankel_kem_decaps(ct, sk, backend=backend)
    return pk, sk, ct, sender, receiver


def measure(function, pool, warmup):
    for inputs in pool[:warmup]:
        function(inputs)
    samples = []
    for inputs in pool[warmup:]:
        start = time.perf_counter_ns()
        function(inputs)
        samples.append(time.perf_counter_ns() - start)
    mean = statistics.mean(samples)
    return {"median_us": statistics.median(samples) / 1000,
            "mean_us": mean / 1000,
            "stddev_us": statistics.pstdev(samples) / 1000,
            "p99_us": float(np.percentile(samples, 99)) / 1000,
            "operations_per_second": 1_000_000_000 / mean,
            "samples_ns": samples, "repeats": len(samples), "warmup": warmup}


def source_hashes():
    root = Path(__file__).resolve().parent
    files = {root / "hankel_kem_core.py", root / "hankel_kem_wrapper.py", Path(__file__).resolve()}
    for directory in ("hankel", "hankel_kem"):
        package = root / directory
        if package.is_dir():
            files.update(package.rglob("*.py"))
    library = root / "libhankel_kem_neon.dylib"
    if library.exists():
        files.add(library)
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backends", nargs="+", default=None,
                        help="Explicit usable backends; default: reference convolution and neon if available")
    parser.add_argument("--warmup", type=nonnegative_int, default=3)
    parser.add_argument("--repeats", type=positive_int, default=9, help="Measured calls per kernel")
    parser.add_argument("--handshake-repeats", type=positive_int, default=5)
    parser.add_argument("--json", type=Path, help="Save JSON to a new path; existing evidence is never overwritten")
    args = parser.parse_args(argv)
    available = tuple(core.available_backends())
    backends = args.backends or [b for b in ("reference", "convolution", "neon") if b in available]
    if len(set(backends)) != len(backends):
        parser.error("backend names must be distinct")
    if any(b not in available or b == "auto" for b in backends):
        parser.error("choose concrete usable backends from: " + ", ".join(b for b in available if b != "auto"))
    if args.json is not None and args.json.exists():
        parser.error("JSON path already exists; choose a new evidence path")

    hashes_before = source_hashes()
    # At least the first10% of calls are discarded. Each operation consumes a
    # distinct freshly generated workload; identical pools are shared by backends.
    kernel_warmup = max(args.warmup, math.ceil(args.repeats / 9))
    handshake_warmup = max(args.warmup, math.ceil(args.handshake_repeats / 9))
    kernel_pool = [
        (core.expand_public_sequence_a(os.urandom(32)),
         core.sample_cbd2_from_bytes(os.urandom(core.N), core.N),
         core.expand_public_sequence_a(os.urandom(32), core.M_LEN))
        for _ in range(kernel_warmup + args.repeats)
    ]
    handshake_pool = [(os.urandom(64), os.urandom(32))
                      for _ in range(handshake_warmup + args.handshake_repeats)]

    # Unmeasured verification is deliberately separate from the timed calls.
    for a, x, y in kernel_pool:
        expected_forward = core.hankel_forward_multiply(a, x, backend="reference")
        expected_project = core.hankel_window_project(x, y, backend="reference")
        for backend in backends:
            np.testing.assert_array_equal(core.hankel_forward_multiply(a, x, backend=backend), expected_forward)
            np.testing.assert_array_equal(core.hankel_window_project(x, y, backend=backend), expected_project)
    fixture_hashes = []
    for seed, entropy in handshake_pool:
        expected = handshake("reference", seed, entropy)
        if expected[3] != expected[4]:
            raise RuntimeError("reference fixture failed its roundtrip")
        for backend in backends:
            if handshake(backend, seed, entropy) != expected:
                raise RuntimeError(f"{backend} does not preserve the fixture outputs")
        fixture_hashes.append({"keygen_seed_sha256": hashlib.sha256(seed).hexdigest(),
                               "encapsulation_entropy_sha256": hashlib.sha256(entropy).hexdigest(),
                               "wire_output_sha256": [hashlib.sha256(value).hexdigest() for value in expected]})

    measured = {}
    for backend in backends:
        measured[backend] = {
            "forward": measure(lambda inputs: core.hankel_forward_multiply(inputs[0], inputs[1], backend=backend), kernel_pool, kernel_warmup),
            "projection": measure(lambda inputs: core.hankel_window_project(inputs[1], inputs[2], backend=backend), kernel_pool, kernel_warmup),
            "full_handshake": measure(lambda inputs: handshake(backend, *inputs), handshake_pool, handshake_warmup),
        }
    hashes_after = source_hashes()
    if hashes_before != hashes_after:
        raise RuntimeError("implementation changed during measurement; results are not retained")
    report = {
        "scope": "Local kernel and complete research-KEM handshake latency on fresh CSPRNG workloads; generation and output verification precede timing.",
        "limits": "Small descriptive sample on one machine, without pinned-core or frequency-lock controls. No security, DFR, side-channel, or portable performance conclusion.",
        "runtime": {"python": sys.version, "platform": platform.platform(), "numpy": np.__version__},
        "parameters": {"q": core.Q, "n": core.N, "window": core.W, "eta": core.ETA},
        "available_backends": available,
        "verified_outputs_equal": True,
        "source_hashes": hashes_before,
        "sources_unchanged": True,
        "workload": {"sampling": "os.urandom; public sequences from SHAKE-256; CBD2 secret vectors; same input pool per backend",
                     "randomness_and_verification_outside_timing": True,
                     "requested_warmup": args.warmup,
                     "kernel_pool_sha256": [hashlib.sha256(a.tobytes() + x.tobytes() + y.tobytes()).hexdigest()
                                              for a, x, y in kernel_pool],
                     "handshake_fixtures": fixture_hashes},
        "measurements": measured,
    }
    payload = json.dumps(report, indent=2) + "\n"
    if args.json is not None:
        with args.json.open("x") as handle:
            handle.write(payload)
        print("backend      operation        median_us    mean_us     std_us     p99_us      ops/s")
        for backend, operations in measured.items():
            for operation, stats in operations.items():
                print(f"{backend:<12} {operation:<16} {stats['median_us']:10.2f} "
                      f"{stats['mean_us']:10.2f} {stats['stddev_us']:10.2f} "
                      f"{stats['p99_us']:10.2f} {stats['operations_per_second']:10.1f}")
        print(f"Artifact: {args.json.resolve()}")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
