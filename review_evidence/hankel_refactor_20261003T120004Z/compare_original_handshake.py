"""Paired local comparison of pristine and refactored native Hankel handshakes.

This is a research implementation benchmark, not a security or constant-time
assessment. Fresh synthetic CSPRNG inputs are generated outside measurement.
Full-byte compatibility is checked in a separate phase before timed calls.
The JSON output is exclusive and retains inputs, samples, paired order, and hashes.
"""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import statistics
import sys
import time

import numpy as np


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ORIGINAL = ROOT / "review_evidence/hankel_architecture_e2080e22fe2d/input_snapshot"
ORIGINAL_HASHES = {
    "hankel_kem_core.py": "e2080e22fe2d23da7ce92eebd1b01860762cf77c948c65c6a511015529fb0f29",
    "hankel_kem_wrapper.py": "4fbbcbc83b37b08408bb526a391b04691b1c28f7db140e5e44a2b1f4e2090d95",
    "hankel_kem_neon.c": "cb1dca679899d210eefb8eeda01d884aa5cb6da3c0c0c7d249454b1253782c9d",
    "hankel_kem_neon.h": "06f016cf42bd9225220e89311664627d0feb3767aeb64f6858345392568b8557",
    "libhankel_kem_neon.dylib": "d20fdc18f5c9bce40772cc6b1536113d62a555c4392f4490589fe06a99cc2952",
}


def hashes(directory, names):
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in names}


def final_source_hashes():
    paths = [ROOT / name for name in (
        "hankel_kem_core.py", "hankel_kem_wrapper.py", "hankel_kem_neon.c",
        "hankel_kem_neon.h", "libhankel_kem_neon.dylib")]
    paths.extend(sorted((ROOT / "hankel_kem").rglob("*.py")))
    paths.append(Path(__file__).resolve())
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def load_isolated(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load retained module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def original_modules():
    suffix = os.urandom(8).hex()
    original_core = load_isolated(f"_hankel_pristine_core_{suffix}", ORIGINAL / "hankel_kem_core.py")
    previous = sys.modules.get("hankel_kem_core")
    sys.modules["hankel_kem_core"] = original_core
    try:
        original_wire = load_isolated(f"_hankel_pristine_wrapper_{suffix}", ORIGINAL / "hankel_kem_wrapper.py")
    finally:
        if previous is None:
            sys.modules.pop("hankel_kem_core", None)
        else:
            sys.modules["hankel_kem_core"] = previous
    if original_core._C_LIB is None:
        raise RuntimeError("Pristine baseline native library did not load; fallback is forbidden")
    return original_core, original_wire


def complete_handshake(wire, seed, entropy, backend=None):
    if backend is None:
        pk, sk = wire.hankel_kem_keygen(seed)
        ct, sender = wire.hankel_kem_encaps(pk, entropy)
        receiver = wire.hankel_kem_decaps(ct, sk)
    else:
        pk, sk = wire.hankel_kem_keygen(seed, backend=backend)
        ct, sender = wire.hankel_kem_encaps(pk, entropy, backend=backend)
        receiver = wire.hankel_kem_decaps(ct, sk, backend=backend)
    return pk, sk, ct, sender, receiver


def summarize(samples):
    return {
        "median_us": statistics.median(samples) / 1000,
        "mean_us": statistics.mean(samples) / 1000,
        "stddev_us": statistics.pstdev(samples) / 1000,
        "p99_us": float(np.percentile(samples, 99)) / 1000,
        "operations_per_second": 1_000_000_000 * len(samples) / sum(samples),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", required=True, type=Path, help="New JSON evidence path; existing files are never overwritten")
    parser.add_argument("--repeats", type=int, default=300, help="Measured paired handshakes, at least 300")
    parser.add_argument("--warmup", type=int, default=0, help="Additional requested warmup; raised to at least 10%% of all calls")
    args = parser.parse_args(argv)
    if args.repeats < 300 or args.warmup < 0:
        parser.error("repeats must be at least 300 and warmup nonnegative")
    if args.json.exists():
        parser.error("JSON evidence path already exists")
    warmup = max(args.warmup, math.ceil(args.repeats / 9))
    before_original = hashes(ORIGINAL, ORIGINAL_HASHES)
    if before_original != ORIGINAL_HASHES:
        raise RuntimeError("Pristine original snapshot hashes do not match the retained baseline")
    before_final = final_source_hashes()

    sys.path.insert(0, str(ROOT))
    import hankel_kem_core as final_core
    import hankel_kem_wrapper as final_wire
    if not final_core.is_native_loaded() or "neon" not in final_core.available_backends():
        raise RuntimeError("Refactored native library did not load; fallback is forbidden")
    original_core, original_wire = original_modules()
    if sys.modules["hankel_kem_core"] is not final_core:
        raise RuntimeError("Pristine wrapper loading did not restore the current module")
    original_symbol = ctypes.cast(original_core._C_LIB.hankel_neon_forward_mul, ctypes.c_void_p).value
    final_symbol = ctypes.cast(final_core.NATIVE_LIBRARY.hankel_neon_forward_mul, ctypes.c_void_p).value
    if original_symbol == final_symbol:
        raise RuntimeError("Both libraries resolve the same native function; distinct original/final artifacts are required")

    pool = []
    seen = set()
    for i in range(warmup + args.repeats):
        while True:
            seed, entropy = os.urandom(64), os.urandom(32)
            identity = seed + entropy
            if identity not in seen:
                seen.add(identity)
                break
        order = ("original", "refactor") if os.urandom(1)[0] & 1 else ("refactor", "original")
        pool.append((seed, entropy, order))

    # Separate untimed compatibility pass over every fresh workload.
    inputs = []
    for i, (seed, entropy, order) in enumerate(pool):
        original_outputs = complete_handshake(original_wire, seed, entropy)
        final_outputs = complete_handshake(final_wire, seed, entropy, "neon")
        if original_outputs != final_outputs or original_outputs[3] != original_outputs[4]:
            raise RuntimeError(f"Full-byte compatibility or roundtrip failed at workload {i}")
        inputs.append({
            "pool_index": i, "phase": "warmup" if i < warmup else "measured",
            "seed_hex": seed.hex(), "entropy_hex": entropy.hex(),
            "input_sha256": hashlib.sha256(seed + entropy).hexdigest(),
            "paired_order": order,
            "output_sha256": [hashlib.sha256(value).hexdigest() for value in original_outputs],
        })

    implementations = {
        "original": lambda seed, entropy: complete_handshake(original_wire, seed, entropy),
        "refactor": lambda seed, entropy: complete_handshake(final_wire, seed, entropy, "neon"),
    }
    measured = {"original": [], "refactor": []}
    pairs = []
    warmup_samples = []
    for i, (seed, entropy, order) in enumerate(pool):
        elapsed = {}
        for name in order:
            start = time.perf_counter_ns()
            implementations[name](seed, entropy)
            elapsed[name] = time.perf_counter_ns() - start
        if i >= warmup:
            for name in measured:
                measured[name].append(elapsed[name])
            pairs.append({"pool_index": i, "paired_order": order, **elapsed})
        else:
            warmup_samples.append({"pool_index": i, "paired_order": order, **elapsed})

    after_original = hashes(ORIGINAL, ORIGINAL_HASHES)
    after_final = final_source_hashes()
    stable = before_original == after_original and before_final == after_final
    # Retain raw evidence even if concurrent source changes invalidate the run.
    report = {
        "scope": "Local paired complete keygen+encaps+decaps comparison of the pristine original native implementation and final explicit-neon refactor.",
        "limits": "Descriptive measurements on this machine with uncontrolled scheduling/frequency; not security, DFR, side-channel, or portable performance evidence.",
        "valid_comparison": stable,
        "runtime": {"python": sys.version, "platform": platform.platform(), "numpy": np.__version__},
        "parameters": {"q": final_core.Q, "n": final_core.N, "window": final_core.W, "eta": final_core.ETA},
        "original_snapshot": str(ORIGINAL),
        "original_native_loaded": original_core._C_LIB is not None,
        "refactored_native_loaded": final_core.is_native_loaded(),
        "native_forward_symbol_addresses": {"original": original_symbol, "refactor": final_symbol},
        "distinct_native_symbols": True,
        "final_backend": "neon",
        "original_source_hashes_before": before_original,
        "original_source_hashes_after": after_original,
        "final_source_hashes_before": before_final,
        "final_source_hashes_after": after_final,
        "sources_unchanged": stable,
        "sampling": "Fresh unique os.urandom keygen seeds of 64 bytes and entropy of 32 bytes; identical per-pair inputs for both implementations; randomized paired order.",
        "verification": {"full_bytes_equal": True, "roundtrips_pass": True,
                         "workloads": len(pool), "outside_timing": True},
        "warmup_pairs": warmup,
        "measured_pairs": args.repeats,
        "stddev_definition": "Population standard deviation of measured samples",
        "inputs": inputs,
        "samples_ns": measured,
        "paired_samples": pairs,
        "discarded_warmup_samples": warmup_samples,
        "statistics": {name: summarize(values) for name, values in measured.items()},
        "paired_summary": {
            "median_original_over_refactor_ratio": statistics.median(a / b for a, b in zip(measured["original"], measured["refactor"])),
            "median_original_minus_refactor_us": statistics.median(a - b for a, b in zip(measured["original"], measured["refactor"])) / 1000,
            "pairs_refactor_faster": sum(b < a for a, b in zip(measured["original"], measured["refactor"])),
        },
    }
    with args.json.open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print("implementation   median_us    mean_us     std_us     p99_us      ops/s")
    for name, stats in report["statistics"].items():
        print(f"{name:<16} {stats['median_us']:10.2f} {stats['mean_us']:10.2f} "
              f"{stats['stddev_us']:10.2f} {stats['p99_us']:10.2f} {stats['operations_per_second']:10.1f}")
    print(f"Full-byte comparison passed for {len(pool)} workloads; source hashes stable: {stable}")
    print(f"Artifact: {args.json.resolve()}")
    return 0 if stable else 1


if __name__ == "__main__":
    raise SystemExit(main())
