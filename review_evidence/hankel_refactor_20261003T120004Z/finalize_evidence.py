"""Retain the final implementation snapshot and summarize bounded local evidence."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def read(name):
    return json.loads((HERE / name).read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, data):
    with (HERE / name).open("x") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def main():
    raw = read("native_candidate/benchmark_unique.json")
    paired = read("original_vs_refactor_handshake.json")
    regressions = read("regressions.status.json")
    kat = read("kat_and_native_checks.json")
    sanitizer = read("native_sanitizer/combined_summary.json")
    assert regressions["success"] and regressions["test_count"] == 13
    assert kat["passed"] and all(kat["backends"].values())
    assert paired["valid_comparison"] and paired["verification"]["full_bytes_equal"]
    assert sanitizer["cases"]["arm64_neon"]["harness_result"]["pass"]
    assert read("retained_kat_diagnosis.json")["all_cases_confirmed"]
    files = [ROOT / name for name in (
        "hankel_kem_core.py", "hankel_kem_wrapper.py", "hankel_kem_neon.c",
        "hankel_kem_neon.h", "libhankel_kem_neon.dylib", "test_hankel_neon.py",
        "test_hankel_refactor.py", "test_hankel_kem_edge_cases.py",
        "benchmark_hankel_backends.py", "nist_analysis_kit/kat/PQCgenKAT_hankel.py",
        "nist_analysis_kit/kat/PQCvalidateKAT_hankel.py")]
    files += sorted((ROOT / "hankel_kem").glob("*.py"))
    vectors = ROOT / "nist_analysis_kit/kat/test_vectors"
    files += sorted(vectors.glob("WINDOWED_HANKEL_640_NIST1.*"))
    files += sorted(vectors.glob("WINDOWED_HANKEL_640_RESEARCH_v2.*"))
    current_hashes = {str(p.relative_to(ROOT)): sha(p) for p in files}
    snapshot = HERE / "final_snapshot"
    snapshot.mkdir()
    for path in files:
        target = snapshot / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        assert sha(target) == current_hashes[str(path.relative_to(ROOT))]
    extracted = Path("/private/tmp/hankel_extracted_codec_sampling_checks.json")
    if extracted.exists():
        with (HERE / "extracted_codec_sampling_checks.json").open("xb") as handle:
            handle.write(extracted.read_bytes())
    result = {
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "cwd": str(ROOT),
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": "Behavior-preserving Hankel research implementation refactor and measured native optimization",
        "changes": [
            "Separated frozen parameters, sampling, codec, arithmetic backends, checked operators, CPA equations, wire format and FO composition",
            "Preserved legacy entry points; added explicit reference/neon/exact-integer-convolution selection with no fallback after explicit failure",
            "Shared 32-coefficient NEON dot helper with independent accumulators, exact vector/scalar tails and fused error",
            "Checked native buffer/range/accumulator bounds, including fused-error overflow regression",
            "Corrected the legacy Python-reference test dispatch and replaced repeated-input timing with fresh-input measurements",
            "Retained historical pre-e2 vectors/failures; added versioned research fixtures derived from the pinned original and protected generator outputs from overwrite",
        ],
        "frozen_profile": {"q": 4096, "n": 640, "window": 128, "eta": 2,
                           "public_key_bytes": 1196, "ciphertext_bytes": 1356, "secret_key_bytes": 1868},
        "verification": {
            "regressions_passed": 13,
            "native_exact_comparisons": 270,
            "arm64_neon_asan_ubsan_cases": 243,
            "versioned_fixture_records_per_backend": 15,
            "fixture_backends": list(kat["backends"]),
            "original_refactor_full_byte_handshakes_equal": paired["verification"]["workloads"],
        },
        "performance": {
            "raw_kernel": raw["summaries"],
            "original_vs_refactor_complete_handshake": paired["statistics"],
            "paired_summary": paired["paired_summary"],
            "measured_pairs": paired["measured_pairs"],
            "discarded_warmup_pairs": paired["warmup_pairs"],
            "complete_handshake_tail_latency_increased_in_this_run": True,
            "primary_end_to_end_evidence": "original_vs_refactor_handshake.json",
            "before_after_backend_evidence": ["before_optimization_benchmark.json", "after_optimization_benchmark.json"],
        },
        "historical_fixture_issue": {
            "diagnosis": "All15 historical ciphertexts omit e2; the pinned original already includes e2",
            "historical_files_unchanged": True,
            "evidence": ["retained_kat_failure.json", "retained_kat_baseline_comparison.json", "retained_kat_diagnosis.json", "new_vector_provenance.json"],
        },
        "evidence_notes": [
            "before/ overlapped wrapper extraction; baseline/ retains the pristine earlier verified implementation, with origin/hash metadata",
            "Initial repeated-pool kernel timing is retained only as diagnostic; benchmark_unique.json is the primary raw comparison",
            "Initial scalar sanitizer run and hash-preflight refusal are retained; the arm64 NEON run is separately verified",
        ],
        "limits": "Finite functional/sanitizer evidence and local descriptive timings with uncontrolled scheduling/frequency. No cryptographic security, NIST category, DFR, universal memory-safety, whole-KEM constant-time, or portable speed guarantee.",
        "commit_or_push_performed": False,
        "final_source_sha256": current_hashes,
    }
    write("RESULT.json", result)
    assert current_hashes == {str(p.relative_to(ROOT)): sha(p) for p in files}
    evidence_hashes = {str(p.relative_to(HERE)): sha(p) for p in sorted(HERE.rglob("*"))
                       if p.is_file() and "__pycache__" not in p.parts}
    write("manifest.json", {"algorithm": "sha256", "files": evidence_hashes,
                            "final_live_sources_sha256": current_hashes,
                            "all_snapshot_copies_match": True})
    print("Final snapshot, RESULT.json and SHA256 manifest retained.")


if __name__ == "__main__":
    main()
