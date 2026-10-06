"""Small current-Hankel refactor baseline. No original source edits or benchmarks."""
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
names = ["hankel_kem_core.py", "hankel_kem_wrapper.py", "hankel_kem_neon.c", "hankel_kem_neon.h",
         "libhankel_kem_neon.dylib", "test_hankel_neon.py", "test_hankel_kem_edge_cases.py"]
before = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
assert before["hankel_kem_core.py"] == "e2080e22fe2d23da7ce92eebd1b01860762cf77c948c65c6a511015529fb0f29"
snapshots = HERE / "input_snapshot"
snapshots.mkdir(exist_ok=True)
for name in names:
    dest = snapshots / name
    if dest.exists():
        assert dest.read_bytes() == (ROOT / name).read_bytes()
    else:
        with dest.open("xb") as handle:
            handle.write((ROOT / name).read_bytes())
sys.path.insert(0, str(ROOT))
import hankel_kem_core as core
import hankel_kem_wrapper as wire
native = core._C_LIB
suite = unittest.defaultTestLoader.loadTestsFromName("test_hankel_kem_edge_cases")
stream = io.StringIO()
test_result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
assert test_result.wasSuccessful(), stream.getvalue()

outputs = {}
try:
    for name, backend in (("loaded_backend", native), ("forced_python", None)):
        core._C_LIB = backend
        pk, sk = wire.hankel_kem_keygen(seed=bytes(range(64)))
        ct, sender = wire.hankel_kem_encaps(pk, entropy=bytes(range(32)))
        receiver = wire.hankel_kem_decaps(ct, sk)
        pk_object = wire.deserialize_public_key(pk)
        u, v, n, w, q = wire.deserialize_ciphertext(ct)
        assert sender == receiver
        assert wire.serialize_public_key(pk_object) == pk
        assert wire.serialize_ciphertext(u, v, n, w, q) == ct
        outputs[name] = (pk, sk, ct, sender, receiver)
    assert outputs["loaded_backend"] == outputs["forced_python"]
finally:
    core._C_LIB = native

after = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
assert before == after
report = {
    "scope": "Three existing edge tests plus one deterministic complete KEM and wire roundtrip per backend; no attacks, parameter change, rebuild, timing, or security assessment.",
    "runtime": {"python": platform.python_version(), "platform": platform.platform()},
    "source_hashes_before": before, "source_hashes_after": after, "sources_unchanged": before == after,
    "native_available": native is not None,
    "existing_test_count": test_result.testsRun, "existing_tests_pass": test_result.wasSuccessful(),
    "existing_tests_log": stream.getvalue(),
    "deterministic_input": "Keygen seed bytes(range(64)); encapsulation entropy bytes(range(32)); generated locally and public checker labels only.",
    "complete_roundtrips_pass": True, "wire_roundtrips_pass": True, "loaded_vs_forced_python_outputs_equal": True,
    "output_lengths": dict(zip(["public_key", "secret_key", "ciphertext", "sender_key", "receiver_key"], map(len, outputs["loaded_backend"]))),
    "output_sha256": {k: [hashlib.sha256(item).hexdigest() for item in values] for k, values in outputs.items()},
    "limits": "Existing tests use random local synthetic inputs. One deterministic canonical tuple establishes only this implementation baseline. The existing all-in-one native benchmark suite was not run; no throughput, DFR, parameter-strength or security conclusion.",
}
result_path = HERE / "results.json"
if result_path.exists():
    result_path = HERE / ("results_replay_" + str(time.time_ns()) + ".json")
with result_path.open("x") as handle:
    json.dump(report, handle, indent=2)
    handle.write("\n")
files = [Path(__file__), result_path] + [snapshots / name for name in names]
manifest = {"files": [{"path": str(path.relative_to(HERE)), "bytes": path.stat().st_size,
                       "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in files]}
manifest_path = HERE / ("manifest.json" if result_path.name == "results.json" else "manifest_" + result_path.stem + ".json")
with manifest_path.open("x") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")
print(json.dumps({"result": str(result_path), "native_available": native is not None,
                  "existing_tests": test_result.testsRun, "roundtrips": 2,
                  "wire_lengths": report["output_lengths"], "sources_unchanged": before == after}))
