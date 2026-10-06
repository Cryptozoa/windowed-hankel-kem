"""Compile and run a bounded standalone ASan+UBSan candidate tail checker."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parents[1] / "native_candidate"
EXPECTED = {
    "hankel_kem_neon.c": "f79933c1a0047fe4ec514fec32949e508b1f3d8298a103299ca00f36126575de",
    "hankel_kem_neon.h": "17b5ee287ca9d651fe0354b158a8855da1418dfb58d1a3031032a49fb0ab863d",
}
SNAPSHOT = HERE / "input_snapshot"
SNAPSHOT.mkdir(exist_ok=True)
for name, expected in EXPECTED.items():
    original = CANDIDATE / name
    data = original.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected, ("Candidate source drift", name)
    destination = SNAPSHOT / name
    with destination.open("xb") as handle:
        handle.write(data)

compiler = "/usr/bin/clang" if Path("/usr/bin/clang").exists() else None
assert compiler is not None, "Existing clang compiler is required; no installation attempted"
version = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=False)
with (HERE / "compiler_version.log").open("x") as handle:
    handle.write(version.stdout + version.stderr)
assert version.returncode == 0

executable = HERE / "tail_harness_asan_ubsan"
command = [compiler, "-arch", "arm64", "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
           "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
           "-fno-omit-frame-pointer", "-I", str(SNAPSHOT),
           str(HERE / "tail_harness.c"), str(SNAPSHOT / "hankel_kem_neon.c"),
           "-o", str(executable)]
compiled = subprocess.run(command, cwd=HERE, capture_output=True, text=True, check=False)
with (HERE / "compile.log").open("x") as handle:
    handle.write(compiled.stdout + compiled.stderr)
record = {
    "scope": "ASan+UBSan on candidate C/header with exact malloc lengths, n=[1,7,8,9,17,31,32,33,640], null/fused error and scalar int64 modular oracle; no live source edits, installs, benchmark or cryptographic security assessment.",
    "candidate_hashes_before": EXPECTED,
    "compiler": compiler, "compiler_command": command,
    "compile_returncode": compiled.returncode,
    "platform": platform.platform(),
}
if compiled.returncode == 0:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    ran = subprocess.run([str(executable)], cwd=HERE, env=env,
                         capture_output=True, text=True, check=False)
    with (HERE / "run_stdout.log").open("x") as handle:
        handle.write(ran.stdout)
    with (HERE / "run_stderr.log").open("x") as handle:
        handle.write(ran.stderr)
    record.update({"run_returncode": ran.returncode,
                   "sanitizer_options": {key: env[key] for key in ("ASAN_OPTIONS", "UBSAN_OPTIONS")}})
    if ran.returncode == 0:
        record["harness_result"] = json.loads(ran.stdout.splitlines()[-1])
        assert record["harness_result"]["native_path"] == "ARM_NEON", "ARM64 sanitizer must execute NEON branch"
        record["sanitizer_stderr_empty"] = not bool(ran.stderr)
record["candidate_hashes_after"] = {
    name: hashlib.sha256((CANDIDATE / name).read_bytes()).hexdigest() for name in EXPECTED
}
record["candidate_unchanged"] = record["candidate_hashes_after"] == EXPECTED
with (HERE / "results.json").open("x") as handle:
    json.dump(record, handle, indent=2)
    handle.write("\n")
files = [path for path in HERE.rglob("*") if path.is_file() and path.name != "manifest.json"]
manifest = {"files": [{"path": str(path.relative_to(HERE)), "bytes": path.stat().st_size,
                       "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(files)]}
with (HERE / "manifest.json").open("x") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")
print(json.dumps({"result_path": str(HERE / "results.json"), "compile_returncode": compiled.returncode,
                  "run_returncode": record.get("run_returncode"), "candidate_unchanged": record["candidate_unchanged"],
                  "harness_result": record.get("harness_result")}))
assert record["candidate_unchanged"]
assert compiled.returncode == 0 and record.get("run_returncode") == 0
