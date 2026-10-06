"""Create versioned fixtures from the pinned original; preserve historical files."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from nist_analysis_kit.kat import PQCgenKAT_hankel as generator


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    spec = importlib.util.spec_from_file_location("original_comparison", HERE / "compare_original_handshake.py")
    comparison = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(comparison)
    assert comparison.hashes(comparison.ORIGINAL, comparison.ORIGINAL_HASHES) == comparison.ORIGINAL_HASHES
    core, original = comparison.original_modules()
    assert core._C_LIB is not None
    directory = ROOT / "nist_analysis_kit/kat/test_vectors"
    historical = {path.name: sha(path) for path in directory.glob("WINDOWED_HANKEL_640_NIST1.*")}
    outputs = [directory / ("WINDOWED_HANKEL_640_RESEARCH_v2." + suffix) for suffix in ("req", "rsp")]
    assert not any(path.exists() for path in outputs), "Versioned fixtures already exist"
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture):
        # Expected cryptographic bytes come from independently loaded pristine
        # code/library; only the text formatting and deterministic input stream
        # come from the current fixture writer.
        with mock.patch.multiple(generator,
                hankel_kem_keygen=original.hankel_kem_keygen,
                hankel_kem_encaps=original.hankel_kem_encaps,
                hankel_kem_decaps=original.hankel_kem_decaps):
            generator.generate_kat_hankel(15, str(directory))
        replay = HERE / "generator_replay"
        generator.generate_kat_hankel(15, str(replay))
    replay_equal = all(path.read_bytes() == (replay / path.name).read_bytes() for path in outputs)
    assert replay_equal, "Current generator does not match the independently pinned original"
    initial = {path.name: sha(path) for path in outputs}
    try:
        generator.generate_kat_hankel(15, str(directory))
    except FileExistsError:
        overwrite_refused = True
    else:
        raise AssertionError("Existing fixture files were not protected")
    assert initial == {path.name: sha(path) for path in outputs}
    assert historical == {path.name: sha(path) for path in directory.glob("WINDOWED_HANKEL_640_NIST1.*")}
    report = {
        "expected_output_source": "Pinned pristine pre-refactor core/wrapper/native library",
        "original_source_sha256": comparison.ORIGINAL_HASHES,
        "writer_sha256": sha(Path(generator.__file__)),
        "versioned_files_sha256": initial,
        "historical_files_sha256_unchanged": historical,
        "current_generator_replay_byte_exact": replay_equal,
        "overwrite_attempt_refused_before_writing": overwrite_refused,
        "vectors": 15,
        "scope": "Custom deterministic research compatibility fixtures including the existing e2 term; no official NIST compliance or security claim",
    }
    with (HERE / "new_vector_provenance.json").open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    with (HERE / "new_vector_generation.log").open("x") as handle:
        handle.write(capture.getvalue())
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
