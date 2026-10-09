# Baseline of the original implementation (October 3, 2026)

Historical evidence, recorded before the refactor of `review_evidence/hankel_refactor_20261003T120004Z/`.
The directory name is the SHA-256 prefix of the original `hankel_kem_core.py`.

- `input_snapshot/`: the original sources (Python reference, NEON kernels and their tests) and the
  compiled library they were tested with.
- `check_baseline.py` -> `results.json`: runs the three existing edge tests and one deterministic
  KEM and wire-format round trip per backend, and records the source hashes before and after (unchanged).
  No attacks, parameter changes, timings or security assessment.
- `manifest.json`: SHA-256 of every evidence file in the directory (this README was added later).

The code at the repository root has since been refactored and extended; this snapshot is kept so that
the refactor's equivalence evidence has a fixed starting point.
