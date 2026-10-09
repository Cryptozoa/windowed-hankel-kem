# Behavior-preserving refactor and native optimization (October 3, 2026)

Evidence that the refactor of the Python research implementation into the `hankel_kem/` package, and the
optimization of its NEON kernels, changed no output. `RESULT.json` summarizes the outcome:

- 13 regression suites passed; 270 exact comparisons between the native kernels and the reference;
  243 cases under AddressSanitizer and UndefinedBehaviorSanitizer on arm64 (`native_sanitizer/`);
- the current known-answer file `WINDOWED_HANKEL_640_RESEARCH_v2` regenerated from the pinned original
  and reproduced by the reference, convolution and NEON backends (`generator_replay/`,
  `new_vector_provenance.json`);
- the historical `WINDOWED_HANKEL_640_NIST1` file, which predates the e2 error term, kept with a
  diagnosis of why it no longer validates (`retained_kat_*`);
- benchmarks before and after the optimization (`*_optimization_benchmark.json`, `native_candidate/`).

`manifest.json` holds the SHA-256 of every evidence file (this README was added later); `REDACTION.md` records the removal of local paths before
publication. `git_head` in `RESULT.json` refers to the private development repository in which this
evidence was first produced.
