# Native C implementation, WH-640 (October 6, 2026)

Evidence for the first version of the native KEM (paper, Section 8), Apple M3 Max, Apple clang 17, -O3:

- `test_native_c.txt`: the standalone C test (hash known answers, all 15 KAT vectors, implicit
  rejection, 200 random round trips);
- `test_native_python.txt`: equivalence with the Python reference, kernel checks, malformed keys, the
  static branch audit and fixed-versus-random timing tests;
- `bench_native.txt`: the latencies quoted in the paper (14, 17 and 20 microseconds, 51 for a handshake);
- `source_sha256.txt`: hashes of the sources measured.

The static-audit figures here (9 functions, 1,274 instructions, 23 branches) describe this version.
The code was later turned into a per-set template; the current figures, which the paper quotes, are in
`review_evidence/hankel_native_sets_20261007T164709Z/`.
