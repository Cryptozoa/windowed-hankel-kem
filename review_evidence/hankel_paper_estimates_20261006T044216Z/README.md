# Windowed Hankel KEM: paper estimates and timings (e2 version)

Evidence for Section 5.1 (Table 3) and the "Performance and test vectors" paragraph of
`paper/hankel_kem_eprint.tex`.

## Lattice estimates

- Tool: [malb/lattice-estimator](https://github.com/malb/lattice-estimator), commit
  `53da5982597709ba0fdf94ea37a84d822310fd84` (2026-08-19), run under SageMath 10.8.
- `estimate_full.sage` -> `estimate_full.txt`: `LWE.estimate.rough` (Core-SVP / ADPS16) and
  `LWE.estimate` (default MATZOV cost model, Arora-GB excluded) for n=640, m=768, q=4096,
  CBD2 secret and error.
- `estimate_coresvp_detail.sage` -> `estimate_coresvp_detail.txt`: per-attack block sizes under
  ADPS16 for Windowed Hankel and the estimator's built-in Kyber-512.
- `estimate_kyber512_bkw.sage` -> `estimate_kyber512_bkw.txt`: coded-BKW for Kyber-512.

Run from this directory, e.g. `LATTICE_ESTIMATOR=~/Documents/lattice-estimator sage estimate_full.sage`.

### `sage_flint_shim.py`

The local SageMath build (x86_64 under Rosetta) raises SIGILL inside FLINT's `arb_exp` when
evaluating symbolic `log`/`exp` of floats. The shim converts float and constant symbolic
arguments of `log`, `exp`, `sqrt` and `coth` in the estimator's modules to 256-bit MPFR
values before the call. The estimator source is not modified.

Calibration: with the shim, every Kyber-512 figure in the estimator's README is reproduced
exactly (uSVP 2^118.6 / 2^143.8, dual hybrid 2^115.5 / 2^139.7, BDD 2^140.2, dual 2^149.9,
coded-BKW 2^178.8).

## Timings

`time_ops.py` (run from the repository root) -> `time_ops_neon.txt`. Median and p90 over
2,000 fresh key pairs and ciphertexts after 200 warm-up calls, NEON backend, Apple M3 Max,
Python 3.13.9, NumPy 2.3.5. Correctness of every decapsulation is checked outside timing, and
the RESEARCH_v2 KAT file validated 15/15 beforehand. The recorded run overlapped a Sage
process; three earlier quiet runs gave keygen 67-68 us, encaps 112-114 us, decaps 147-150 us,
handshake 330-344 us. The paper rounds to 0.07 / 0.11 / 0.15 / 0.34 ms.

These are Python-orchestrated timings with native NEON kernels, not a fully native KEM.
