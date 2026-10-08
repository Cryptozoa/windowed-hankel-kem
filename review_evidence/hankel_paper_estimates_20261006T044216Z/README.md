# Windowed Hankel KEM: paper estimates and timings (e2 version)

Evidence for the security estimates and parameter study of `paper/hankel_kem_eprint.tex`
(Sections 6 and 7, Appendix A). The native-implementation timings of Section 8 are in
`review_evidence/hankel_native_20261006T054758Z/`; `time_ops.py` below measured the earlier
Python-orchestrated implementation.

## Lattice estimates

- Tool: [malb/lattice-estimator](https://github.com/malb/lattice-estimator), commit
  `53da5982597709ba0fdf94ea37a84d822310fd84` (2026-08-19), run under SageMath 10.8.
- `estimate_full.sage` -> `estimate_full.txt`: `LWE.estimate.rough` (Core-SVP / ADPS16) and
  `LWE.estimate` (default MATZOV cost model, Arora-GB excluded) for n=640, m=768, q=4096,
  CBD2 secret and error.
- `estimate_coresvp_detail.sage` -> `estimate_coresvp_detail.txt`: per-attack block sizes under
  ADPS16 for Windowed Hankel and the estimator's built-in Kyber-512.
- `estimate_kyber512_bkw.sage` -> `estimate_kyber512_bkw.txt`: coded-BKW for Kyber-512.
- `estimate_param_grid.sage` -> `estimate_param_grid.txt`: primal and dual hybrid costs and sizes for
  the parameter alternatives (paper Table 5).
- `estimate_hybrids_alt.sage` -> `estimate_hybrids_alt.txt`: primal hybrid attacks with and without
  meet-in-the-middle guessing, which `LWE.estimate` runs but does not print when they are not the
  cheapest, for the chosen set and two q = 2^11, CBD_1 alternatives.
- `estimate_dual_mitm.sage` -> `estimate_dual_mitm.txt`: dual hybrid with meet-in-the-middle guessing
  (not run by `LWE.estimate`). For the CBD_1 alternatives the optimizer fails in some cost models.
- `estimate_arora_gb.sage` -> `estimate_arora_gb.txt`: Arora-GB for the chosen set (degree of
  regularity 442, about 2^2100.7) and the q = 2^11, CBD_1 alternative (173, about 2^1204.5). Uses
  `install_gb()` from the shim (below).
- `crosscheck_native_sage.sage` -> `crosscheck_native_sage.txt`: recomputes every estimate in the paper
  on a native arm64 SageMath 10.9 (conda-forge) **without** the shim. All figures agree with the runs
  above.
- `dfr_grid.py` -> `dfr_grid.txt`: Chernoff DFR bound for combinations of q, eta and bits per
  coordinate (paper Table 4); its last line reproduces the 2^-134.1 bound of Theorem 1.

Run from this directory, e.g. `LATTICE_ESTIMATOR=~/Documents/lattice-estimator sage estimate_full.sage`.

### `sage_flint_shim.py`

The local SageMath build (x86_64 under Rosetta) raises SIGILL inside FLINT's `arb_exp` when
evaluating symbolic `log`/`exp` of floats. The shim converts float and constant symbolic
arguments of `log`, `exp`, `sqrt` and `coth` in the estimator's modules to 256-bit MPFR
values before the call. The estimator source is not modified.

`install_gb()` replaces the estimator's `gb_cost`, whose exact power-series expansion raises a FLINT
exception in the same build, with an identical computation in Python integers.
`validate_gb_shim.sage` -> `validate_gb_shim.txt` checks it against the estimator's documented
examples (one `gb_cost` and six `arora_gb` cases): all costs and degrees of regularity agree.

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
