# Windowed Hankel KEM

Windowed Hankel KEM is a lattice-based key-encapsulation mechanism built on truncated linear convolution (middle products). It publishes a 128-coordinate window of a Hankel product between one long pseudorandom sequence and a short binomial secret. This sits between unstructured LWE, as in FrodoKEM, and ring- or module-LWE, as in ML-KEM, and needs no reduction modulo a fixed polynomial.

> [!WARNING]
> **Research code.** The instance lies outside the hypotheses of the known Middle-Product LWE reductions, so the scheme has **no security reduction**. Its security figures are lattice-estimator results that treat it as unstructured LWE. Attacks that exploit the Hankel structure have not been analyzed, and the scheme has received no third-party cryptanalysis. Do not use it in production.

The accompanying paper, [*Windowed Hankel LWE: A Structured-LWE Problem for Cryptanalysis, with a Compact KEM*](paper/hankel_kem_eprint.pdf), offers the underlying problem as a test case for cryptanalysis. Its Table 2 summarizes the status of every attack family considered, and Section 4.4 states what would count as a break. Reports of attacks, positive or negative, are welcome.

## Parameters and sizes

| Set | Target | n | Window W | q | Secret / error | Message | Public key | Ciphertext | Secret key |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| WH-640 | Category 1 | 640 | 128 | 4096 | CBD₂ | 256 bits (4-PAM) | 1,196 B | 1,356 B | 1,868 B |
| WH-936 | Category 3 (candidate) | 936 | 128 | 8192 | CBD₂ | 256 bits (4-PAM) | 1,773 B | 1,949 B | 2,741 B |
| WH-1208 | Category 5 (candidate) | 1,208 | 128 | 8192 | CBD₂ | 256 bits (4-PAM) | 2,215 B | 2,391 B | 3,455 B |

The sizes include 12-byte format headers. Without them, a WH-640 exchange is 2,528 B, against 1,568 B for ML-KEM-512, and WH-936 and WH-1208 exchanges are 3,698 B and 4,582 B, against 2,272 B and 3,136 B for ML-KEM-768 and ML-KEM-1024. IND-CCA security uses the Fujisaki–Okamoto transform with implicit rejection.

WH-640 is the set analyzed in the body of the paper. WH-936 and WH-1208 are derived in its Appendix D, and they rest on the same unproven assumption about Hankel structure.

## Security summary

All figures are log₂ costs from the lattice estimator, treating the scheme as unstructured LWE (paper, Section 7).

| Attack | Core-SVP | MATZOV | Kyber-512 (Core-SVP / MATZOV) |
| :--- | :---: | :---: | :---: |
| Primal (uSVP) | 142.5 (β = 488) | 166.8 | 118.6 / 143.8 |
| Dual | 148.0 (β = 507) | 173.7 | 123.8 / 149.9 |
| **Dual hybrid (cheapest)** | **137.1 (β = 468)** | **160.3** | 115.5 / 139.7 |

The decryption failure rate is at most 2^-134.1, from an exact Chernoff bound.

Scripts, raw outputs and the estimator commit are in [`review_evidence/hankel_paper_estimates_20261006T044216Z/`](review_evidence/hankel_paper_estimates_20261006T044216Z/).

For the candidate sets, the cheapest attack is again the dual hybrid:

| Set | Core-SVP | MATZOV | Kyber reference (Core-SVP / MATZOV) | Failure rate |
| :--- | :---: | :---: | :---: | :---: |
| WH-936 | 196.8 (β = 674) | 218.2 | Kyber-768: 174.3 / 196.4 | ≤ 2^-370.1 |
| WH-1208 | 263.5 (β = 902) | 283.7 | Kyber-1024: 241.8 / 262.3 | ≤ 2^-291.9 |

The derivation is in [`review_evidence/hankel_higher_categories/`](review_evidence/hankel_higher_categories/).

## Building and testing

You need macOS on Apple Silicon and Python 3.9+ with NumPy. Without the native library, the Python layer falls back to its pure-Python backends. The native KEM itself is plain C99 with NEON and SHA-256 instructions where available, and portable fallbacks otherwise.

```bash
make
make test
```

`make` builds `libhankel_kem_neon.dylib`. `make test` runs every suite:
- the native KEM in C, for every set: hash known answers, all KAT vectors, and implicit rejection;
- the native KEM from Python, for every set: byte-exact equivalence with the reference, the static constant-time audit, and fixed-versus-random timing tests;
- the refactor and edge-case unit tests;
- NEON/Python bit-exactness;
- the stress gauntlet: 500 IND-CCA exchanges, tampering and implicit rejection, and an exact recomputation of the DFR bound;
- the KAT checks for all three sets.

Other targets:

```bash
make kat
make bench
make paper
```

## Native implementation

`hankel_kem_native.c` implements the complete KEM in C: key generation, encapsulation and decapsulation, with SHAKE-256 and SHA-256 in `hankel_hash.c`. The per-set code is the template `hankel_kem_native_impl.h`, compiled once for each set. It is bit-exact with the Python references and reproduces every KAT vector.

```c
int hankel_kem_keypair(uint8_t *pk, uint8_t *sk);
int hankel_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int hankel_kem_dec(uint8_t *ss, const uint8_t *ct, size_t ct_len, const uint8_t *sk);
```

These are the WH-640 functions. WH-936 and WH-1208 have the same API under the prefixes `hankel936_` and `hankel1208_`, with sizes `HANKEL936_KEM_*` and `HANKEL1208_KEM_*`. Deterministic variants (`_derand`) take the same seeds and entropy as the Python functions. From Python, `hankel_kem.native` exposes `keygen`, `encaps` and `decaps`, with `profile="WH-640"` (default), `"WH-936"` or `"WH-1208"`. `hankel_kem/generic.py` is a compact parameterized reference for all three sets; for WH-640 it agrees byte for byte with the package reference.

- **Arithmetic.** Since q = 2¹² and q = 2¹³ both divide 2¹⁶, the Hankel products accumulate in 16-bit lanes with natural wraparound and are masked once at the end. The NEON kernel computes 64 outputs at a time, broadcasting each secret coefficient across the public sequence (`vmlaq_laneq_u16`).
- **Domain separation.** For WH-936 and WH-1208, every derivation tag is followed by `_wh936` or `_wh1208`. WH-640 tags are unchanged.
- **Constant time.** Secrets never select a branch or a memory address. The zero-secret fix-up, the re-encryption comparison and the implicit-rejection selection use masks behind a value barrier. Each secret-handling step is a separate function, and `ct_branch_audit.py` checks the compiled code: every conditional branch in these 25 functions (8 per set, plus Keccak-f) depends only on public values. Fixed-versus-random timing tests find no dependence on secrets in any set, and decapsulation takes the same time whether it accepts or rejects.

## Known-answer tests

`nist_analysis_kit/kat/test_vectors/` holds custom SHAKE-based fixtures. These are not official NIST DRBG vectors.
- `WINDOWED_HANKEL_640_RESEARCH_v2` is current for WH-640, and the implementation reproduces all 15 vectors.
- `WINDOWED_HANKEL_936_v1` and `WINDOWED_HANKEL_1208_v1` hold 15 vectors each for the candidate sets, from `PQCgenKAT_hankel_sets.py` (`validate` checks the Python reference and the native code).
- `WINDOWED_HANKEL_640_NIST1` predates the e₂ error term. It is kept for provenance and is expected to fail.

## Performance

Medians on an Apple M3 Max: 5,000 calls for the native KEM (`make bench`) and 2,000 for the Python path:

| Implementation | Key generation | Encapsulation | Decapsulation | Handshake |
| :--- | :---: | :---: | :---: | :---: |
| Native C (NEON, SHA-256 instructions), WH-640 | 14 µs | 17 µs | 20 µs | 51 µs |
| Native C, WH-936 | 30 µs | 31 µs | 37 µs | ≈ 100 µs |
| Native C, WH-1208 | 40 µs | 48 µs | 48 µs | ≈ 135 µs |
| Python with NEON kernels (`hankel_kem_wrapper`), WH-640 | 70 µs | 110 µs | 150 µs | 340 µs |

In the native KEM, about 8 µs of each WH-640 encapsulation goes to the Hankel products and about 6 µs to SHAKE-256. Records are in [`review_evidence/hankel_native_20261006T054758Z/`](review_evidence/hankel_native_20261006T054758Z/) (WH-640) and [`review_evidence/hankel_native_sets_20261007T164709Z/`](review_evidence/hankel_native_sets_20261007T164709Z/) (all sets).

## Reproducing the paper

Every figure in the paper comes from a script in this repository, with its recorded output next to it.

| Paper | Command | Evidence |
| :--- | :--- | :--- |
| Implementation, KATs, constant-time audit, timing tests (Section 8) | `make test` | [`review_evidence/hankel_native_sets_20261007T164709Z/`](review_evidence/hankel_native_sets_20261007T164709Z/) |
| Latencies (Section 8, Appendix D) | `make bench` | same directory, `bench_native.txt` |
| Known-answer tests, all sets | `make kat` | `nist_analysis_kit/kat/test_vectors/` |
| Generic attack estimates (Section 7, Table 7) | `LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimate_full.sage`, and the other `estimate_*.sage` scripts | [`review_evidence/hankel_paper_estimates_20261006T044216Z/`](review_evidence/hankel_paper_estimates_20261006T044216Z/) |
| Parameter study and failure-rate bound (Section 6, Appendix A) | `sage estimate_param_grid.sage`; `python3 dfr_grid.py` | same directory |
| Cyclic-embedding functionals (Section 4.3, Appendix C) | `sage functionals.sage full`; `sage functionals.sage case n W target trials seed` | [`review_evidence/hankel_embedding_functionals/`](review_evidence/hankel_embedding_functionals/) |
| Subring argument and decryption equations (Sections 4.3 and 5.3, Proposition 2) | `sage subrings.sage`; `sage decryption_equations.sage` | [`review_evidence/hankel_open_directions/`](review_evidence/hankel_open_directions/) |
| Category 3 and 5 sets (Appendix D) | the `.sage` and `.py` scripts listed in its README | [`review_evidence/hankel_higher_categories/`](review_evidence/hankel_higher_categories/) |

The estimates use the [lattice estimator](https://github.com/malb/lattice-estimator) at commit `53da598` and SageMath 10.9 (the functionals also need fpylll). Run each script from its evidence directory; the README there lists inputs, outputs and versions.

## Layout

| Path | Contents |
| :--- | :--- |
| `hankel_kem/` | Package: parameters, codec, sampling, Hankel operators, CPA scheme, FO transform, wire format, backends; `generic.py`, the parameterized reference for all sets |
| `hankel_kem_core.py`, `hankel_kem_wrapper.py` | Compatibility layers over the package |
| `hankel_kem_native.c`, `.h`, `hankel_kem_native_impl.h` | Native KEM (C, NEON); the per-set template |
| `hankel_hash.c`, `.h` | SHAKE-256 and SHA-256 |
| `test_hankel_native.c`, `bench_hankel_native.c` | Standalone C tests and benchmark |
| `test_hankel_native_kem.py`, `ct_branch_audit.py` | Native/reference equivalence, static audit, timing tests |
| `hankel_kem_neon.c`, `.h` | ARMv8 NEON kernels used by the Python backends |
| `nist_analysis_kit/kat/` | KAT generator, validator and fixtures |
| `review_evidence/` | Refactor equivalence evidence, the paper's estimate and timing evidence, and the higher-category derivation |
| `paper/` | Paper source, bibliography and PDF |

## License

Dual-licensed under Apache-2.0 or MIT, at your option. See [`LICENSE`](LICENSE).
