# Windowed Hankel KEM

Windowed Hankel KEM is a lattice-based key-encapsulation mechanism built on truncated linear convolution (middle products). It publishes a 128-coordinate window of a Hankel product between one long pseudorandom sequence and a short binomial secret. This sits between unstructured LWE, as in FrodoKEM, and ring- or module-LWE, as in ML-KEM, and needs no reduction modulo a fixed polynomial.

> [!WARNING]
> **Research code.** The instance lies outside the hypotheses of the known Middle-Product LWE reductions, so the scheme has **no security reduction**. Its security figures are lattice-estimator results that treat it as unstructured LWE. Attacks that exploit the Hankel structure have not been analyzed, and the scheme has received no third-party cryptanalysis. Do not use it in production.

The accompanying paper is [`paper/hankel_kem_eprint.pdf`](paper/hankel_kem_eprint.pdf).

## Parameters and sizes

| n | Window W | q | Secret / error | Message | Public key | Ciphertext | Secret key |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 640 | 128 | 4096 | CBD₂ | 256 bits (4-PAM) | 1,196 B | 1,356 B | 1,868 B |

The sizes include 12-byte format headers; without them the exchange is 2,528 B, against 1,568 B for ML-KEM-512. IND-CCA security uses the Fujisaki–Okamoto transform with implicit rejection.

## Security summary

All figures are log₂ costs from the lattice estimator, treating the scheme as unstructured LWE (paper, Section 5).

| Attack | Core-SVP | MATZOV | Kyber-512 (Core-SVP / MATZOV) |
| :--- | :---: | :---: | :---: |
| Primal (uSVP) | 142.5 (β = 488) | 166.8 | 118.6 / 143.8 |
| Dual | 148.0 (β = 507) | 173.7 | 123.8 / 149.9 |
| **Dual hybrid (cheapest)** | **137.1 (β = 468)** | **160.3** | 115.5 / 139.7 |

The decryption failure rate is at most 2^-134.1, from an exact Chernoff bound.

Scripts, raw outputs and the estimator commit are in [`review_evidence/hankel_paper_estimates_20261006T044216Z/`](review_evidence/hankel_paper_estimates_20261006T044216Z/).

## Building and testing

You need macOS on Apple Silicon and Python 3.9+ with NumPy. Without the native library, the Python layer falls back to its pure-Python backends. The native KEM itself is plain C99 with NEON and SHA-256 instructions where available, and portable fallbacks otherwise.

```bash
make
make test
```

`make` builds `libhankel_kem_neon.dylib`. `make test` runs every suite:
- the native KEM in C: hash known answers, all KAT vectors, and implicit rejection;
- the native KEM from Python: byte-exact equivalence with the reference, the static constant-time audit, and fixed-versus-random timing tests;
- the refactor and edge-case unit tests;
- NEON/Python bit-exactness;
- the stress gauntlet: 500 IND-CCA exchanges, tampering and implicit rejection, and an exact recomputation of the DFR bound;
- the KAT check.

Other targets:

```bash
make kat
make bench
make paper
```

## Native implementation

`hankel_kem_native.c` implements the complete KEM in C: key generation, encapsulation and decapsulation, with SHAKE-256 and SHA-256 in `hankel_hash.c`. It is bit-exact with the Python reference and reproduces every KAT vector.

```c
int hankel_kem_keypair(uint8_t *pk, uint8_t *sk);
int hankel_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int hankel_kem_dec(uint8_t *ss, const uint8_t *ct, size_t ct_len, const uint8_t *sk);
```

Deterministic variants (`_derand`) take the same seeds and entropy as the Python functions. From Python, `hankel_kem.native` exposes `keygen`, `encaps` and `decaps`.

- **Arithmetic.** Since q = 2¹² divides 2¹⁶, the Hankel products accumulate in 16-bit lanes with natural wraparound and are masked once at the end. The NEON kernel computes 64 outputs at a time, broadcasting each secret coefficient across the public sequence (`vmlaq_laneq_u16`).
- **Constant time.** Secrets never select a branch or a memory address. The zero-secret fix-up, the re-encryption comparison and the implicit-rejection selection use masks behind a value barrier. Each secret-handling step is a separate function, and `ct_branch_audit.py` checks the compiled code: every conditional branch in these 9 functions depends only on public values. Fixed-versus-random timing tests find no dependence on secrets, and decapsulation takes the same time whether it accepts or rejects.

## Known-answer tests

`nist_analysis_kit/kat/test_vectors/` holds two custom SHAKE-based fixtures. These are not official NIST DRBG vectors.
- `WINDOWED_HANKEL_640_RESEARCH_v2` is current, and the implementation reproduces all 15 vectors.
- `WINDOWED_HANKEL_640_NIST1` predates the e₂ error term. It is kept for provenance and is expected to fail.

## Performance

Medians on an Apple M3 Max: 5,000 calls for the native KEM (`make bench`) and 2,000 for the Python path:

| Implementation | Key generation | Encapsulation | Decapsulation | Handshake |
| :--- | :---: | :---: | :---: | :---: |
| Native C (NEON, SHA-256 instructions) | 14 µs | 17 µs | 20 µs | 51 µs |
| Python with NEON kernels (`hankel_kem_wrapper`) | 70 µs | 110 µs | 150 µs | 340 µs |

In the native KEM, about 8 µs of each encapsulation goes to the Hankel products and about 6 µs to SHAKE-256. Records are in [`review_evidence/hankel_native_20261006T054758Z/`](review_evidence/hankel_native_20261006T054758Z/).

## Layout

| Path | Contents |
| :--- | :--- |
| `hankel_kem/` | Package: parameters, codec, sampling, Hankel operators, CPA scheme, FO transform, wire format, backends |
| `hankel_kem_core.py`, `hankel_kem_wrapper.py` | Compatibility layers over the package |
| `hankel_kem_native.c`, `.h` | Native KEM (C, NEON) |
| `hankel_hash.c`, `.h` | SHAKE-256 and SHA-256 |
| `test_hankel_native.c`, `bench_hankel_native.c` | Standalone C tests and benchmark |
| `test_hankel_native_kem.py`, `ct_branch_audit.py` | Native/reference equivalence, static audit, timing tests |
| `hankel_kem_neon.c`, `.h` | ARMv8 NEON kernels used by the Python backends |
| `nist_analysis_kit/kat/` | KAT generator, validator and fixtures |
| `review_evidence/` | Refactor equivalence evidence and the paper's estimate and timing evidence |
| `paper/` | Paper source, bibliography and PDF |

## License

Dual-licensed under Apache-2.0 or MIT, at your option. See [`LICENSE`](LICENSE).
