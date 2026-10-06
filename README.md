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

You need macOS on Apple Silicon and Python 3.9+ with NumPy. Without the native library, the Python layer falls back to its pure-Python backends.

```bash
make
make test
```

`make` builds `libhankel_kem_neon.dylib`. `make test` runs every suite:
- the refactor and edge-case unit tests;
- NEON/Python bit-exactness;
- the stress gauntlet: 500 IND-CCA exchanges, tampering and implicit rejection, and an exact recomputation of the DFR bound;
- the KAT check.

Other targets:

```bash
make kat
make paper
```

## Known-answer tests

`nist_analysis_kit/kat/test_vectors/` holds two custom SHAKE-based fixtures. These are not official NIST DRBG vectors.
- `WINDOWED_HANKEL_640_RESEARCH_v2` is current, and the implementation reproduces all 15 vectors.
- `WINDOWED_HANKEL_640_NIST1` predates the e₂ error term. It is kept for provenance and is expected to fail.

## Performance

These timings use Python orchestration with NEON kernels for the Hankel products and decoding, on an Apple M3 Max (median of 2,000 runs):

| Key generation | Encapsulation | Decapsulation | Handshake |
| :---: | :---: | :---: | :---: |
| 0.07 ms | 0.11 ms | 0.15 ms | 0.34 ms |

They include Python overhead and do not represent a fully native implementation.

## Layout

| Path | Contents |
| :--- | :--- |
| `hankel_kem/` | Package: parameters, codec, sampling, Hankel operators, CPA scheme, FO transform, wire format, backends |
| `hankel_kem_core.py`, `hankel_kem_wrapper.py` | Compatibility layers over the package |
| `hankel_kem_neon.c`, `.h` | ARMv8 NEON kernels |
| `nist_analysis_kit/kat/` | KAT generator, validator and fixtures |
| `review_evidence/` | Refactor equivalence evidence and the paper's estimate and timing evidence |
| `paper/` | Paper source, bibliography and PDF |

## License

Dual-licensed under Apache-2.0 or MIT, at your option. See [`LICENSE`](LICENSE).
