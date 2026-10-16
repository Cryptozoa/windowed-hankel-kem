# v0.3: the exact FO transform, and records after the review revisions (paper, Sections 5 and 8)

## What changed in the code

The KEM now implements the Fujisaki–Okamoto transform with implicit rejection, FO^⊥̸ = U^⊥̸ ∘ T of
Hofheinz, Hövelmanns and Kiltz (TCC 2017), exactly as Theorem 2 of the paper states it, with its two random
oracles instantiated by domain-separated SHAKE256:

    G(M)     = SHAKE256(M || "_hankel_fo_G" || dom, 32)          coins of the CPA encryption
    H(X, ct) = SHAKE256(X || ct || "_hankel_fo_H" || dom, 32)    shared key, X = M or the rejection seed z

Encapsulation returns ct = CPA.Enc(pk, M; G(M)) and K = H(M, ct). Decapsulation re-encrypts M' under G(M')
and returns H(M', ct) if the ciphertexts agree and H(z, ct) otherwise, choosing the input to H in constant
time and calling H once. `dom` is empty for WH-640 and `_wh936`, `_wh1208` for the other sets.

Versions up to 0.2 used a Kyber-style variant: (pre-key, coins) = SHAKE256(M || SHA-256(pk), 64) and
K = SHAKE256(pre-key || SHA-256(ct), 32). Key generation is unchanged, so public and secret keys are
identical; ciphertexts and shared secrets differ. The KAT files are therefore new versions
(`WINDOWED_HANKEL_640_RESEARCH_v3`, `WINDOWED_HANKEL_936_v2`, `WINDOWED_HANKEL_1208_v2`); the v0.2 files are
kept for provenance. Python reference (`hankel_kem/generic.py`, `hankel_kem/fo.py`) and C template
(`hankel_kem_native_impl.h`) were changed together and agree bit for bit on all three sets.

## Records (Apple M3 Max, macOS 27.0.1, Apple clang 21.0.0)

| File | Contents |
| :--- | :--- |
| `make_test.txt` | `make test`: all suites pass, including the KATs of all sets, the static audit and the timing tests |
| `audit_totals.py`, `.txt` | static-audit totals: Category 1, 9 functions, 1,167 instructions, 30 branches; all sets, 25 functions, 2,970 instructions, 92 branches, all on public values |
| `bench_native.txt` | `./bench_hankel_native 5000`: WH-640 14 / 20 / 23 µs, 57 µs per handshake; WH-936 106 µs; WH-1208 149 µs |
| `python_path.txt` | the Python path with NEON kernels: 69 / 114 / 153 µs, 344 µs per handshake |
| `bench_liboqs.c`, `baselines.txt` | ML-KEM-512 and FrodoKEM-640 from liboqs 0.16.0, timed exactly like our benchmark and run back to back with it: handshakes of 19.5 µs (ML-KEM-512), 740 µs (FrodoKEM-640-AES) and 3.3 ms (FrodoKEM-640-SHAKE), against 60 µs for WH-640 in that session |
| `bench_parts.c`, `.txt` | where an encapsulation spends its time: Hankel products 7.06 + 1.14 µs; SHAKE256 3.63 (public sequence), 2.09 (coins), 0.24 (G), 4.57 µs (H over the ciphertext) |

For comparison, the v0.2 code built with the same compiler runs a WH-640 handshake in 52.1 µs (14.1 / 17.4 /
20.3 µs): the exact transform costs about 4.6 µs, one SHAKE256 pass over the 1,356-byte ciphertext in each of
encapsulation and decapsulation, where v0.2 used the SHA-256 instructions. A faster Keccak would recover it.

Run from the repository root after `make`:

    make test
    ./bench_hankel_native 5000
    python3 review_evidence/hankel_fo_v03_20261016/audit_totals.py
    cc -O3 -std=c99 -arch arm64 -I. -o bench_parts review_evidence/hankel_fo_v03_20261016/bench_parts.c \
       hankel_kem_native.c hankel_hash.c && ./bench_parts
