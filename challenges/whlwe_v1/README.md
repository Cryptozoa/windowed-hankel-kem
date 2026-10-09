# Windowed Hankel LWE challenge, version 1

Concrete targets for the cryptanalysis that the paper asks for. Each instance is an LWE instance whose
matrix is a Hankel matrix, at sizes from trivial to the shape of the KEM's public key. Each comes with a
**uniform twin** of the same shape whose matrix is uniformly random. The question is whether the Hankel
structure helps: by the criteria of Section 4.4 of the paper, solving Hankel instances markedly more
cheaply than their uniform twins, over several sizes, would be evidence of a structural weakness, even
at sizes far below the KEM's.

## Instances

`instances/whlwe-v1-nNNNN-{hankel,uniform}.json`, for n = 64, 96, 128, 160, 192, 224, 256, 320, 384, 448,
512, 576 and 640. Each instance is

    b = A s + e  mod q,   q = 4096,   s in Z^n and e in Z^m drawn from CBD_2 (values -2..2),

with m = round(1.2 n) samples: the ratio of the KEM's public key, which the n = 640 instances match
exactly (m = 768). Fields: `name`, `kind`, `n`, `m`, `q`, `public_seed` (hex), `b` (m integers in
[0, q)) and `secret_commitment` (hex).

**The public matrix.** Expand `public_seed` with SHAKE256 and read the output as little-endian 16-bit
words reduced mod q: `n + m - 1` words a for a Hankel instance, with `A[i][j] = a[i + j]`, or `m n` words
in row-major order for a uniform one. The seed is SHA-256 of the string
`WHLWE-challenge-v1/public/<name>`, so it depends only on the instance name and nobody chose the matrix.
`python3 verify.py --matrix <name>` prints A and b.

**The secret.** s and e come from a master seed held by the author. `secret_commitment` is SHA-256 of
`WHLWE-challenge-v1/commit/<name>/` followed by s as signed bytes, so a solution can be checked without
revealing the others. `index.json` holds a commitment to the master seed
(`3ea2f818a1734b3e63fa1927779b692ccf591fdab17efa242851a09ec9f030fa`) so that a later reveal of all
secrets can be checked too.

## Checking a solution

    python3 verify.py whlwe-v1-n0256-hankel solution.txt

where `solution.txt` holds the n coordinates of s, separated by commas, spaces or newlines. `SOLVED`
means the commitment matches. The script also reports whether b - A s mod q lies in [-2, 2]; another
secret with that property would itself be worth reporting. Only NumPy is needed.

## Expected difficulty

Generic attacks, from the lattice estimator (`estimates.sage`, commit `53da598`), treating the instances
as unstructured LWE: log2 of the cost, with the block size in parentheses. The estimator reports no
block size below 40, so the small sizes are better judged by the measured block sizes below. Its MATZOV
primal figures at n = 160 and 192 are an artifact of the cost model at small sizes.

| n | m | primal uSVP, Core-SVP | dual hybrid, Core-SVP | primal uSVP, MATZOV | dual hybrid, MATZOV |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 64 | 77 | 2^11.7 (40) | 2^12.4 (41) | 2^38.6 (40) | 2^40.4 (40) |
| 96 | 115 | 2^11.7 (40) | 2^13.0 (41) | 2^39.8 (40) | 2^41.6 (41) |
| 128 | 154 | 2^11.7 (40) | 2^17.4 (55) | 2^40.8 (40) | 2^41.9 (40) |
| 160 | 192 | 2^19.6 (67) | 2^23.7 (79) | 2^75.6 (193) | 2^49.9 (67) |
| 192 | 230 | 2^27.4 (94) | 2^30.5 (103) | 2^86.4 (232) | 2^57.6 (92) |
| 224 | 269 | 2^35.0 (120) | 2^37.6 (127) | 2^64.0 (120) | 2^63.6 (114) |
| 256 | 307 | 2^42.9 (147) | 2^45.1 (154) | 2^71.5 (147) | 2^70.3 (139) |
| 320 | 384 | 2^58.7 (201) | 2^59.5 (202) | 2^86.6 (201) | 2^84.9 (191) |
| 384 | 461 | 2^75.0 (257) | 2^74.5 (255) | 2^102.2 (257) | 2^99.6 (244) |
| 448 | 538 | 2^91.4 (313) | 2^89.9 (306) | 2^117.9 (313) | 2^114.5 (296) |
| 512 | 614 | 2^108.3 (371) | 2^105.4 (361) | 2^134.1 (371) | 2^129.6 (351) |
| 576 | 691 | 2^125.3 (429) | 2^121.2 (414) | 2^150.3 (429) | 2^145.1 (405) |
| 640 | 768 | 2^142.5 (488) | 2^137.1 (468) | 2^166.8 (488) | 2^160.3 (459) |

Measured with `baseline.py` (progressive BKZ 2.0 on the primal embedding, fpylll 0.6.4, Apple M3 Max):
both n = 64 instances fall to LLL alone, and both n = 96 instances at block size 15. Appendix E of the
paper reports, for n = 100 to 130 and 24 to 48 instances of each kind, the same success block sizes for
Hankel and uniform matrices (from about 20 at n = 100 to about 46 at n = 130).

## Reporting

Open an issue in this repository, or write to marcos.mendoza@tuta.com, with the instance name, the
output of `verify.py`, and enough about the method to reproduce it: the algorithm, its parameters and the cost. Results that compare a Hankel
instance with its uniform twin are the most useful, and so are negative results: a structural attack
that does no better than `baseline.py` is worth knowing about too. Solved instances will be listed here.

## Files

| File | Purpose |
| :--- | :--- |
| `instances/`, `index.json` | the challenge |
| `whlwe_challenge.py` | definitions: matrix expansion, commitments, solution check |
| `verify.py` | check a solution; print A and b |
| `baseline.py` | the generic primal attack, from public data only |
| `estimates.sage`, `estimates.txt`, `estimates.json` | the table above |
| `generate.py` | how the instances were made (needs the master seed; `--check` regenerates and compares) |
