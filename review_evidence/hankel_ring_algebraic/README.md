# Algebraic structure over Z/2^12 (paper, Appendix E and Section 4.4)

The XL experiments of Appendix E run over GF(4093), which removes the zero divisors and the 2-adic
structure of the scheme's ring Z/2^12. This folder covers that ring.

| File | Contents |
| :--- | :--- |
| `layers.py`, `layers.txt` | Exact. The reduction of WH-640 modulo 2^j carries at most m (j - H(e mod 2^j)) bits about s: 0 bits modulo 2 (CBD_2 is uniform modulo 2), 72.5 modulo 4, 744.5 modulo 8, against 640, 1,219.6 and 1,299.6 bits of entropy in s mod 2^j; only from modulo 16 on can the reduced data determine the secret. The Arora-Ge error polynomial prod (t - c) over the CBD_2 support has 24 roots modulo 4096 (5 in the support). |
| `projections.sage`, `projections.txt` | Lattice estimator (53da598, rough) for the reductions modulo 16 and 32: 2^382.8 and 2^316.5, against 2^137.1 for the full instance. |
| `solution_counts.py`, `.txt` | Exact solution counts of the Arora-Ge system l^3 - l = 0, x^3 - x = 0 (CBD_1) over Z/16 and Z/4096, n = 4, 6, 8, m around the uniqueness threshold, 64 Hankel and 64 uniform instances per cell: confidence intervals and TOST margins for the difference in the fraction of uniquely solvable instances. |
| `replicate.py`, `.txt` | 512 fresh instances per kind for the m = 16 cells, where the 64-instance run showed nominally significant differences, and their neighbours: all differences within 0.020, all intervals contain zero, TOST margins 0.018-0.054. |

Groebner bases over Z/2^k (Singular via Sage) do not isolate the secret even when it is the unique
solution: polynomials such as 8x(x - 1) vanish on every root of x^3 - x modulo 16 without lying in the
ideal, so we count solutions exhaustively over the five roots of x^3 = x in each coordinate instead.

Run from the repository root: `python3 review_evidence/hankel_ring_algebraic/layers.py`,
`python3 review_evidence/hankel_ring_algebraic/solution_counts.py` (about 1.5 minutes), then
`cd review_evidence/hankel_ring_algebraic && python3 replicate.py`; the estimate needs Sage and the
lattice estimator (`ESTIMATOR=... sage projections.sage`).
