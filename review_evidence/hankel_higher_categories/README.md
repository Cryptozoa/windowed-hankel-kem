# Parameters for NIST Categories 3 and 5 (paper Appendix D)

Lattice estimator commit `53da5982597709ba0fdf94ea37a84d822310fd84`, run on native SageMath 10.9
(`/Library/anaconda3/envs/sage/bin/sage`), without the Sage 10.8 workaround shim. Run each `.sage`
file from this directory with `LATTICE_ESTIMATOR=/path/to/lattice-estimator sage <file>`.

| Script | Output | Content |
| :--- | :--- | :--- |
| `dfr.py` | `dfr_limits.txt` | Exact Chernoff DFR bound; largest n (step 32) meeting ML-KEM-768/1024's failure rates (2^-164.8, 2^-174.8, FIPS 203 Table 1) for each q, eta, encoding |
| `kyber_reference.sage` | `kyber_reference.txt` | Kyber-512/768/1024: primal and dual hybrid, Core-SVP and MATZOV |
| `families.sage` | `families_{A,B,C,D}.txt`, `refine_*.txt` | Cheapest of primal and dual hybrid, both models, failure rate and sizes, over n |
| `select_sets.py` | `selection.txt` | Smallest n per family and target, with the factor degrees of X^L - 1 over F_2 |
| `detail.sage` | `detail.txt` | Primal (uSVP, BDD), dual, dual hybrid and coded-BKW for the proposed sets |
| `embedding_check.sage` | `embedding_check.txt` | Full-rank check of the functional lattices for the plain dual and X - 1 at the proposed sizes |

Families (W = 256 / bits; m = n + W; L = 2n + W - 1):

- A: q = 2^13, CBD_2, 4-PAM (W = 128) -- proposed;
- B: q = 2^12, CBD_2, 1 bit per coordinate (W = 256);
- C: q = 2^12, CBD_1, 4-PAM (sparse ternary secret; set aside, as at Category 1);
- D: q = 2^13, CBD_3, 1 bit per coordinate.

Targets: the cheapest estimated attack at least 20 bits above Kyber-768 / Kyber-1024 in both cost
models (the margin Category 1 has over Kyber-512), and a failure rate no larger than ML-KEM's. Proposed
sets: n = 936 (L = 1999) and n = 1208 (L = 2543); both L are prime with ord_L(2) = 333 and 1271, so X - 1
is the only factor of X^L - 1 of small degree.
