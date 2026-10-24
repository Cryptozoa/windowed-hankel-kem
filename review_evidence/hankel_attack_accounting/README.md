# Fast Hankel products in the attack cost (paper, Section 7)

Hankel matrix-vector products cost O((m + n) log(m + n)) by FFT instead of m n. This folder checks where an
attacker could use them in the attacks behind the paper's estimates.

| File | Contents |
| :--- | :--- |
| `fast_products.sage`, `.txt` | The dual hybrid attack (lattice-estimator 53da598, class MATZOV) at the published optima: the per-candidate work (FFT over t coordinates, table updates over the N dual vectors) does not multiply by A; the one-time products of the N dual vectors with the zeta + t guessed columns cost N m (zeta + t) = 2^111.4 (Core-SVP) and 2^110.1 (MATZOV), against totals of 2^137.1 and 2^160.3, and the estimator does not charge them. |

Lattice reduction does not multiply by A; the structural effect it could exploit, shifts of short dual
vectors, is bounded at about one bit in `review_evidence/hankel_shift_structure/`. Making the whole guessing
phase free is not a meaningful bound: it also makes exhaustive search over the guessed coordinates free.

Run: `ESTIMATOR=/path/to/lattice-estimator sage review_evidence/hankel_attack_accounting/fast_products.sage`
