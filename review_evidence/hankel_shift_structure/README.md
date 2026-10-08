# Shifted dual functionals (paper, Section 4.3 and Table 2)

The Hankel analogue of ring rotations. If phi satisfies (H^T phi)_j = 0 mod q for j in J and
phi_{m-1} = 0, its shift (S phi)_i = phi_{i-1} has the same length and satisfies the constraints on
J - 1, since (H^T S phi)_j = (H^T phi)_{j+1}; symmetrically for S^{-1} when phi_0 = 0. Unlike a rotation
in a ring lattice, S phi is not in the original lattice.

| Script | Output | What it shows |
| :--- | :--- | :--- |
| `shift_check.py` | `shift_check.txt` | n = 48, m = 58, J = [0, 40), BKZ-20, 10 Hankel matrices: the shifted constraints hold for 228/228 (forward) and 171/171 (backward) reduced vectors, and the dropped constraint holds for none of them. Needs `../hankel_reduced_lattices/geometry.py`. |
| `matzov_vectors.sage` | `matzov_vectors.txt` | At the MATZOV dual-hybrid optimum for WH-640 (2^160.3, beta = 459), the distinguisher needs N = 2^94.9 short vectors; one sieve call yields about 2^95.2. |
| `free_vectors.sage` | `free_vectors.txt` | Upper bound: every request for N short vectors charged as N / T, with no extra guessing, and the attack re-optimized. For T = 2, 8, 64, 640 the estimate drops by 0.20, 0.27, 0.49, 0.89 bits (MATZOV) and 0.19, 0.34, 0.49, 1.03 bits (Core-SVP). |

Run the `.sage` files with `LATTICE_ESTIMATOR=/path/to/lattice-estimator sage <file>` (estimator commit
`53da5982597709ba0fdf94ea37a84d822310fd84`, SageMath 10.9) and `shift_check.py` with the Python of the
SageMath environment (fpylll 0.6.4).
