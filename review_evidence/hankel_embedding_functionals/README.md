# Short functionals from the cyclic embedding (paper Section 4.3, Appendix C)

A public key `b = H_m(a) s + e` is the window of degrees `n-1 .. L-1` of `a(X) s~(X) mod (X^L - 1)`,
with `L = n + m - 1 = 1407`. For a factor `g` of `X^L - 1` over `Z/2^12` of degree `k`, functionals
`phi` with `H_m(a)^T phi = R_g^T c (mod q)` give `phi^T b = c^T (s~ mod g) + phi^T e`. They form the
q-ary lattice `Lambda_g = { phi : B_g phi = 0 mod q }`, `B_g` in `Z_q^((n-k) x m)`. This is the same
shape as the lattice of the dual hybrid attack that guesses `k` coordinates of `s`, so the question is
whether Hankel structure makes `Lambda_g` contain unusually short vectors.

`functionals.sage` (run with a SageMath that has fpylll; used: conda-forge SageMath 10.9, fpylll 0.6.4):

- Factors `X^1407 - 1` over `Z/2^12` via the 2-adic factorizations of `Phi_d` (`d | 1407`) and keeps the
  low-degree factors: `X - 1`, `Phi_3`, the two cubic factors of `Phi_7`, the two sextic factors of
  `Phi_21` (the other 21 factors have degree 66).
- `sage functionals.sage full` -> `full_size.txt`: for n = 640, m = 768 and 5 random sequences `a`,
  checks that `B_g` has full rank mod 2 (so `det Lambda_g = q^(n-k)`, as for a uniform matrix), and
  reports the Gaussian heuristic for `lambda_1`, the single-vector advantage `exp(-2 pi^2 (l/q)^2)` (for reference only; not an attack cost, and not used in the paper) of a functional of
  that length against unit-variance noise, and the entropy of `s~ mod g` (Gaussian approximation with
  covariance `R_g R_g^T`, capped at 12 bits per coordinate) against `2.031 k` bits for `k` coordinates of
  `s`.
- `sage functionals.sage case n W target trials seed` -> `cases/case_*.txt`: exact `lambda_1` (fpylll
  `SVP.shortest_vector` after LLL and BKZ-40 preprocessing) for Hankel-derived `B_g` and for uniform
  matrices of the same shape, divided by the Gaussian heuristic. Sizes `(n, W) = (40, 5), (48, 10),
  (56, 15)` (lattice dimension `m = 45, 58, 71`) are chosen so that `21 | L` and all six target factors
  divide `X^L - 1`; 20 instances per case for the first two sizes, 5 for the third. `cases/jobs.txt`
  lists the cases and `small_size.txt` collects the results.

## Biased functionals (`biased.sage` -> `biased.txt`)

Functionals with `H_m(a)^T phi = R_g^T c + w`, `w` short, give
`phi^T b = c^T (s~ mod g) + w^T s + phi^T e`. The pairs `(phi, w)` form the lattice
`{ (phi, w) : E_g (H^T phi - w) = 0 mod q }` of dimension `m + n` and determinant `q^(n-k)`
(`E_g` has kernel `{R_g^T c}` and contains an identity block).

- `sage biased.sage full`: at n = 640, the biased lattice's Gaussian heuristic is below that of the
  dual-hybrid lattice that guesses `k` coordinates (same determinant, dimension `m + n - k`) by at most
  0.02 bits (sextic factors), while the guess `s~ mod g` costs 4.7 to 58.8 bits more.
- `sage biased.sage small`: the lattice contains trivial vectors `(0, R_g^T c)` (`phi = 0`, no
  information), which for `X - 1` and `Phi_3` are far shorter than any useful vector. The script projects
  them away (orthogonally to the `k` vectors `(0, R_g^T e_t)`) and compares the projected lattice with its
  own Gaussian heuristic: exact SVP at `(n, W) = (24, 16)` (dimension 64), BKZ-40 first vector at
  `(32, 21)` and `(40, 5)` (dimension 85), 20 Hankel and 20 uniform instances per target. Mean ratios
  differ by at most 0.015 (exact) and 0.018 (BKZ-40), in both directions; smallest p = 0.086 over 21
  comparisons. The script uses 14 worker processes ("fork" start method) and took about 16 minutes.
