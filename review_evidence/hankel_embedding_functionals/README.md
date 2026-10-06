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
