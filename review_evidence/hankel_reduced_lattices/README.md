# Lattice reduction at reduced dimensions: Hankel versus uniform matrices (paper, Appendix E)

Attack-agnostic test of the reduced-dimension criterion of Section 4.4: if lattice reduction could
exploit the Hankel structure, Hankel instances would fall at smaller block sizes, or their lattices
would reduce to shorter vectors, than instances with uniform matrices of the same shape. All runs use
q = 4096, CBD_2, fpylll 0.6.4 with BKZ 2.0 and its default strategies, in the Python of the conda-forge
SageMath 10.9 environment, 14 worker processes on an Apple M3 Max.

## Primal attack with a planted secret (`primal.py`, `run_primal.sh`)

Kannan embedding of b = A s + e, progressive BKZ (two tours per block size from 3), success when a
basis vector equals +-(-e, s, -1). m minimizes the block size predicted by the 2016 estimate, using the
estimator's root-Hermite-factor table below block size 40 (`predict.sage` shows the estimator itself,
which reports no block size below 40). All instances were solved.

| n | m | d | predicted beta | Hankel mean (sd) | uniform mean (sd) | trials per kind | Mann-Whitney p |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 100 | 87 | 188 | 10 | 19.83 (2.37) | 19.54 (2.42) | 48 | 0.607 |
| 110 | 119 | 230 | 15 | 26.19 (3.13) | 26.65 (3.14) | 48 | 0.521 |
| 120 | 124 | 245 | 25 | 37.00 (3.54) | 36.06 (4.32) | 48 | 0.245 |
| 130 | 143 | 274 | 40 | 45.54 (1.59) | 45.58 (3.27) | 24 | 0.215 |

Outputs: `primal_n100.txt` ... `primal_n130.txt` (one line per trial with seed, success block size and
time, then the summary). Two calibration runs are not included: one used the asymptotic root Hermite
factor below block size 40, which is invalid there and chose far too few samples; the other, at
n = 110 with 7 trials per kind, gave a mean difference of -2.71 (p = 0.069), which the 48-trial run
does not confirm (-0.46, p = 0.521).

## Lattice geometry without a target (`geometry.py`, `run_geometry.sh`)

BKZ-30 (at most 8 tours), m = 1.2 n, 32 trials per kind. Metrics: first vector relative to the Gaussian
heuristic, achieved root Hermite factor, slope of the log Gram-Schmidt profile over the middle half.

| Lattice | n | log2(b1/GH), Hankel / uniform (p) | GS slope, Hankel / uniform (p) | file |
| :--- | :---: | :---: | :---: | :--- |
| dual attack, Lambda(A^T), det q^n | 100 | 3.442 / 3.432 (0.672) | -0.05055 / -0.05049 (0.506) | `geometry_dualsec_n100.txt` |
| dual attack, Lambda(A^T), det q^n | 120 | 4.394 / 4.404 (0.555) | -0.05083 / -0.05080 (0.835) | `geometry_dualsec_n120.txt` |
| primal, Lambda(A), det q^m | 100 | 3.442 / 3.436 (0.840) | -0.05102 / -0.05104 (0.773) | `geometry_primal_n100.txt` |
| primal, Lambda(A), det q^m | 120 | trivial q-vector in all runs | -0.05179 / -0.05167 (0.128) | `geometry_primal_n120.txt` |
| Lambda_perp(A), det q^n | 100 | trivial q-vector in all runs | -0.04135 / -0.04131 (0.577) | `geometry_dual_n100.txt` |
| Lambda_perp(A), det q^n | 120 | trivial q-vector in all runs | -0.04186 / -0.04194 (0.432) | `geometry_dual_n120.txt` |

Where BKZ-30 finds nothing shorter than the trivial vectors of length q, the first-vector metric is
constant and uninformative (p reported as nan); the slope still compares the two kinds.

Commands: `./run_primal.sh`; `./run_geometry.sh "dualsec 100 120" "dualsec 120 144" "primal 100 120"
"primal 120 144" "dual 100 120" "dual 120 144"`; `LATTICE_ESTIMATOR=/path/to/lattice-estimator sage
predict.sage`.
