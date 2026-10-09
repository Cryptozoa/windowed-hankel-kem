# Decapsulation timing: accept versus reject (paper, Section 8)

`decaps_timing.py` decapsulates a fixed ciphertext under its own secret key (accepts) or under one of 64
other keys (rejects), in random order, 20,000 calls per class, with every input prepared before timing.
It reports the Welch t statistic (slowest 10% trimmed), the medians, and a control that splits the
accepting calls into two random halves. `decaps_timing.txt` holds three runs for each parameter set:

| Set | accept vs reject, abs(t), runs 1-3 | control abs(t), max | medians |
| :--- | :--- | :---: | :--- |
| WH-640 | 0.46, 2.13, 0.61 | 0.86 | equal in all runs |
| WH-936 | 0.20, 2.17, 2.42 | 1.73 | equal, or one timer tick (41 ns) apart |
| WH-1208 | 1.48, 0.63, 1.07 | 1.42 | equal in all runs |

Run from the repository root after `make`, with Python 3 and NumPy:
`python3 review_evidence/hankel_decaps_timing/decaps_timing.py` (Apple M3 Max, Apple clang 17, -O3).
