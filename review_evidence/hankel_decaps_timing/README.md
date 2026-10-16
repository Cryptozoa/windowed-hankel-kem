# Decapsulation timing: accept versus reject (paper, Section 8)

`decaps_timing.py` decapsulates a fixed ciphertext under its own secret key (accepts) or under one of 64
other keys (rejects), in random order, 20,000 calls per class, with every input prepared before timing.
It reports the Welch t statistic (slowest 10% trimmed), the medians, and a control that splits the
accepting calls into two random halves. `decaps_timing.txt` holds three runs for each parameter set:

| Set | accept vs reject, abs(t), runs 1-3 | control abs(t), max | medians |
| :--- | :--- | :---: | :--- |
| WH-640 | 0.53, 0.86, 0.58 | 1.77 | equal, or one timer tick (41 ns) apart |
| WH-936 | 0.99, 2.06, 0.43 | 1.46 | equal in all runs |
| WH-1208 | 0.82, 0.36, 0.14 | 1.84 | equal, or three ticks (124 ns) apart, out of about 55 µs |

These are the runs of v0.3, whose decapsulation follows the exact FO transform (one SHAKE256 call to H
over the received ciphertext, with its input selected in constant time), on an idle machine; a run made
while another job used all cores was discarded. The v0.2 runs are in the history of this file.

Run from the repository root after `make`, with Python 3 and NumPy:
`python3 review_evidence/hankel_decaps_timing/decaps_timing.py` (Apple M3 Max, Apple clang 21, -O3).
