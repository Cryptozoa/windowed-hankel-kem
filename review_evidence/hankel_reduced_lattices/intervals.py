#!/usr/bin/env python3
"""
Confidence intervals for the primal-attack block sizes of Appendix E (Table 14).

For each n, from the per-trial records primal_n*.txt: the mean success block size of Hankel minus
uniform instances, a 95% Welch confidence interval for that difference, and the equivalence margin of a
two one-sided tests (TOST) procedure at the 5% level, i.e. the smallest Delta such that the 90% Welch
interval lies inside [-Delta, Delta]. A structural advantage of Delta or more blocks is then excluded at
that level for that n.
Run from the repository root: python3 review_evidence/hankel_reduced_lattices/intervals.py
"""
import glob
import os
import re

import numpy as np
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
print(" n   trials   mean(H) - mean(U)   95% CI            TOST margin (5%)")
for path in sorted(glob.glob(os.path.join(HERE, "primal_n*.txt")), key=lambda p: int(re.findall(r"\d+", os.path.basename(p))[0])):
    n = int(re.findall(r"\d+", os.path.basename(path))[0])
    h, u = [], []
    for line in open(path):
        m = re.match(r"(hankel|uniform)\s+seed \d+ success_beta (\d+)", line)
        if m:
            (h if m.group(1) == "hankel" else u).append(int(m.group(2)))
    h, u = np.array(h, float), np.array(u, float)
    d = h.mean() - u.mean()
    va, vb = h.var(ddof=1) / len(h), u.var(ddof=1) / len(u)
    se = np.sqrt(va + vb)
    df = (va + vb) ** 2 / (va ** 2 / (len(h) - 1) + vb ** 2 / (len(u) - 1))
    lo95, hi95 = d - stats.t.ppf(0.975, df) * se, d + stats.t.ppf(0.975, df) * se
    lo90, hi90 = d - stats.t.ppf(0.95, df) * se, d + stats.t.ppf(0.95, df) * se
    print(f"{n:3d}   {len(h):2d}/{len(u):2d}      {d:+.2f}            [{lo95:+.2f}, {hi95:+.2f}]    {max(abs(lo90), abs(hi90)):.2f}")
