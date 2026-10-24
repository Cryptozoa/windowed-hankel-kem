#!/usr/bin/env python3
"""Replication with 512 fresh instances per kind of the cells where the 64-instance run of
solution_counts.py showed nominally significant differences (m = 16), with their neighbours.
Seeds are disjoint from the first run (prefix 'rep')."""
import itertools, random, statistics, sys
import numpy as np
sys.path.insert(0, '.')
from solution_counts import roots, instance, count_solutions, tost_margin
T = 512
for Q, n, m in ((4096, 4, 16), (4096, 6, 16), (16, 6, 16), (4096, 6, 14), (4096, 6, 18)):
    X = np.array(list(itertools.product(roots(Q), repeat=n)), dtype=np.int64)
    st = {}
    for kind in ("hankel", "uniform"):
        c = [count_solutions(*instance(n, m, Q, kind, random.Random(f"rep-{Q}-{n}-{m}-{kind}-{t}")), X, Q) for t in range(T)]
        st[kind] = (statistics.mean(c), sum(x == 1 for x in c) / T)
    (mh, uh), (mu, uu) = st["hankel"], st["uniform"]
    d, ci, mg = tost_margin(uh, uu, T, T)
    print(f"Q={Q} n={n} m={m}: mean solutions {mh:.3f} vs {mu:.3f} | unique {uh:.3f} vs {uu:.3f}, diff {d:+.3f}, "
          f"95% CI [{ci[0]:+.3f}, {ci[1]:+.3f}], TOST margin {mg:.3f}", flush=True)
