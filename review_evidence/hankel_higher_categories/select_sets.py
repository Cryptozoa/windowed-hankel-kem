"""Smallest n per family meeting each target, and the factor structure of X^L - 1 over F_2 (L = 2n + W - 1).

Targets (log2, Core-SVP / MATZOV, cheapest attack): parity with Kyber-768/1024 (kyber_reference.txt) and
parity + 20 bits, the margin Category 1 has over Kyber-512. Failure-rate targets: ML-KEM-768/1024
(FIPS 203, Table 1): 2^-164.8 and 2^-174.8.
"""
import re, glob
from sympy import divisors, totient, isprime

TARGETS = {"Cat3 parity": (174.3, 196.4, -164.8), "Cat3 +20": (194.3, 216.4, -164.8),
           "Cat5 parity": (241.8, 262.3, -174.8), "Cat5 +20": (261.8, 282.3, -174.8)}
W_OF = {"A": 128, "B": 256, "C": 128, "D": 256}

def ordmod(a, d):
    k, x = 1, a % d
    while x != 1:
        x, k = x * a % d, k + 1
    return k

def factor_degrees(L):
    degs = {}
    for d in divisors(L):
        if d > 1:
            o = ordmod(2, d)
            degs[o] = degs.get(o, 0) + int(totient(d)) // o
    return dict(sorted(degs.items()))

rows = set()
for f in glob.glob("families_*.txt") + glob.glob("refine_*.txt"):
    for line in open(f):
        m = re.match(r"(\w) n=(\d+) q=2\^(\d+) eta=(\d) bits=(\d) \| min CoreSVP ([\d.]+) MATZOV ([\d.]+) \| "
                     r"DFR 2\^(-[\d.]+) \| pk (\d+) ct (\d+) total (\d+)", line)
        if m:
            g = m.groups()
            rows.add((g[0], int(g[1]), int(g[2]), int(g[3]), int(g[4]), float(g[5]), float(g[6]), float(g[7]),
                      int(g[8]), int(g[9]), int(g[10])))
for name, (tc, tm, tdfr) in TARGETS.items():
    print(name)
    for fam in "ABCD":
        ok = [r for r in rows if r[0] == fam and r[5] >= tc and r[6] >= tm and r[7] <= tdfr]
        if not ok:
            continue
        r = min(ok, key=lambda r: r[1])
        L = 2 * r[1] + W_OF[fam] - 1
        degs = factor_degrees(L)
        small = {k: v for k, v in degs.items() if k <= 20}
        print(f"  {fam}: n={r[1]:5d} q=2^{r[2]} eta={r[3]} bits={r[4]} CoreSVP {r[5]:.1f} MATZOV {r[6]:.1f} "
              f"DFR 2^{r[7]:.1f} pk {r[8]} ct {r[9]} total {r[10]} | L={L}{' prime' if isprime(L) else ''}, "
              f"small factors of X^L-1 besides X-1: {small or 'none'}")
