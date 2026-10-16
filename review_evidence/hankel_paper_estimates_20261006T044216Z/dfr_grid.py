"""Paper Table 4 and Appendix A: Chernoff DFR bound for (q, eta, bits per coordinate) with n = 640.

A coordinate decodes correctly when its error lies in [-T, T - 1], T = q / 2^(bits + 1), so the bound adds
the two tails exactly: Pr[e >= T] + Pr[e <= -(T + 1)] = Pr[e >= T] + Pr[e >= T + 1] (e is symmetric), each
from its own Chernoff bound, then takes the union over the W coordinates. Earlier versions bounded the two
tails by 2 Pr[e >= T], which is also valid but slightly weaker (by up to 0.25 bits)."""
import math
def cbd(eta):
    return {v: math.comb(2*eta, v+eta) / 4**eta for v in range(-eta, eta+1)}
def log2_dfr(n, q, eta, bits):
    W = 256 // bits
    c = cbd(eta); prod = {}
    for x, px in c.items():
        for y, py in c.items():
            prod[x*y] = prod.get(x*y, 0) + px*py
    T = q // (2 ** (bits + 1))        # decision threshold: half the constellation spacing
    lm = lambda d, t: math.log(sum(p * math.exp(t*v) for v, p in d.items()))

    def tail(thr):
        f = lambda t: (2*n*lm(prod, t) + lm(c, t) - t*thr) / math.log(2)
        lo, hi = 1e-7, 3.0
        for _ in range(300):
            a, b = lo + (hi-lo)/3, hi - (hi-lo)/3
            lo, hi = (lo, b) if f(a) < f(b) else (a, hi)
        return f((lo+hi)/2)

    var = 2*n*(eta/2)**2 + eta/2
    upper, lower = tail(T), tail(T + 1)
    top = max(upper, lower)   # log-sum-exp, to avoid underflow
    return top + math.log2(2**(upper - top) + 2**(lower - top)) + math.log2(W), T / math.sqrt(var), W
print(f"{'q':>6} {'eta':>3} {'bits':>4} {'W':>4} {'T/sigma':>8} {'log2 DFR':>9}")
for q in (2**11, 2**12, 2**13):
    for eta in (1, 2, 3):
        for bits in (1, 2):
            d, ts, W = log2_dfr(640, q, eta, bits)
            print(f"{q:>6} {eta:>3} {bits:>4} {W:>4} {ts:8.2f} {d:9.1f}")
print("check (paper, q = 4096, eta = 2, 2 bits): log2 DFR =", round(log2_dfr(640, 4096, 2, 2)[0], 2))
print("chosen sets (two-sided bound, union over W = 128 coordinates):")
for name, n, q in (("WH-640", 640, 4096), ("WH-936", 936, 8192), ("WH-1208", 1208, 8192)):
    print(f"  {name}: log2 DFR = {log2_dfr(n, q, 2, 2)[0]:.2f}")
