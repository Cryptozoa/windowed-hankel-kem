"""Paper Table 3 and Appendix A: Chernoff DFR bound for (q, eta, bits per coordinate) with n = 640."""
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
    f = lambda t: (2*n*lm(prod, t) + lm(c, t) - t*T) / math.log(2)
    lo, hi = 1e-7, 3.0
    for _ in range(300):
        a, b = lo + (hi-lo)/3, hi - (hi-lo)/3
        lo, hi = (lo, b) if f(a) < f(b) else (a, hi)
    var = 2*n*(eta/2)**2 + eta/2
    return f((lo+hi)/2) + 1 + math.log2(W), T / math.sqrt(var), W
print(f"{'q':>6} {'eta':>3} {'bits':>4} {'W':>4} {'T/sigma':>8} {'log2 DFR':>9}")
for q in (2**11, 2**12, 2**13):
    for eta in (1, 2, 3):
        for bits in (1, 2):
            d, ts, W = log2_dfr(640, q, eta, bits)
            print(f"{q:>6} {eta:>3} {bits:>4} {W:>4} {ts:8.2f} {d:9.1f}")
print("check (paper):", round(log2_dfr(640, 4096, 2, 2)[0], 1))
