import math
def cbd(eta): return {v: math.comb(2*eta, v+eta)/4**eta for v in range(-eta, eta+1)}
_prod = {}
def prod(eta):
    if eta not in _prod:
        c = cbd(eta); pr = {}
        for x, px in c.items():
            for y, py in c.items(): pr[x*y] = pr.get(x*y, 0) + px*py
        _prod[eta] = pr
    return _prod[eta]
def log2_dfr(n, q, eta, bits):
    W = 256 // bits; c = cbd(eta); pr = prod(eta); T = q // 2**(bits+1)
    lm = lambda d, t: math.log(sum(p*math.exp(t*v) for v, p in d.items()))
    f = lambda t: (2*n*lm(pr, t) + lm(c, t) - t*T) / math.log(2)
    lo, hi = 1e-7, 4.0
    for _ in range(200):
        a, b = lo+(hi-lo)/3, hi-(hi-lo)/3
        lo, hi = (lo, b) if f(a) < f(b) else (a, hi)
    return f((lo+hi)/2) + 1 + math.log2(W)
if __name__ == "__main__":
    # largest n (step 32) meeting each failure target, per (q, eta, bits)
    for tgt_name, tgt in (("Cat3 <= 2^-164.8", -164.8), ("Cat5 <= 2^-174.8", -174.8)):
        print(tgt_name)
        for q in (2**12, 2**13, 2**14):
            for eta in (1, 2, 3):
                for bits in (2, 1):
                    best = None
                    for n in range(640, 3001, 32):
                        if log2_dfr(n, q, eta, bits) <= tgt: best = n
                    print(f"  q=2^{q.bit_length()-1} eta={eta} bits={bits}: max n = {best}")
