# Embedding check at the proposed sizes (cf. Appendix C for Category 1). For q = 2^13, W = 128:
#   n = 936  -> L = 1999 (prime, ord_L(2) = 333);  n = 1208 -> L = 2543 (prime, ord_L(2) = 1271).
# X^L - 1 has X - 1 as its only factor of degree below 333 over F_2, hence over Z/2^13 (Hensel).
# For g in {none (plain dual), X - 1}: is B_g of full rank mod 2 (det Lambda_g = q^(n-k)) for random a?
import sys
from math import lgamma, log2, pi, e as E
set_random_seed(20261007)
q, LOGQ, W = 8192, 13, 128
def ordmod(a, d):
    k, x = 1, a % d
    while x != 1:
        x, k = x * a % d, k + 1
    return k
for n in (936, 1208):
    m, L = n + W, 2 * n + W - 1
    assert is_prime(L)
    degs = sorted(set(ordmod(2, d) for d in divisors(L) if d > 1))
    print(f"n={n} m={m} L={L}: prime; degrees of the irreducible factors of X^L-1 besides X-1: {degs}", flush=True)
    for name, k in (("plain", 0), ("X-1", 1)):
        ok = 0
        for t in range(5):
            a = [randint(0, q - 1) for _ in range(n + m - 1)]
            HT = matrix(GF(2), n, m, lambda j, i: a[i + j] % 2)
            if k == 1:  # c = (H^T phi)_{n-1}; rows j < n-1: (H^T phi)_j - (H^T phi)_{n-1}
                B = matrix(GF(2), [HT.row(j) - HT.row(n - 1) for j in range(n - 1)])
            else:
                B = HT
            ok += int(B.rank() == n - k)
        logdet = LOGQ * (n - k)
        lgh = (lgamma(m / 2 + 1) / m - 0.5 * log(pi)) / log(2.0) + logdet / m
        ent = 0 if k == 0 else 0.5 * log2(2 * pi * E * n)  # s(1) ~ sum of n CBD_2, variance n
        print(f"  {name:5s} k={k}: full rank mod 2 in {ok}/5; log2 det {logdet}; GH {2**lgh:.0f} (q = {q}); "
              f"bits to guess: {ent:.1f} vs {2.031 * k:.1f} for k coordinates of s", flush=True)
