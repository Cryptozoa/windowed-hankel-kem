# Subring attacks with the withheld coefficients as unknowns (paper, Section 4.3, Proposition 2).
#
# With L = n + m - 1 and c = a(X) s~(X) mod (X^L - 1), the coefficients c_{n-1..L-1} are the published
# window (b = c_window + e) and c_{0..n-2} = u are withheld. For a factor g of X^L - 1 of degree k,
#   c mod g = (u mod g) + (window part mod g),
# and u mod g = P_g u with P_g in Z_q^{k x (n-1)} (column i = X^i mod g). If P_g is onto Z_q^k, the
# withheld coefficients can give u mod g any value, so the equation modulo g alone says nothing about s,
# and the only u-free linear consequences of the ring relation are the window equations b = H s + e.
#
# Checks, for n = 640, m = 768, q = 2^12:
#   (1) the complete factorization of X^1407 - 1 over Z/2^12 (product check, degrees);
#   (2) the embedding identity c_window = H_m(a) s on random instances;
#   (3) P_g has full rank k modulo 2 (hence is onto Z_q^k) for every irreducible factor g.
# Run: sage subrings.sage
n, m, q = 640, 768, 4096
L = n + m - 1
Zq = Zmod(q)
R.<Y> = Zq[]
set_random_seed(20261008)

def factors_mod_q(d):
    K = Qp(2, prec=60)
    out = []
    for f, mult in cyclotomic_polynomial(d).change_ring(K).factor():
        assert mult == 1
        out.append(R([Zq(ZZ(c.lift() if hasattr(c, "lift") else c)) for c in f.monic().list()]))
    return out

print("Sage", version())
print(f"n = {n}, m = {m}, q = {q}, L = {L} = {factor(L)}")

# (1) factorization of X^L - 1 = prod_{d | L} Phi_d over Z/2^12
factors = []
for d in divisors(L):
    fs = factors_mod_q(d)
    factors += [(d, g) for g in fs]
    print(f"Phi_{d:<5d} degree {euler_phi(d):4d}: {len(fs):3d} factors of degree {sorted(set(g.degree() for _, g in [(d, x) for x in fs]))}")
prod = R(1)
for _, g in factors:
    prod *= g
assert prod == Y**L - 1, "factorization check failed"
degs = sorted(g.degree() for _, g in factors)
print(f"(1) {len(factors)} irreducible factors, product equals X^{L} - 1 mod {q}; largest degree {max(degs)} <= n - 1 = {n - 1}")

# (2) embedding identity on random instances
for t in range(3):
    a = [Zq.random_element() for _ in range(L)]
    s = [Zq(randint(-2, 2)) for _ in range(n)]
    st = R([s[n - 1 - i] for i in range(n)])          # s~ = sum_j s_j X^(n-1-j)
    c = (R(a) * st) % (Y**L - 1)
    cl = c.list() + [Zq(0)] * (L - len(c.list()))
    Hs = [sum(a[i + j] * s[j] for j in range(n)) for i in range(m)]
    assert cl[n - 1:L] == Hs, "embedding identity failed"
print("(2) window of a(X) s~(X) mod (X^L - 1) equals H_m(a) s on 3 random instances")

# (3) u -> u mod g is onto for every factor
GF2 = GF(2)
for d, g in factors:
    k = g.degree()
    P = matrix(Zq, k, n - 1)
    p = R(1)
    for i in range(n - 1):
        col = p.list() + [Zq(0)] * (k - len(p.list()))
        for r in range(k):
            P[r, i] = col[r]
        p = (p * Y) % g
    assert P.change_ring(GF2).rank() == k, f"P_g not onto for a factor of Phi_{d}"
print(f"(3) for all {len(factors)} factors, u -> u mod g has full rank modulo 2 (onto Z_q^k)")
print("Conclusion: modulo any single factor, the withheld coefficients mask the equation completely;")
print("eliminating them from the full ring relation leaves exactly the m window equations b = H s + e.")
