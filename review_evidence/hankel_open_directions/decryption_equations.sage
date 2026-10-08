# Cost of the "decryption equations" that ciphertexts give about the secret key s (paper, Section 5.3).
#
# For each ciphertext (u, v) under the public key b = H(a) s + e,
#   v - H_W(u) s = PAM(M) + N,   N = e2 + H_W(e) r - H_W(e1) s,
# and PAM(M) is a multiple of q/4 = 1024. Reducing modulo 1024 removes the unknown message, so each
# ciphertext gives W = 128 LWE samples (H_W(u), v mod 1024) in s with noise N of variance 2n + 1 = 1281
# (sigma ~ 35.79). An attacker can collect any number of ciphertexts: m = oo. The estimator treats the
# samples as independent; in fact N depends on s and e, which is covered by the hybrid argument of
# Section 5.3 rather than by this estimate.
#
# Run from this directory:
#   LATTICE_ESTIMATOR=/path/to/lattice-estimator sage decryption_equations.sage
# Estimator commit: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
from math import log2

def show(tag, c):
    rop = c["rop"]
    r = "inf" if rop == oo else f"2^{float(log(rop, 2)):.1f}"
    extra = " ".join(f"{k} {c[k]}" for k in ("beta", "m", "d", "zeta") if k in c)
    print(f"{tag:34s} rop {r:>10s}  {extra}", flush=True)

print("Sage", version())
sigma = sqrt(2 * 640 + 1)
P = LWE.Parameters(n=640, q=1024, Xs=ND.CenteredBinomial(2), Xe=ND.DiscreteGaussian(float(sigma)), m=oo,
                   tag="WH640-decryption-equations")
print(P)
print(f"q/sigma = {1024 / float(sigma):.1f} (public key: 4096/1 = 4096)")
for an, fn in (("primal uSVP", LWE.primal_usvp), ("primal BDD", LWE.primal_bdd), ("dual", LWE.dual),
               ("dual hybrid", LWE.dual_hybrid)):
    for rn, rc in (("Core-SVP", RC.ADPS16), ("MATZOV", RC.MATZOV)):
        try:
            show(f"{an} [{rn}]", fn(P, red_cost_model=rc))
        except Exception as ex:
            print(f"{an} [{rn}] failed: {type(ex).__name__}: {ex}", flush=True)
for an, fn in (("coded-BKW", LWE.coded_bkw),):
    try:
        show(an, fn(P))
    except Exception as ex:
        print(f"{an} failed: {type(ex).__name__}: {ex}", flush=True)
