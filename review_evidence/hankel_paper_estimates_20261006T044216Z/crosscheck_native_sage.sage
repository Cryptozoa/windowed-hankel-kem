# Independent cross-check of every estimate in the paper, run WITHOUT sage_flint_shim on a native
# arm64 SageMath (conda-forge Sage 10.9), where FLINT works. Run from this directory:
#   LATTICE_ESTIMATOR=/path/to/lattice-estimator /path/to/sage-10.9/bin/sage crosscheck_native_sage.sage
# Estimator commit used: 53da5982597709ba0fdf94ea37a84d822310fd84 (malb/lattice-estimator, 2026-08-19)
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
from estimator.lwe_dual import dual_hybrid as dual_hybrid_fn
from functools import partial
from math import comb, log2

def lg(x):
    return f"2^{log2(int(x)) if x == int(x) else float(log(x, 2)):.1f}" if x != oo else "inf"

def show(tag, c):
    keys = [k for k in ("beta", "dreg", "m", "t") if k in c]
    rop = c["rop"]
    r = "inf" if rop == oo else (f"2^{log2(int(rop)):.1f}" if rop > 2**1000 else f"2^{float(log(rop, 2)):.1f}")
    print(f"{tag} :: rop {r} " + " ".join(f"{k} {c[k]}" for k in keys), flush=True)

print("Sage", version())
WH = LWE.Parameters(n=640, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=768, tag="WH640")
K = schemes.Kyber512
for name, P in (("WH640", WH), ("Kyber512", K)):
    for an, fn in (("usvp", LWE.primal_usvp), ("bdd", LWE.primal_bdd), ("dual", LWE.dual), ("dual_hybrid", LWE.dual_hybrid)):
        for rn, rc in (("CoreSVP", RC.ADPS16), ("MATZOV", RC.MATZOV)):
            show(f"{name} {an} {rn}", fn(P, red_cost_model=rc))
    show(f"{name} coded-bkw", LWE.coded_bkw(P))
for rn, rc in (("CoreSVP", RC.ADPS16), ("MATZOV", RC.MATZOV)):
    show(f"WH640 bdd_hybrid {rn}", LWE.primal_hybrid(WH, mitm=False, babai=False, red_cost_model=rc))
    show(f"WH640 bdd_mitm_hybrid {rn}", LWE.primal_hybrid(WH, mitm=True, babai=True, red_cost_model=rc))
    show(f"WH640 dual_mitm_hybrid {rn}", dual_hybrid_fn(WH, red_cost_model=rc, mitm_optimization=True))
for n, q, eta in ((512, 4096, 2), (576, 4096, 2), (704, 4096, 2), (640, 2048, 1), (640, 8192, 3)):
    P = LWE.Parameters(n=n, q=q, Xs=ND.CenteredBinomial(eta), Xe=ND.CenteredBinomial(eta), m=n + 128)
    for rn, rc in (("CoreSVP", RC.ADPS16), ("MATZOV", RC.MATZOV)):
        show(f"n={n} q={q} eta={eta} usvp {rn}", LWE.primal_usvp(P, red_cost_model=rc))
        show(f"n={n} q={q} eta={eta} dual_hybrid {rn}", LWE.dual_hybrid(P, red_cost_model=rc))
for n, q, eta in ((640, 4096, 2), (640, 2048, 1)):
    P = LWE.Parameters(n=n, q=q, Xs=ND.CenteredBinomial(eta), Xe=ND.CenteredBinomial(eta), m=768)
    show(f"n={n} q={q} eta={eta} arora-gb", LWE.arora_gb(P))
