# Run from this directory: checks that the exact gb_cost replacement reproduces the estimator's
# documented examples (estimator/gb.py docstrings, commit 53da598).
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
sys.path.insert(0, os.getcwd())
from estimator import *
import sage_flint_shim; sage_flint_shim.install(); sage_flint_shim.install_gb()
from estimator.gb import gb_cost
c = gb_cost(128, [(2, 256)]); print("gb_cost(128, [(2, 256)])  expect rop 2^144.6, dreg 17 ::", f"rop 2^{float(log(c['rop'], 2)):.1f} dreg {c['dreg']}")
params = LWE.Parameters(n=64, q=7681, Xs=ND.DiscreteGaussian(3.0), Xe=ND.DiscreteGaussian(3.0), m=2**50)
checks = [
    ("base m=2^50                expect 2^307.1 dreg 99", params),
    ("m=2^120                    expect 2^282.6 dreg 83", params.updated(m=2**120)),
    ("Xe=UniformMod(7)           expect 2^60.6 dreg 7", params.updated(Xe=ND.UniformMod(7))),
    ("Xe=CBD(8)                  expect 2^122.3 dreg 19", params.updated(Xe=ND.CenteredBinomial(8))),
    ("Xs=U(5) Xe=CBD(4) m=1024   expect 2^227.2 dreg 54", params.updated(Xs=ND.UniformMod(5), Xe=ND.CenteredBinomial(4), m=1024)),
    ("Xs=U(3) Xe=CBD(4) m=1024   expect 2^189.9 dreg 39", params.updated(Xs=ND.UniformMod(3), Xe=ND.CenteredBinomial(4), m=1024)),
]
for label, P in checks:
    c = LWE.arora_gb(P); print(label, "::", f"rop 2^{float(log(c['rop'], 2)):.1f} dreg {c['dreg']}", flush=True)
