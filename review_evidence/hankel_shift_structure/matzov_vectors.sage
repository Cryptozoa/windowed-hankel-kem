# Does the MATZOV dual-hybrid optimum for WH-640 need more short vectors than one sieve call yields?
# Shifted functionals could at best multiply the supply of short vectors (paper, Section 4.4); that only
# saves work if the required number N exceeds the sieve's output 2^(0.2075 beta'), so that the
# estimator charges for repeated sieving.
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
from estimator.lwe_dual import dual_hybrid
WH = LWE.Parameters(n=640, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=768, tag="WH640")
c = LWE.dual_hybrid(WH, red_cost_model=RC.MATZOV)
print(c)
bs = c["beta_"] if "beta_" in c else c["beta"]
for k in sorted(c.keys()):
    print(f"  {k}: {c[k]}")
print(f"log2 N = {float(log(c['N'], 2)):.2f}" if "N" in c else "no N field")
print(f"one sieve call in dimension beta' = {bs} yields about 2^{0.2075 * float(bs):.2f} vectors")
