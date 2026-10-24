# LWE estimates (lattice-estimator 53da598, rough mode) for the reductions of WH-640 modulo 16 and 32,
# and the full instance modulo 4096 for comparison. Run with native Sage 10.9:
#   sage review_evidence/hankel_ring_algebraic/projections.sage  (set ESTIMATOR to the estimator checkout)
import os, sys
sys.path.insert(0, os.environ.get("ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
for q in (16, 32, 4096):
    p = LWE.Parameters(n=640, q=q, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=768, tag=f"WH-640 mod {q}")
    r = LWE.estimate.rough(p)
    print(f"mod {q}: " + ", ".join(f"{k} 2^{float(log(v['rop'], 2)):.1f}" for k, v in r.items()), flush=True)
