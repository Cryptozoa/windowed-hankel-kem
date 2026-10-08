# Kyber-512/768/1024 under the same estimator and cost models (yardsticks for Categories 1/3/5).
# Run: LATTICE_ESTIMATOR=~/Documents/lattice-estimator sage kyber_reference.sage   (SageMath 10.9, native)
# Estimator commit: 53da5982597709ba0fdf94ea37a84d822310fd84
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
for K in (schemes.Kyber512, schemes.Kyber768, schemes.Kyber1024):
    out = []
    for rc in (RC.ADPS16, RC.MATZOV):
        u = LWE.primal_usvp(K, red_cost_model=rc); d = LWE.dual_hybrid(K, red_cost_model=rc)
        out.append((float(log(u['rop'], 2)), float(log(d['rop'], 2))))
    print(f"{K.tag}: CoreSVP usvp {out[0][0]:.1f} dual_hybrid {out[0][1]:.1f} | MATZOV usvp {out[1][0]:.1f} dual_hybrid {out[1][1]:.1f}", flush=True)
