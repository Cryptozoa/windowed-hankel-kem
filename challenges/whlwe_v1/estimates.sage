# Generic-attack estimates for every challenge size (lattice estimator, commit 53da598): the instances
# treated as unstructured LWE, n, m = 1.2 n, q = 4096, CBD_2 secret and error. Primal uSVP and dual hybrid
# under Core-SVP (ADPS16) and MATZOV. A Hankel instance solved at clearly lower cost than these, or than its
# uniform twin, is evidence of a structural weakness.
# Run: LATTICE_ESTIMATOR=/path/to/lattice-estimator sage estimates.sage
import os, sys, json
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/Documents/lattice-estimator")))
from estimator import *
SIZES = tuple(int(x) for x in os.environ["SIZES"].split(",")) if "SIZES" in os.environ else (64, 96, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640)
out = {}
print(f"{'n':>4} {'m':>4} | {'uSVP CoreSVP':>14} {'DH CoreSVP':>14} | {'uSVP MATZOV':>14} {'DH MATZOV':>14}", flush=True)
for n in SIZES:
    m = round(1.2 * n)
    P = LWE.Parameters(n=n, q=4096, Xs=ND.CenteredBinomial(2), Xe=ND.CenteredBinomial(2), m=m)
    row = {}
    for an, fn in (("usvp", LWE.primal_usvp), ("dual_hybrid", LWE.dual_hybrid)):
        for rn, rc in (("core_svp", RC.ADPS16), ("matzov", RC.MATZOV)):
            c = fn(P, red_cost_model=rc)
            row[f"{an}_{rn}"] = {"log2_cost": float(f"{float(log(c['rop'], 2)):.1f}"), "beta": int(c["beta"])}
    out[str(n)] = row
    f = lambda k: f"2^{row[k]['log2_cost']:.1f} ({row[k]['beta']})"
    print(f"{n:4d} {m:4d} | {f('usvp_core_svp'):>14} {f('dual_hybrid_core_svp'):>14} | {f('usvp_matzov'):>14} {f('dual_hybrid_matzov'):>14}", flush=True)
json.dump({"estimator_commit": "53da5982597709ba0fdf94ea37a84d822310fd84", "note": "log2 cost (block size); the estimator reports no block size below 40", "estimates": out},
          open("estimates.json", "w"), indent=1)
