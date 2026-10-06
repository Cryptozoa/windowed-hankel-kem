# Workaround for this x86_64 Sage 10.8 build under Rosetta: FLINT's arb_exp raises SIGILL
# when Sage evaluates symbolic log/exp of Python floats
# (and of constant symbolic expressions). Routing float arguments through
# MPFR (RealField) gives the same values without touching FLINT. The estimator clone itself
# is unmodified.
import sys
from sage.all import RealField
from sage.symbolic.expression import Expression
_R = RealField(256)
def _wrap(f):
    def g(*a, **k):
        a = tuple(_R(x) if isinstance(x, float) or (isinstance(x, Expression) and x.is_constant()) else x
                  for x in a)
        return f(*a, **k)
    g.__wrapped__ = f
    return g
def install():
    for name, mod in list(sys.modules.items()):
        if name.startswith("estimator") and mod is not None:
            for fn in ("log", "exp", "coth", "sqrt"):
                if hasattr(mod, fn) and not hasattr(getattr(mod, fn), "__wrapped__"):
                    setattr(mod, fn, _wrap(getattr(mod, fn)))
