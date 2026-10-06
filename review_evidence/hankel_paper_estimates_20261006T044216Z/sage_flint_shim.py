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


def _gb_cost_exact(n, D, omega=2, prec=None):
    """Drop-in replacement for estimator.gb.gb_cost (same output).

    The original expands prod_(d,m) (1 - z^d)^m / (1 - z)^n as a Sage power series over QQ; with
    n = 640 the coefficients are very large and FLINT's polynomial multiplication raises an
    exception in this Sage build. Here the same series is computed exactly with Python integers:
    the expansion of each (1 - z^d)^m is sparse, and 1/(1 - z)^n has coefficients C(n-1+i, i).
    The degree of regularity is the index of the first negative coefficient, as in the original.
    """
    from math import comb
    from sage.all import binomial, oo
    from estimator.cost import Cost
    prec = 2 * n if prec is None else prec
    num = [0] * prec
    num[0] = 1
    for d, m in D:
        m = int(m)
        terms = [(d * k, (-1) ** k * comb(m, k)) for k in range(0, (prec - 1) // d + 1) if k <= m]
        new = [0] * prec
        for i, c in enumerate(num):
            if c:
                for shift, t in terms:
                    if i + shift >= prec:
                        break
                    new[i + shift] += c * t
        num = new
    den = [comb(n - 1 + i, i) for i in range(prec)]
    retval = Cost(rop=oo, dreg=oo)
    retval.register_impermanent({"rop": True, "dreg": False, "mem": False})
    for dreg in range(prec):
        coeff = sum(num[k] * den[dreg - k] for k in range(dreg + 1) if num[k])
        if coeff < 0:
            retval["dreg"] = dreg
            retval["rop"] = binomial(n + dreg, dreg) ** omega
            retval["mem"] = binomial(n + dreg, dreg) ** 2
            break
    return retval


def install_gb():
    """Route the Arora-GB estimate through _gb_cost_exact."""
    import estimator.gb as gb
    gb.gb_cost = _gb_cost_exact
