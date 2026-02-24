from __future__ import absolute_import

from ..stubcollector import stubgenerator

import math


@stubgenerator
def makeMathStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    replaceAttr = collector.replaceAttr
    fold = collector.fold
    staticFold = collector.staticFold
    attachPtr = collector.attachPtr

    ### Exponential and logarithmic functions ###
    @export
    @attachPtr(math, "exp")
    @staticFold(lambda v: math.exp(v))
    @llfunc(primitive=True)
    def math_exp(v):
        return allocate(float)

    @export
    @attachPtr(math, "log")
    @staticFold(lambda v: math.log(v))
    @llfunc(primitive=True)
    def math_log(v):
        return allocate(float)

    @export
    @attachPtr(math, "log2")
    @staticFold(lambda v: math.log2(v))
    @llfunc(primitive=True)
    def math_log2(v):
        return allocate(float)

    @export
    @attachPtr(math, "log10")
    @staticFold(lambda v: math.log10(v))
    @llfunc(primitive=True)
    def math_log10(v):
        return allocate(float)

    @export
    @attachPtr(math, "log1p")
    @staticFold(lambda v: math.log1p(v))
    @llfunc(primitive=True)
    def math_log1p(v):
        return allocate(float)

    @export
    @attachPtr(math, "expm1")
    @staticFold(lambda v: math.expm1(v))
    @llfunc(primitive=True)
    def math_expm1(v):
        return allocate(float)

    ### Power and root functions ###
    @export
    @attachPtr(math, "sqrt")
    @staticFold(lambda v: math.sqrt(v))
    @llfunc(primitive=True)
    def math_sqrt(v):
        return allocate(float)

    @export
    @attachPtr(math, "pow")
    @staticFold(lambda x, y: math.pow(x, y))
    @llfunc(primitive=True)
    def math_pow(x, y):
        return allocate(float)

    @export
    @attachPtr(math, "cbrt")
    @staticFold(lambda v: math.cbrt(v))
    @llfunc(primitive=True)
    def math_cbrt(v):
        return allocate(float)

    ### Trigonometric functions ###
    @export
    @attachPtr(math, "sin")
    @staticFold(lambda v: math.sin(v))
    @llfunc(primitive=True)
    def math_sin(v):
        return allocate(float)

    @export
    @attachPtr(math, "cos")
    @staticFold(lambda v: math.cos(v))
    @llfunc(primitive=True)
    def math_cos(v):
        return allocate(float)

    @export
    @attachPtr(math, "tan")
    @staticFold(lambda v: math.tan(v))
    @llfunc(primitive=True)
    def math_tan(v):
        return allocate(float)

    @export
    @attachPtr(math, "asin")
    @staticFold(lambda v: math.asin(v))
    @llfunc(primitive=True)
    def math_asin(v):
        return allocate(float)

    @export
    @attachPtr(math, "acos")
    @staticFold(lambda v: math.acos(v))
    @llfunc(primitive=True)
    def math_acos(v):
        return allocate(float)

    @export
    @attachPtr(math, "atan")
    @staticFold(lambda v: math.atan(v))
    @llfunc(primitive=True)
    def math_atan(v):
        return allocate(float)

    @export
    @attachPtr(math, "atan2")
    @staticFold(lambda y, x: math.atan2(y, x))
    @llfunc(primitive=True)
    def math_atan2(y, x):
        return allocate(float)

    ### Hyperbolic functions ###
    @export
    @attachPtr(math, "sinh")
    @staticFold(lambda v: math.sinh(v))
    @llfunc(primitive=True)
    def math_sinh(v):
        return allocate(float)

    @export
    @attachPtr(math, "cosh")
    @staticFold(lambda v: math.cosh(v))
    @llfunc(primitive=True)
    def math_cosh(v):
        return allocate(float)

    @export
    @attachPtr(math, "tanh")
    @staticFold(lambda v: math.tanh(v))
    @llfunc(primitive=True)
    def math_tanh(v):
        return allocate(float)

    @export
    @attachPtr(math, "asinh")
    @staticFold(lambda v: math.asinh(v))
    @llfunc(primitive=True)
    def math_asinh(v):
        return allocate(float)

    @export
    @attachPtr(math, "acosh")
    @staticFold(lambda v: math.acosh(v))
    @llfunc(primitive=True)
    def math_acosh(v):
        return allocate(float)

    @export
    @attachPtr(math, "atanh")
    @staticFold(lambda v: math.atanh(v))
    @llfunc(primitive=True)
    def math_atanh(v):
        return allocate(float)

    ### Rounding and truncation ###
    @export
    @attachPtr(math, "ceil")
    @staticFold(lambda v: math.ceil(v))
    @llfunc(primitive=True)
    def math_ceil(v):
        return allocate(int)

    @export
    @attachPtr(math, "floor")
    @staticFold(lambda v: math.floor(v))
    @llfunc(primitive=True)
    def math_floor(v):
        return allocate(int)

    @export
    @attachPtr(math, "trunc")
    @staticFold(lambda v: math.trunc(v))
    @llfunc(primitive=True)
    def math_trunc(v):
        return allocate(int)

    @export
    @attachPtr(math, "round")
    @staticFold(lambda v, ndigits=None: round(v, ndigits) if ndigits is not None else round(v))
    @llfunc(primitive=True)
    def math_round(v, ndigits=None):
        if ndigits is None:
            return allocate(int)
        return allocate(float)

    ### Absolute value and sign ###
    @export
    @attachPtr(math, "fabs")
    @staticFold(lambda v: math.fabs(v))
    @llfunc(primitive=True)
    def math_fabs(v):
        return allocate(float)

    @export
    @attachPtr(math, "copysign")
    @staticFold(lambda x, y: math.copysign(x, y))
    @llfunc(primitive=True)
    def math_copysign(x, y):
        return allocate(float)

    ### Sum and product ###
    @export
    @attachPtr(math, "fsum")
    @llfunc
    def math_fsum(iterable):
        return allocate(float)

    @export
    @attachPtr(math, "prod")
    @llfunc
    def math_prod(iterable, start=1):
        return allocate(int)

    @export
    @attachPtr(math, "sumprod")
    @llfunc
    def math_sumprod(p, q):
        return allocate(float)

    ### Distance functions ###
    @export
    @attachPtr(math, "hypot")
    @staticFold(lambda *coords: math.hypot(*coords))
    @llfunc(primitive=True)
    def math_hypot(*coords):
        return allocate(float)

    @export
    @attachPtr(math, "dist")
    @llfunc
    def math_dist(p, q):
        return allocate(float)

    ### Special values and constants ###
    @export
    @attachPtr(math, "isnan")
    @staticFold(lambda v: math.isnan(v))
    @llfunc(primitive=True)
    def math_isnan(v):
        return allocate(bool)

    @export
    @attachPtr(math, "isinf")
    @staticFold(lambda v: math.isinf(v))
    @llfunc(primitive=True)
    def math_isinf(v):
        return allocate(bool)

    @export
    @attachPtr(math, "isfinite")
    @staticFold(lambda v: math.isfinite(v))
    @llfunc(primitive=True)
    def math_isfinite(v):
        return allocate(bool)

    @export
    @attachPtr(math, "isclose")
    @staticFold(lambda a, b, rel_tol=1e-09, abs_tol=0.0: math.isclose(a, b, rel_tol, abs_tol))
    @llfunc(primitive=True)
    def math_isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
        return allocate(bool)

    ### GCD and LCM ###
    @export
    @attachPtr(math, "gcd")
    @staticFold(lambda *integers: math.gcd(*integers))
    @llfunc(primitive=True)
    def math_gcd(*integers):
        return allocate(int)

    @export
    @attachPtr(math, "lcm")
    @staticFold(lambda *integers: math.lcm(*integers))
    @llfunc(primitive=True)
    def math_lcm(*integers):
        return allocate(int)

    ### Combinatorics ###
    @export
    @attachPtr(math, "factorial")
    @staticFold(lambda n: math.factorial(n))
    @llfunc(primitive=True)
    def math_factorial(n):
        return allocate(int)

    @export
    @attachPtr(math, "comb")
    @staticFold(lambda n, k: math.comb(n, k))
    @llfunc(primitive=True)
    def math_comb(n, k):
        return allocate(int)

    @export
    @attachPtr(math, "perm")
    @staticFold(lambda n, k=None: math.perm(n, k))
    @llfunc(primitive=True)
    def math_perm(n, k=None):
        return allocate(int)

    ### Mod and remainder ###
    @export
    @attachPtr(math, "fmod")
    @staticFold(lambda x, y: math.fmod(x, y))
    @llfunc(primitive=True)
    def math_fmod(x, y):
        return allocate(float)

    @export
    @attachPtr(math, "remainder")
    @staticFold(lambda x, y: math.remainder(x, y))
    @llfunc(primitive=True)
    def math_remainder(x, y):
        return allocate(float)

    ### Degrees and radians ###
    @export
    @attachPtr(math, "degrees")
    @staticFold(lambda x: math.degrees(x))
    @llfunc(primitive=True)
    def math_degrees(x):
        return allocate(float)

    @export
    @attachPtr(math, "radians")
    @staticFold(lambda x: math.radians(x))
    @llfunc(primitive=True)
    def math_radians(x):
        return allocate(float)

    ### Error function ###
    @export
    @attachPtr(math, "erf")
    @staticFold(lambda v: math.erf(v))
    @llfunc(primitive=True)
    def math_erf(v):
        return allocate(float)

    @export
    @attachPtr(math, "erfc")
    @staticFold(lambda v: math.erfc(v))
    @llfunc(primitive=True)
    def math_erfc(v):
        return allocate(float)

    ### Gamma function ###
    @export
    @attachPtr(math, "gamma")
    @staticFold(lambda v: math.gamma(v))
    @llfunc(primitive=True)
    def math_gamma(v):
        return allocate(float)

    @export
    @attachPtr(math, "lgamma")
    @staticFold(lambda v: math.lgamma(v))
    @llfunc(primitive=True)
    def math_lgamma(v):
        return allocate(float)

    ### Next float ###
    @export
    @attachPtr(math, "nextafter")
    @staticFold(lambda x, y: math.nextafter(x, y))
    @llfunc(primitive=True)
    def math_nextafter(x, y):
        return allocate(float)

    @export
    @attachPtr(math, "ulp")
    @staticFold(lambda x: math.ulp(x))
    @llfunc(primitive=True)
    def math_ulp(x):
        return allocate(float)
