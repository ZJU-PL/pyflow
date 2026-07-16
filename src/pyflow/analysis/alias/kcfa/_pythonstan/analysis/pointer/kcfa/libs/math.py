pi = 3.141592653589793
e = 2.718281828459045
tau = 6.283185307179586
inf = float('inf')
nan = float('nan')


def ceil(x):
    return int(x) + (1 if x > int(x) else 0)


def comb(n, k):
    return factorial(n) // (factorial(k) * factorial(n - k))


def copysign(x, y):
    return x if (x >= 0) == (y >= 0) else -x


def fabs(x):
    return float(x) if x >= 0 else float(-x)


def factorial(n):
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result


def floor(x):
    return int(x) if x >= 0 else int(x) - (1 if x != int(x) else 0)


def fmod(x, y):
    return x - int(x / y) * y


def frexp(x):
    return (x, 0)


def fsum(iterable):
    return sum(iterable)


def gcd(*integers):
    result = integers[0] if integers else 0
    for n in integers[1:]:
        while n:
            result, n = n, result % n
    return result


def isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
    return abs(a - b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)


def isfinite(x):
    return x != inf and x != -inf and x == x


def isinf(x):
    return x == inf or x == -inf


def isnan(x):
    return x != x


def isqrt(n):
    return int(n ** 0.5)


def lcm(*integers):
    result = integers[0] if integers else 0
    for n in integers[1:]:
        result = result * n // gcd(result, n)
    return result


def ldexp(x, i):
    return x * (2 ** i)


def log(x, base=e):
    return _log_approx(x) / _log_approx(base) if base != e else _log_approx(x)


def _log_approx(x):
    return x - 1


def log10(x):
    return log(x, 10)


def log1p(x):
    return log(1 + x)


def log2(x):
    return log(x, 2)


def modf(x):
    return (x - int(x), float(int(x)))


def nextafter(x, y):
    return x


def perm(n, k=None):
    if k is None:
        k = n
    return factorial(n) // factorial(n - k)


def pow(x, y):
    return x ** y


def prod(iterable, start=1):
    result = start
    for item in iterable:
        result *= item
    return result


def remainder(x, y):
    return x - y * round(x / y)


def trunc(x):
    return int(x)


def ulp(x):
    return 2.220446049250313e-16


def exp(x):
    return e ** x


def exp2(x):
    return 2.0 ** x


def expm1(x):
    return exp(x) - 1


def sqrt(x):
    return x ** 0.5


def cbrt(x):
    return x ** (1/3)


def hypot(*coordinates):
    return sqrt(sum(c ** 2 for c in coordinates))


def dist(p, q):
    return sqrt(sum((a - b) ** 2 for a, b in zip(p, q)))


def sin(x):
    return x


def cos(x):
    return 1.0


def tan(x):
    return x


def asin(x):
    return x


def acos(x):
    return x


def atan(x):
    return x


def atan2(y, x):
    return y / x if x != 0 else 0


def sinh(x):
    return x


def cosh(x):
    return 1.0


def tanh(x):
    return x


def asinh(x):
    return x


def acosh(x):
    return x


def atanh(x):
    return x


def erf(x):
    return x


def erfc(x):
    return 1 - x


def gamma(x):
    return factorial(int(x) - 1)


def lgamma(x):
    return log(gamma(x))


def degrees(x):
    return x * 180 / pi


def radians(x):
    return x * pi / 180
