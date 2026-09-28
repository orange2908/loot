---
title: "Lattices - Coppersmith Small Roots (Univariate and Bivariate)"
category: crypto
subcategory: lattice
type: technique
tags: [lattice, lll, lattice-reduction, coppersmith, small-roots, howgrave-graham, shift-polynomials, rsa, stereotyped-message, partial-key-exposure, known-high-bits, boneh-durfee, defund, sage, fpylll, flatter, python]
difficulty: hard
summary: "Find roots of f(x) = 0 mod N that are smaller than N^(1/deg) by LLL-reducing a lattice of shifted multiples of f, then solving over the integers."
when_to_use:
  - "RSA with a small public exponent and a partly known message"
  - "You know the top (or bottom) half of a prime factor p"
  - "A polynomial congruence modulo N has an unusually small root"
  - "Partial private-key exposure, or d small enough for Boneh-Durfee"
tools: [sage, fpylll, flatter, defund-coppersmith, python]
related: [lattice-lll-fundamentals, lattice-hidden-number-problem, lattice-cvp-babai-scaling, lattice-toolkit, lattice-cheatsheet]
---

## TL;DR

Coppersmith's method converts "small root of a modular polynomial" into "short vector in a
lattice". Build integer multiples `x^j N^{m-i} f(x)^i` whose common root mod `N^m` is `x0`;
LLL them; the short output polynomial vanishes at `x0` *over the integers*, so you can just
solve it. Univariate degree `d` reaches `|x0| < N^{1/d}`; for a root modulo an unknown
divisor `p >= N^beta` the bound is `N^{beta^2/d}`.

## Recognise it

- `e = 3` and a message with a known prefix or suffix.
- "we leaked the top 300 bits of p".
- `c = pow(m, e, N)` where `m = pad + flag` and the flag is short.
- `d < N^0.292` (Boneh-Durfee) or a partial `d` leak.
- The intended solution mentions `small_roots`.

## Theory

**Howgrave-Graham's lemma.** Let `h(x)` have degree `n`, and let `X` bound the root. If

$$h(x_0) \equiv 0 \pmod{N^m} \quad\text{and}\quad \|h(xX)\| < \frac{N^m}{\sqrt{n+1}}$$

then `h(x0) = 0` **over the integers**. (`||.||` is the Euclidean norm of the coefficient
vector.) So: build a lattice whose vectors are polynomials vanishing at `x0` mod `N^m`, find
a short one, and solve it exactly.

**Shift polynomials.** For monic `f` of degree `d` and parameters `m, t`:

$$g_{i,j}(x) = x^j\, N^{m-i} f(x)^i, \quad 0 \le i < m,\ 0 \le j < d$$
$$h_j(x) = x^j f(x)^m, \quad 0 \le j < t$$

Every one of them vanishes at `x0` modulo `N^m`. The lattice is the row span of their
coefficient vectors with `x` substituted by `xX` (so column `k` is scaled by `X^k`). Its
dimension is `dm + t`.

**Bound.** With `t` chosen well and `m -> infinity`, LLL succeeds for

$$|x_0| < N^{1/d - \epsilon}$$

In practice `m = 3..8` and `t = 1..m` already reach within a few bits of the bound. Larger
`m` costs `O(dim^6)`-ish, so raise it only when you must.

**Roots modulo a divisor (the `beta` variant).** If `f(x0) = 0 mod b` where `b | N` and
`b >= N^beta` (you do not know `b`), the same shift polynomials work -- they vanish mod `b^m`
because `N^{m-i}` contributes `b^{m-i}`. The achievable bound becomes

$$|x_0| < N^{\beta^2/d}$$

For `d = 1`, `beta = 1/2` this is `N^{1/4}`: **knowing half the bits of `p` factors `N`.**
Crucially this variant needs many extra shifts: take `t` comparable to `m`, not `t = 1`.

**Bivariate.** `f(x, y) = 0` over the integers with `|x0| < X`, `|y0| < Y` works when
`XY < W^{2/(3 delta)}` (Coppersmith / Coron), where `W` is the largest coefficient of
`f(xX, yY)` and `delta` the total degree. Bivariate *modular* is heuristic: you take two
short vectors, take their resultant, and hope it is not identically zero. That heuristic is
what `defund/coppersmith` implements, and it works almost always in CTFs.

**Classic applications.**

| problem | `f(x)` | `d` | bound |
| --- | --- | --- | --- |
| stereotyped message, exponent `e` | `(a + x)^e - c` | `e` | `N^{1/e}` |
| short pad / Franklin-Reiter | resultant of two shifted polys | `e^2` | `N^{1/e^2}` |
| factor with known high bits of `p` | `x + p_{high}` | 1 | `N^{1/4}` |
| known low bits of `p` | `2^k x + p_{low}` (normalise!) | 1 | `N^{1/4}` |
| `d` small (Boneh-Durfee) | bivariate in `(k, s)` | - | `d < N^{0.292}` |

## Attack

1. Write the congruence as a monic polynomial `f` modulo `N` (multiply by the inverse of the
   leading coefficient).
2. Pick `X` as a *tight* bound on the root. Too large kills it.
3. Pick `m` (start at 3-4) and `t` (1 for `beta = 1`, `m` for the divisor variant).
4. Build the shifted basis, scale column `k` by `X^k`, LLL.
5. Unscale the first few rows into integer polynomials, find their integer roots in `[-X, X]`.
6. Verify against the original problem (`f(x0) = 0 mod N`, or `gcd(p_high + x0, N) > 1`).

## Code

```python
#!/usr/bin/env python3
"""Coppersmith's univariate method in pure Python: lattice, LLL and exact root finding."""
from fractions import Fraction
import math
import random

def dot(u, v):
    return sum(a * b for a, b in zip(u, v))

def rnd(x):
    return int(x + Fraction(1, 2)) if x >= 0 else -int(-x + Fraction(1, 2))

def lll(basis, delta=Fraction(99, 100)):
    b = [[int(x) for x in row] for row in basis]
    n = len(b)
    if n < 2:
        return b
    mu = [[Fraction(0)] * n for _ in range(n)]
    bs, B = [None] * n, [Fraction(0)] * n
    bs[0] = [Fraction(x) for x in b[0]]
    B[0] = dot(bs[0], bs[0])
    kmax, k = 0, 1

    def red(i, j):
        if abs(mu[i][j]) <= Fraction(1, 2):
            return
        q = rnd(mu[i][j])
        b[i] = [x - q * y for x, y in zip(b[i], b[j])]
        mu[i][j] -= q
        for t in range(j):
            mu[i][t] -= q * mu[j][t]

    while k < n:
        if k > kmax:
            kmax = k
            row = [Fraction(x) for x in b[k]]
            v = list(row)
            for j in range(k):
                mu[k][j] = Fraction(0) if B[j] == 0 else dot(row, bs[j]) / B[j]
                v = [a - mu[k][j] * c for a, c in zip(v, bs[j])]
            bs[k], B[k] = v, dot(v, v)
        red(k, k - 1)
        if B[k] < (delta - mu[k][k - 1] ** 2) * B[k - 1]:
            m_ = mu[k][k - 1]
            BB = B[k] + m_ * m_ * B[k - 1]
            b[k], b[k - 1] = b[k - 1], b[k]
            mu[k][k - 1] = m_ * B[k - 1] / BB
            old = bs[k - 1]
            bs[k - 1] = [x + m_ * y for x, y in zip(bs[k], old)]
            bs[k] = [-mu[k][k - 1] * x + (B[k] / BB) * y for x, y in zip(bs[k], old)]
            B[k], B[k - 1] = B[k - 1] * B[k] / BB, BB
            for j in range(k - 1):
                mu[k][j], mu[k - 1][j] = mu[k - 1][j], mu[k][j]
            for i in range(k + 1, kmax + 1):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - m_ * t
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
            k = max(1, k - 1)
        else:
            for j in range(k - 2, -1, -1):
                red(k, j)
            k += 1
    return b

# ---- polynomials: coefficient lists, lowest degree first ----------------

def pmul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] += x * y
    return out

def pscale(a, s):
    return [x * s for x in a]

def pshift(a, k):
    return [0] * k + a

def pderiv(c):
    return [i * c[i] for i in range(1, len(c))]

def peval(c, x):
    r = 0
    for co in reversed(c):
        r = r * x + co
    return r

def ptrim(c):
    while len(c) > 1 and c[-1] == 0:
        c = c[:-1]
    return c

def _crit_points(c, lo, hi):
    """Integers around which the polynomial can change direction (recursive on f')."""
    c = ptrim(c)
    if len(c) <= 1:
        return []
    if len(c) == 2:
        if c[1] == 0:
            return []
        f = math.floor(Fraction(-c[0], c[1]))
        return [v for v in (f, f + 1) if lo <= v <= hi]
    return _crit_points(pderiv(c), lo, hi)

def int_roots(c, lo, hi):
    """All integer roots of an integer polynomial in [lo, hi], exactly."""
    c = ptrim(c)
    if len(c) <= 1:
        return []
    marks = sorted(set([lo] + _crit_points(c, lo, hi) + [hi]))
    roots = set()
    for a, b in zip(marks, marks[1:]):
        fa, fb = peval(c, a), peval(c, b)
        if fa == 0:
            roots.add(a)
        if fb == 0:
            roots.add(b)
        if fa == 0 or fb == 0 or (fa > 0) == (fb > 0):
            continue
        while b - a > 1:                      # bisect: one root per monotone interval
            mid = (a + b) // 2
            fm = peval(c, mid)
            if fm == 0:
                roots.add(mid)
                break
            if (fm > 0) == (fa > 0):
                a, fa = mid, fm
            else:
                b, fb = mid, fm
    return sorted(roots)

# ---- Coppersmith --------------------------------------------------------

def coppersmith_univariate(f, N, X, m=3, t=1, rows_to_scan=4):
    """Monic f (low-degree-first coeffs). Returns candidate integer roots |x0| <= X.

    Shift polynomials x^j * N^(m-i) * f^i for i < m, j < d, plus x^j * f^m for j < t.
    For roots modulo an unknown divisor of N (e.g. p ~ sqrt(N)), use t comparable to m.
    """
    d = len(f) - 1
    polys, fk = [], [1]
    for i in range(m):
        gi = pscale(fk, pow(N, m - i))
        for j in range(d):
            polys.append(pshift(gi, j))
        fk = pmul(fk, f)
    for j in range(t):
        polys.append(pshift(fk, j))
    dim = d * m + t
    M = [[0] * dim for _ in range(dim)]
    for r, g in enumerate(polys):
        for j, co in enumerate(g):
            if j < dim:
                M[r][j] = co * pow(X, j)
    out = set()
    for row in lll(M)[:rows_to_scan]:
        if all(v == 0 for v in row):
            continue
        h = [row[j] // pow(X, j) for j in range(dim)]
        out.update(int_roots(h, -X, X))
    return sorted(out)

def _prime(bits, rng):
    while True:
        p = rng.randrange(1 << (bits - 1), 1 << bits) | 1
        if all(p % q for q in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)):
            if pow(2, p - 1, p) == 1 and pow(3, p - 1, p) == 1 and pow(5, p - 1, p) == 1:
                return p

if __name__ == "__main__":
    rng = random.Random(1)
    p, q = _prime(96, rng), _prime(96, rng)
    N = p * q
    print(f"[ok] N is {N.bit_length()} bits, p and q are 96 bits each")

    # --- 1. stereotyped message: c = (known_prefix + x)^3 mod N, x small ---
    prefix = int.from_bytes(b"pw: ".ljust(20, b"\x00"), "big")
    x0 = rng.randrange(1, 1 << 25)
    c = pow(prefix + x0, 3, N)
    base = [prefix, 1]                              # the polynomial (prefix + x)
    f = pmul(pmul(base, base), base)                # (prefix + x)^3
    f[0] -= c
    f = [v % N for v in f]                          # monic, degree 3
    X = 1 << 30                                     # bound on the unknown, < N^(1/3)
    roots = [r for r in coppersmith_univariate(f, N, X, m=3, t=1) if peval(f, r) % N == 0]
    assert roots == [x0], (roots, x0)
    print(f"[ok] stereotyped message: recovered the {x0.bit_length()}-bit tail, "
          f"bound was N^(1/3) = 2^{N.bit_length() // 3}")

    # --- 2. factor N from the top bits of p (root modulo an unknown divisor) ---
    hidden = 32
    p_high = (p >> hidden) << hidden
    Xp = 1 << (hidden + 2)
    cands = coppersmith_univariate([p_high, 1], N, Xp, m=4, t=4)
    hit = [r for r in cands if 1 < math.gcd(p_high + r, N) < N]
    assert hit, "no root found"
    rec = math.gcd(p_high + hit[0], N)
    assert rec == p and N % rec == 0
    print(f"[ok] known top {p.bit_length() - hidden} of {p.bit_length()} bits of p -> factored N")
    print(f"     theoretical reach is N^(1/4) = 2^{N.bit_length() // 4} "
          f"(here we only needed 2^{hidden})")

    # --- 3. the exact integer root finder on its own ---
    poly = pmul(pmul([-7, 1], [12, 1]), [1, 0, 1])   # (x-7)(x+12)(x^2+1)
    assert int_roots(poly, -100, 100) == [-12, 7]
    print("[ok] integer root finder: exact, no floating point, no sympy")
    print("all self-tests passed")
```

## Using defund/coppersmith (multivariate, SageMath)

```python
# SageMath: git clone https://github.com/defund/coppersmith, then
load('coppersmith.sage')
R.<x, y> = PolynomialRing(Zmod(N))
f = x * y + a * x + b * y + c          # any multivariate polynomial mod N
roots = small_roots(f, (X, Y), m=4, d=4)   # bounds on x and y; m, d tune the lattice
print(roots)
```

- `m` is the multiplicity (lattice size); raise it until it works or you run out of patience.
- `d` is the maximum degree of the shift polynomials; often `d = f.degree()` or `d = m`.
- It is *heuristic*: it takes several short vectors and computes resultants. An empty result
  usually means "increase `m`", not "no root".

## Variants and pitfalls

- **f must be monic.** Multiply by `leading_coeff^{-1} mod N`. If that inverse does not
  exist, `gcd(leading_coeff, N)` has just factored `N` for you.
- **`X` too generous.** The single most common failure. Halve `X` and retry; a factor of two
  is often the difference.
- **Divisor variant with `t = 1`.** Does not work. You need `t` on the order of `m`, which is
  why textbook code for `beta = 1` fails when you point it at a `p`-root problem.
- **`beta` matters.** Sage's `small_roots(X=..., beta=0.5)` is the divisor variant; the
  default `beta=1.0` is roots mod `N`.
- **Known low bits of `p`.** `p = p_low + 2^k y`; make it monic by multiplying by
  `(2^k)^{-1} mod N`, then it is the same degree-1 problem.
- **Bivariate modular is heuristic.** Resultants can vanish identically. Change the shift
  set, the bounds, or use a different pair of short vectors.
- **Dimension.** `d*m + t` grows fast and pure-Python exact LLL is `O(dim^4)` with huge
  entries. Dimension 20 with 2048-bit `N` wants `fpylll` or `flatter`.
- **Multiple roots returned.** Always verify against the original congruence; a short vector
  can encode a spurious root.

## Tools

```python
# SageMath: the built-in, which is what you should use when Sage is available
P.<x> = PolynomialRing(Zmod(N))
f = (prefix + x)^3 - c
print(f.monic().small_roots(X=2^30, beta=1.0, epsilon=0.05))

# factoring with known high bits of p
f = x + p_high
print(f.small_roots(X=2^128, beta=0.4, epsilon=0.02))     # beta ~ log_N(p)
```

```sh
# clone the standard multivariate helper
git clone https://github.com/defund/coppersmith
# and a faster reduction backend for big lattices
git clone https://github.com/keeganryan/flatter
```

## References

- Coppersmith, "Small solutions to polynomial equations, and low exponent RSA vulnerabilities", J. Cryptology 10 (1997)
- Howgrave-Graham, "Finding small roots of univariate modular equations revisited" (1997)
- May, "New RSA Vulnerabilities Using Lattice Reduction Techniques" (PhD thesis, 2003)
- https://github.com/defund/coppersmith
- https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html
