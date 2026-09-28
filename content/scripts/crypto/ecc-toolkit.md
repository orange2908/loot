---
title: "ECC Toolkit - Pure-Python Elliptic Curve Attack Module"
category: crypto
subcategory: ecc
type: script
tags: [ecc, elliptic-curve, ecdlp, discrete-log, dlp, pohlig-hellman, smart-attack, anomalous-curve, singular-curve, cusp, node, ecdsa, nonce-reuse, bsgs, baby-step-giant-step, tonelli-shanks, crt, chinese-remainder-theorem, padic, pure-python]
summary: "Dependency-free Python module: GF(p) point arithmetic, point counting, Pohlig-Hellman, Smart's attack with a hand-rolled Q_p, singular-curve solver, ECDSA nonce reuse."
tools: [python, sage]
related: [ecc-pohlig-hellman, ecc-smart-anomalous, ecc-singular-curve, ecdsa-nonce-reuse, ecc-cheatsheet, ecc-recover-curve-params]
---

## What this is

A single stdlib-only file you can drop next to a challenge script when SageMath is not
available (remote box, CI container, `nc`-only environment). Everything below is exercised
by the `__main__` self-test, including Smart's attack on a real 254-bit anomalous curve.

Save as `ecc_toolkit.py` and run `python3 ecc_toolkit.py`.

## API

| function | does |
| --- | --- |
| `Curve(p, a, b)` | short Weierstrass `y^2 = x^3 + a*x + b` over `GF(p)` |
| `E.add / mul / neg / lift_x / contains` | group law, points are `(x, y)` tuples, `None` = infinity |
| `E.count_points()` | naive `O(p)` order, fine for `p < 10**7` |
| `E.point_order(P, hint=N)` | exact order of a point given a multiple |
| `ec_bsgs(E, P, Q, order)` | `O(sqrt(order))` ECDLP |
| `ec_pohlig_hellman(E, P, Q, order)` | ECDLP when the order is smooth |
| `smart_attack(E, P, Q)` | linear-time ECDLP when `#E == p` |
| `singular_dlog(p, a, b, P, Q)` | ECDLP on a discriminant-0 curve |
| `ecdsa_nonce_reuse(r, s1, h1, s2, h2, n)` | `(k, d)` from two signatures sharing `k` |

## Code

```python
#!/usr/bin/env python3
"""ecc_toolkit.py -- pure-Python elliptic-curve CTF toolkit (stdlib only)."""
from __future__ import annotations
import random
from math import gcd, isqrt

INF = None  # the point at infinity

# ---- number theory -------------------------------------------------------

def legendre(a, p):
    return pow(a % p, (p - 1) // 2, p)

def tonelli(n, p):
    """Square root of n mod odd prime p, or None if it is a non-residue."""
    n %= p
    if n == 0:
        return 0
    if legendre(n, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = 2
    while legendre(z, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % p, i + 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t, r = t * c % p, r * b % p
    return r

def is_prime(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for q in small:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def _rho(n):
    """One non-trivial factor of composite n (Pollard rho, Floyd cycle)."""
    if n % 2 == 0:
        return 2
    while True:
        x = random.randrange(2, n)
        y, c, d = x, random.randrange(1, n), 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
        if d != n:
            return d

def factorize(n):
    """{prime: exponent}. Good enough for CTF-sized group orders."""
    out, q = {}, 2
    while q < 100000 and q * q <= n:
        while n % q == 0:
            out[q] = out.get(q, 0) + 1
            n //= q
        q += 1
    stack = [n] if n > 1 else []
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            out[m] = out.get(m, 0) + 1
        else:
            d = _rho(m)
            stack += [d, m // d]
    return dict(sorted(out.items()))

def crt(residues, moduli):
    """Chinese remainder theorem, tolerates non-coprime but consistent moduli."""
    x, m = 0, 1
    for r, nn in zip(residues, moduli):
        g = gcd(m, nn)
        assert (r - x) % g == 0, "inconsistent CRT system"
        t = ((r - x) // g * pow(m // g, -1, nn // g)) % (nn // g)
        x, m = x + m * t, m // g * nn
    return x % m

# ---- curve over GF(p) ----------------------------------------------------

class Curve:
    """y^2 = x^3 + a*x + b over GF(p). Points: (x, y) tuples, None = infinity."""

    def __init__(self, p, a, b):
        self.p, self.a, self.b = p, a % p, b % p

    def discriminant(self):
        return (-16 * (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p))) % self.p

    def is_singular(self):
        return self.discriminant() == 0

    def contains(self, P):
        if P is INF:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def neg(self, P):
        return INF if P is INF else (P[0], (-P[1]) % self.p)

    def add(self, P, Q):
        p = self.p
        if P is INF:
            return Q
        if Q is INF:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return INF
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1 % p, -1, p) % p
        else:
            lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    def mul(self, k, P):
        if k < 0:
            return self.neg(self.mul(-k, P))
        R, Q = INF, P
        while k:
            if k & 1:
                R = self.add(R, Q)
            Q, k = self.add(Q, Q), k >> 1
        return R

    def lift_x(self, x):
        """All points with this x coordinate (0, 1 or 2 of them)."""
        y = tonelli((x * x * x + self.a * x + self.b) % self.p, self.p)
        if y is None:
            return []
        return [(x % self.p, 0)] if y == 0 else [(x % self.p, y), (x % self.p, -y % self.p)]

    def random_point(self):
        while True:
            pts = self.lift_x(random.randrange(self.p))
            if pts:
                return random.choice(pts)

    def count_points(self):
        """Naive O(p) point count via Legendre symbols. Small p only."""
        n = 1
        for x in range(self.p):
            rhs = (x * x * x + self.a * x + self.b) % self.p
            n += 1 if rhs == 0 else (2 if legendre(rhs, self.p) == 1 else 0)
        return n

    def point_order(self, P, hint):
        """Exact order of P, given any multiple of it (usually the curve order)."""
        if P is INF:
            return 1
        n = hint
        for q, e in factorize(n).items():
            for _ in range(e):
                if self.mul(n // q, P) is INF:
                    n //= q
                else:
                    break
        return n

# ---- ECDLP ---------------------------------------------------------------

def ec_bsgs(E, P, Q, order):
    """Solve Q = k*P for 0 <= k < order. O(sqrt(order)) time and memory."""
    m = isqrt(order) + 1
    table, R = {}, INF
    for j in range(m):
        table.setdefault(R, j)
        R = E.add(R, P)
    step, S = E.neg(E.mul(m, P)), Q
    for i in range(m + 1):
        if S in table:
            return (i * m + table[S]) % order
        S = E.add(S, step)
    return None

def ec_pohlig_hellman(E, P, Q, order):
    """ECDLP when ord(P) = order is smooth. Returns k with Q = k*P."""
    residues, moduli = [], []
    for q, e in factorize(order).items():
        x, qk = 0, 1
        gen = E.mul(order // q, P)
        for i in range(e):
            Qi = E.add(Q, E.neg(E.mul(x, P)))
            d = ec_bsgs(E, gen, E.mul(order // q ** (i + 1), Qi), q)
            if d is None:
                raise ValueError(f"no log in the order-{q} subgroup")
            x, qk = x + d * qk, qk * q
        residues.append(x % q ** e)
        moduli.append(q ** e)
    return crt(residues, moduli) % order

# ---- a minimal fixed-precision Q_p, used by Smart's attack ---------------

class Qp:
    """p^val * unit with unit known mod p^prec. Zero is val=None."""
    __slots__ = ("p", "val", "unit", "prec")

    def __init__(self, p, val, unit, prec):
        if val is None or unit == 0:
            self.p, self.val, self.unit, self.prec = p, None, 0, prec
            return
        while unit % p == 0 and prec > 0:
            unit, val, prec = unit // p, val + 1, prec - 1
        self.p, self.val, self.unit, self.prec = p, val, unit % p ** prec, prec

    @classmethod
    def from_int(cls, n, p, prec):
        return cls(p, 0, n % p ** prec, prec)

    def is_zero(self):
        return self.val is None

    def __add__(self, o):
        if self.is_zero():
            return o
        if o.is_zero():
            return self
        p, v = self.p, min(self.val, o.val)
        absprec = min(self.val + self.prec, o.val + o.prec)
        if absprec <= v:
            return Qp(p, None, 0, 1)
        mod = p ** (absprec - v)
        s = (self.unit * p ** (self.val - v) + o.unit * p ** (o.val - v)) % mod
        return Qp(p, v, s, absprec - v)

    def __neg__(self):
        return Qp(self.p, self.val, -self.unit, self.prec)

    def __sub__(self, o):
        return self + (-o)

    def __mul__(self, o):
        prec = min(self.prec, o.prec)
        if self.is_zero() or o.is_zero():
            return Qp(self.p, None, 0, prec)
        return Qp(self.p, self.val + o.val, self.unit * o.unit, prec)

    def inverse(self):
        assert not self.is_zero(), "cannot invert p-adic zero"
        return Qp(self.p, -self.val, pow(self.unit, -1, self.p ** self.prec), self.prec)

    def __truediv__(self, o):
        return self * o.inverse()

    def residue(self):
        """Leading digit as an element of GF(p); requires valuation 0."""
        assert self.val == 0, "residue() needs valuation 0"
        return self.unit % self.p

def qp_sqrt(c, root_mod_p):
    """Hensel-lift a square root of the p-adic unit c, matching root_mod_p."""
    p, prec = c.p, c.prec
    y, two = Qp.from_int(root_mod_p, p, prec), Qp.from_int(2, p, prec)
    for _ in range(prec.bit_length() + 2):      # Newton: y <- (y + c/y)/2
        y = (y + c / y) / two
    return y if y.residue() == root_mod_p % p else -y

# ---- Smart's attack: anomalous curves (#E(GF(p)) == p) -------------------

def _qp_add(P, Q, A):
    if P is INF:
        return Q
    if Q is INF:
        return P
    x1, y1 = P
    x2, y2 = Q
    if (x1 - x2).is_zero() and (y1 + y2).is_zero():
        return INF
    if (x1 - x2).is_zero():
        three = Qp.from_int(3, A.p, A.prec)
        two = Qp.from_int(2, A.p, A.prec)
        lam = (three * x1 * x1 + A) / (two * y1)
    else:
        lam = (y2 - y1) / (x2 - x1)
    x3 = lam * lam - x1 - x2
    return (x3, lam * (x1 - x3) - y1)

def _qp_mul(k, P, A):
    R, Q = INF, P
    while k:
        if k & 1:
            R = _qp_add(R, Q, A)
        Q, k = _qp_add(Q, Q, A), k >> 1
    return R

def smart_attack(E, P, Q, prec=8):
    """ECDLP in O(log p) when #E == p. Lifts to Z_p and uses the formal logarithm."""
    p = E.p
    for _ in range(12):
        # perturb a, b by multiples of p so the LIFTED curve is not anomalous
        A = Qp.from_int(E.a + p * random.randrange(1, p), p, prec)
        B = Qp.from_int(E.b + p * random.randrange(1, p), p, prec)
        try:
            lifted = []
            for (x, y) in (P, Q):
                X = Qp.from_int(x, p, prec)
                lifted.append((X, qp_sqrt(X * X * X + A * X + B, y)))
            pP, pQ = _qp_mul(p, lifted[0], A), _qp_mul(p, lifted[1], A)
            if pP is INF or pQ is INF:
                continue
            k = (-(pQ[0] / pQ[1])) / (-(pP[0] / pP[1]))
            if k.val != 0:
                continue
            return k.residue()
        except AssertionError:
            continue
    raise ValueError("Smart's attack failed -- is #E really equal to p?")

# ---- singular curves -----------------------------------------------------

def _bsgs_mod(g, h, order, p):
    m, table, cur = isqrt(order) + 1, {}, 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    step, cur = pow(g, -m, p), h % p
    for i in range(m + 1):
        if cur in table:
            return (i * m + table[cur]) % order
        cur = cur * step % p
    return None

def element_order(g, p):
    """Exact multiplicative order of g mod p."""
    n = p - 1
    for q, e in factorize(n).items():
        for _ in range(e):
            if pow(g, n // q, p) == 1:
                n //= q
            else:
                break
    return n

def mul_group_dlog(g, h, p):
    """Pohlig-Hellman discrete log in <g> <= GF(p)^*; needs ord(g) smooth."""
    n, residues, moduli = element_order(g, p), [], []
    for q, e in factorize(n).items():
        x, qk, gen = 0, 1, pow(g, n // q, p)
        for i in range(e):
            hi = pow(h * pow(g, -x, p) % p, n // q ** (i + 1), p)
            d = _bsgs_mod(gen, hi, q, p)
            if d is None:
                raise ValueError(f"no log in the order-{q} subgroup")
            x, qk = x + d * qk, qk * q
        residues.append(x % q ** e)
        moduli.append(q ** e)
    return crt(residues, moduli) % n

def singular_dlog(p, a, b, P, Q):
    """DLP on the singular curve y^2 = x^3+a*x+b (discriminant 0). Returns k, Q=k*P."""
    assert (4 * pow(a, 3, p) + 27 * b * b) % p == 0, "curve is not singular"
    # double root alpha of x^3+a*x+b; for a cusp (a=b=0) it sits at the origin
    alpha = 0 if (a % p == 0 and b % p == 0) else (-3 * b % p) * pow(2 * a % p, -1, p) % p
    sx = lambda X: (X - alpha) % p
    t = 3 * alpha % p               # curve becomes y^2 = x'^2 * (x' + t)
    if t == 0:                      # cusp: (x, y) -> x'/y is an iso onto (GF(p), +)
        uP = sx(P[0]) * pow(P[1], -1, p) % p
        uQ = sx(Q[0]) * pow(Q[1], -1, p) % p
        return uQ * pow(uP, -1, p) % p
    s = tonelli(t, p)
    if s is None:
        raise NotImplementedError("non-split node: the DLP lives in GF(p^2)^*, use Sage")
    # split node: (x, y) -> (y + s*x')/(y - s*x') is an iso onto GF(p)^*
    f = lambda R: (R[1] + s * sx(R[0])) % p * pow((R[1] - s * sx(R[0])) % p, -1, p) % p
    return mul_group_dlog(f(P), f(Q), p)

# ---- ECDSA ---------------------------------------------------------------

def ecdsa_nonce_reuse(r, s1, h1, s2, h2, n):
    """Two signatures sharing k under the same key -> (k, d)."""
    assert s1 != s2, "identical s values carry no information"
    k = (h1 - h2) * pow((s1 - s2) % n, -1, n) % n
    return k, (s1 * k - h1) * pow(r, -1, n) % n

# ---- self-test -----------------------------------------------------------

def _some_point(E, lo=0):
    """A point with y != 0, for the singular-curve demos."""
    while True:
        pts = E.lift_x(random.randrange(lo, E.p))
        if pts and pts[0][1]:
            return pts[0]

def _selftest():
    random.seed(1337)
    p = 2**256 - 2**32 - 977
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    E = Curve(p, 0, 7)
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    assert E.contains(G) and E.mul(n, G) is INF and not E.is_singular()
    print("[ok] secp256k1: G on curve, n*G == O")

    Es = Curve(10007, 3, 8)
    N = Es.count_points()
    P = Es.random_point()
    o = Es.point_order(P, hint=N)
    k = random.randrange(2, o)
    Q = Es.mul(k, P)
    assert ec_bsgs(Es, P, Q, o) == k and ec_pohlig_hellman(Es, P, Q, o) == k
    print(f"[ok] #E = {N}, ord(P) = {o}, BSGS + Pohlig-Hellman recovered k")

    # anomalous curve built by CM with discriminant -3: 4p = 1 + 3*v^2
    pa = 0x3000000000000000000000000000000fc000000000000000000000000000014b
    Ea = Curve(pa, 0, 13)
    Ga = (0x2ba19fe4f01e17676e757e860dedee27532e2209a6fcb716c62947c91d68ed5b,
          0x5dab425c3d67157fee012930c209ef8d30d381d9897ec46edefc0a8a89e69db)
    assert Ea.contains(Ga) and Ea.mul(pa, Ga) is INF          # #E == p
    ka = 0xdeadbeefcafebabe1234567890
    assert smart_attack(Ea, Ga, Ea.mul(ka, Ga)) == ka
    print("[ok] Smart: 96-bit key on a 254-bit anomalous curve, no Sage")

    ps = 904363372984020100431281                              # p-1 is 43-smooth
    alpha = 4
    while legendre(3 * alpha % ps, ps) != 1:
        alpha += 1
    an, bn = -3 * alpha * alpha % ps, 2 * pow(alpha, 3, ps) % ps
    En = Curve(ps, an, bn)
    Pn = _some_point(En)
    kn = random.randrange(2, ps - 1)
    assert En.mul(singular_dlog(ps, an, bn, Pn, En.mul(kn, Pn)), Pn) == En.mul(kn, Pn)
    print("[ok] singular curve (node): DLP solved in GF(p)^*")

    Ec = Curve(ps, 0, 0)
    Pc = _some_point(Ec, lo=1)
    kc = random.randrange(2, ps)
    assert singular_dlog(ps, 0, 0, Pc, Ec.mul(kc, Pc)) == kc % ps
    print("[ok] singular curve (cusp): DLP solved in (GF(p), +)")

    d, kk = random.randrange(1, n), random.randrange(1, n)
    r = E.mul(kk, G)[0] % n
    h1, h2 = random.randrange(1, n), random.randrange(1, n)
    s1 = pow(kk, -1, n) * (h1 + r * d) % n
    s2 = pow(kk, -1, n) * (h2 + r * d) % n
    assert ecdsa_nonce_reuse(r, s1, h1, s2, h2, n) == (kk, d)
    print("[ok] ECDSA nonce reuse: private key recovered")
    print("all self-tests passed")

if __name__ == "__main__":
    _selftest()
```

## Notes and limits

- `count_points()` is `O(p)`: fine up to about `10**7`. For anything larger you need Schoof-Elkies-Atkin, i.e. Sage's `E.order()` or PARI's `ellcard`.
- `smart_attack` needs `#E == p` exactly. Check it with `E.mul(p, P) is INF` for a few random `P`, or with `E.count_points() == p` on small curves.
- `singular_dlog` raises `NotImplementedError` on a non-split node (when `3*alpha` is a
  quadratic non-residue). There the group is the norm-1 subgroup of `GF(p^2)^*`, of order
  `p+1`; if `p+1` is smooth, redo the same reduction inside `GF(p^2)` in Sage.
- `ec_pohlig_hellman` is only fast when every prime factor of the order is small. The cost
  is `sum(e_i * sqrt(q_i))` group operations.
- Nothing here is constant-time. It is an attack tool, not a library.

## References

- https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
- https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
- https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_finite_field.html
