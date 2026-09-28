---
title: "ECC - Singular Curve Attack (Cusp and Node)"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, singular-curve, cusp, node, discriminant, additive-group, multiplicative-group, ecdlp, dlp, discrete-log, pohlig-hellman, tonelli-shanks, group-isomorphism, sage, python]
difficulty: medium
summary: "Discriminant 0 means the curve is not a curve: a cusp maps to (GF(p), +) and the ECDLP is a division; a node maps to GF(p)^* or GF(p^2)^*."
when_to_use:
  - "4*a^3 + 27*b^2 == 0 mod p (the discriminant vanishes)"
  - "Sage refuses the parameters with 'singular curve' / ArithmeticError"
  - "The challenge lets you choose a or b, so you can force the discriminant to zero"
  - "A 'custom ECC' implementation never validates the discriminant"
tools: [sage, python, pari]
related: [ecc-recover-curve-params, ecc-pohlig-hellman, dlp-pohlig-hellman, ecc-toolkit, ecc-cheatsheet]
---

## TL;DR

`y^2 = x^3 + a*x + b` with `4a^3 + 27b^2 = 0` has a singular point. Delete it and the rest
of the points still form a group under the usual chord-and-tangent law -- but that group is
isomorphic to something trivial: `(GF(p), +)` for a cusp (ECDLP becomes one modular
division) or `GF(p)^*` / the norm-1 subgroup of `GF(p^2)^*` for a node (ECDLP becomes an
ordinary DLP, usually Pohlig-Hellman-able).

## Recognise it

- `(4*pow(a,3,p) + 27*b*b) % p == 0`.
- Sage: `EllipticCurve(GF(p), [a,b])` raises `ArithmeticError: invariants ... define a singular curve`.
- The source rolls its own `point_add` with raw formulas and never calls a curve validator.
- The server accepts arbitrary `a`, `b` in a "bring your own curve" handshake.
- `b == 0` and `a == 0` at once (pure cusp `y^2 = x^3`) -- an easy give-away.

## Theory

Factor the cubic. The discriminant vanishing means `x^3 + a*x + b` has a repeated root
`alpha`, so

$$x^3 + a x + b = (x - \alpha)^2 (x + 2\alpha), \qquad a = -3\alpha^2,\; b = 2\alpha^3$$

and `alpha = -3b / (2a) mod p` (take `alpha = 0` when `a = b = 0`). Substituting
`x' = x - alpha` puts the singularity at the origin:

$$y^2 = x'^2 (x' + 3\alpha)$$

Let `t = 3*alpha`.

**Case t = 0 (cusp).** `y^2 = x'^3`. The map

$$\varphi(x, y) = \frac{x'}{y} = \frac{x - \alpha}{y}$$

is a group isomorphism from the non-singular points onto `(GF(p), +)`. So `Q = k P` becomes
`phi(Q) = k * phi(P) mod p`, i.e.

$$k = \varphi(Q)\,\varphi(P)^{-1} \bmod p$$

One inversion. Done. The group has order `p`.

**Case t is a nonzero square (split node).** Let `s^2 = t`. Then

$$\varphi(x, y) = \frac{y + s x'}{y - s x'}$$

is an isomorphism onto `GF(p)^*`, of order `p - 1`. The ECDLP becomes a DLP in `GF(p)^*`:
Pohlig-Hellman it if `p - 1` is smooth, index-calculus it otherwise.

**Case t is a non-residue (non-split node).** `s` lives in `GF(p^2)`, and the image is the
norm-one subgroup of `GF(p^2)^*`, of order `p + 1`. Same recipe, but the DLP is in
`GF(p^2)^*`; it is easy exactly when `p + 1` is smooth. Sage handles this in two lines.

The three orders `p`, `p - 1`, `p + 1` are the tell: a singular curve never has a
Hasse-interval order near `p + 1 - t` with `|t| <= 2*sqrt(p)` randomly distributed.

## Attack

1. Confirm `4a^3 + 27b^2 = 0 mod p`.
2. Compute `alpha = -3b * inverse(2a) mod p` (or `0` if `a = b = 0`), then `t = 3*alpha`.
3. Shift all points: `x' = x - alpha`.
4. `t == 0` -> cusp: `k = (x'_Q / y_Q) * (x'_P / y_P)^{-1} mod p`.
5. `t` a QR -> split node: map both points, solve the DLP in `GF(p)^*`.
6. `t` a non-QR -> non-split node: map into `GF(p^2)`, solve in the order-`(p+1)` subgroup.
7. Check: recompute `k*P` with the original group law and compare to `Q`.

## Code

```python
#!/usr/bin/env python3
"""Singular curve ECDLP: cusp -> additive, split node -> multiplicative."""
from math import gcd, isqrt
import random

def legendre(a, p):
    return pow(a % p, (p - 1) // 2, p)

def tonelli(n, p):
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

def factorize(n):
    out, q = {}, 2
    while q * q <= n and q < 100000:
        while n % q == 0:
            out[q] = out.get(q, 0) + 1
            n //= q
        q += 1
    if n > 1:
        out[n] = out.get(n, 0) + 1
    return out

def crt(rs, ms):
    x, m = 0, 1
    for r, n in zip(rs, ms):
        g = gcd(m, n)
        t = ((r - x) // g * pow(m // g, -1, n // g)) % (n // g)
        x, m = x + m * t, m // g * n
    return x % m

def bsgs(g, h, order, p):
    m, tab, cur = isqrt(order) + 1, {}, 1
    for j in range(m):
        tab.setdefault(cur, j)
        cur = cur * g % p
    step, cur = pow(g, -m, p), h % p
    for i in range(m + 1):
        if cur in tab:
            return (i * m + tab[cur]) % order
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

def dlog_fp_star(g, h, p):
    """Pohlig-Hellman in <g> <= GF(p)^*; requires ord(g) smooth."""
    n, rs, ms = element_order(g, p), [], []
    for q, e in factorize(n).items():
        x, qk, gen = 0, 1, pow(g, n // q, p)
        for i in range(e):
            hi = pow(h * pow(g, -x, p) % p, n // q ** (i + 1), p)
            d = bsgs(gen, hi, q, p)
            if d is None:
                raise ValueError("no log; p-1 is not smooth enough")
            x, qk = x + d * qk, qk * q
        rs.append(x % q ** e)
        ms.append(q ** e)
    return crt(rs, ms) % n

def singular_dlog(p, a, b, P, Q):
    """Return k with Q = k*P on the singular curve y^2 = x^3 + a*x + b."""
    assert (4 * pow(a, 3, p) + 27 * b * b) % p == 0, "curve is not singular"
    alpha = 0 if (a % p == 0 and b % p == 0) else (-3 * b % p) * pow(2 * a % p, -1, p) % p
    sx = lambda X: (X - alpha) % p
    t = 3 * alpha % p
    if t == 0:                                    # cusp -> (GF(p), +)
        uP = sx(P[0]) * pow(P[1], -1, p) % p
        uQ = sx(Q[0]) * pow(Q[1], -1, p) % p
        return ("cusp", uQ * pow(uP, -1, p) % p, p)
    s = tonelli(t, p)
    if s is None:
        raise NotImplementedError("non-split node: solve in GF(p^2)^*, see the Sage block")
    f = lambda R: (R[1] + s * sx(R[0])) % p * pow((R[1] - s * sx(R[0])) % p, -1, p) % p
    gP = f(P)
    return ("split-node", dlog_fp_star(gP, f(Q), p), element_order(gP, p))

# ---- plain group law, only used to build and verify the demo -------------

def add(p, a, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    lam = ((3 * x1 * x1 + a) * pow(2 * y1 % p, -1, p) if P == Q
           else (y2 - y1) * pow((x2 - x1) % p, -1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)

def mul(p, a, k, P):
    R, S = None, P
    while k:
        if k & 1:
            R = add(p, a, R, S)
        S, k = add(p, a, S, S), k >> 1
    return R

def smooth_prime(bits, rng):
    """A prime p with p-1 smooth, so the node case is Pohlig-Hellman friendly."""
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    while True:
        m = 2
        while m.bit_length() < bits:
            m *= rng.choice(primes)
        if is_prime(m + 1):
            return m + 1

def random_point(p, a, b, rng):
    while True:
        x = rng.randrange(1, p)
        y = tonelli((x ** 3 + a * x + b) % p, p)
        if y:
            return (x, y)

if __name__ == "__main__":
    rng = random.Random(7)

    # --- cusp: y^2 = x^3 over a 256-bit prime ---
    p = 2**256 - 2**32 - 977
    P = random_point(p, 0, 0, rng)
    k = rng.randrange(2, p)
    Q = mul(p, 0, k, P)
    kind, rec, order = singular_dlog(p, 0, 0, P, Q)
    assert kind == "cusp" and rec == k % p
    print(f"[ok] cusp on a 256-bit prime: recovered k in one inversion (group order {order.bit_length()} bits)")

    # --- split node: alpha chosen so that 3*alpha is a QR ---
    pn = smooth_prime(96, rng)
    alpha = 1
    while legendre(3 * alpha % pn, pn) != 1:
        alpha += 1
    a = -3 * alpha * alpha % pn
    b = 2 * pow(alpha, 3, pn) % pn
    assert (4 * pow(a, 3, pn) + 27 * b * b) % pn == 0
    P = random_point(pn, a, b, rng)
    k = rng.randrange(2, pn - 1)
    Q = mul(pn, a, k, P)
    kind, rec, order = singular_dlog(pn, a, b, P, Q)
    assert kind == "split-node" and mul(pn, a, rec, P) == Q
    print(f"[ok] split node on a {pn.bit_length()}-bit prime: DLP in GF(p)^*, ord(P) = {order}")
    print("[ok] all singular-curve self-tests passed")
```

## Variants and pitfalls

- **Non-split node.** `tonelli(3*alpha, p)` returns `None`. The group has order `p + 1`;
  work in `GF(p^2)` with `s = sqrt(t)` there. In Sage:

```python
# SageMath: non-split node, group is the order-(p+1) subgroup of GF(p^2)^*
# (there is no clean pure-python shortcut; GF(p^2) arithmetic is needed)
F2 = GF(p**2, 'i', modulus=x**2 - non_residue)
s = F2(t).sqrt()
def phi(P):
    xp = F2(P[0] - alpha); yp = F2(P[1])
    return (yp + s*xp) / (yp - s*xp)
k = discrete_log(phi(Q), phi(P), ord=p+1, operation='*')
```

- **`a = 0`, `b != 0`.** Then `4a^3 + 27b^2 = 27b^2 != 0` unless `p = 3`; such a curve is
  *not* singular. Do not confuse "j-invariant 0" with "singular".
- **`p = 3`.** The formulas degenerate (`3*alpha = 0` always). Handle `p = 2, 3` by hand.
- **Order of the cusp group is `p`.** That is also the order of an anomalous *non-singular*
  curve, so verify the discriminant before reaching for Smart's attack.
- **Fake singularity.** If `4a^3 + 27b^2 = 0 mod n` for a composite `n`, you may only be
  singular modulo one prime factor. `gcd(4a^3 + 27b^2, n)` then factors `n` for free.
- **Point on the singular point itself.** `(alpha, 0)` is not in the group; the maps divide
  by zero there. Drop it.
- **Sign of the isomorphism.** `(y + s*x')/(y - s*x')` and its inverse are both valid
  isomorphisms; if `k` verifies neither, try `p - 1 - k` or swap numerator and denominator.

## Tools

```sh
# quick discriminant check from the shell
python3 -c 'p=...;a=...;b=...;print((4*pow(a,3,p)+27*b*b)%p)'
```

```python
# SageMath: singular curves are rejected, so work on the affine plane curve instead
R.<x,y> = GF(p)[]
C = Curve(y^2 - x^3 - a*x - b)
print(C.is_singular(), C.singular_points())
```

## References

- https://en.wikipedia.org/wiki/Singular_point_of_an_algebraic_variety
- https://en.wikipedia.org/wiki/Elliptic_curve#Singular_curves
- Washington, *Elliptic Curves: Number Theory and Cryptography*, section 2.10 ("Singular Curves")
