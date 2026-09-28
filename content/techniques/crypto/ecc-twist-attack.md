---
title: "ECC - Twist Attack on x-Only / Montgomery Implementations"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, twist-attack, quadratic-twist, montgomery-curve, montgomery-ladder, x-only, curve25519, ecdh, small-subgroup, twist-security, crt, chinese-remainder-theorem, pohlig-hellman, sage, python]
difficulty: medium
summary: "An x-only ladder cannot tell the curve from its twist. If #E' = 2p + 2 - #E is smooth, feed twist x-coordinates and CRT the static key out."
when_to_use:
  - "The API takes only an x coordinate (Montgomery ladder, compressed point, X25519-style)"
  - "The curve is non-standard and nobody checked twist security"
  - "factor(2*p + 2 - E.order()) is smooth"
  - "A static ECDH key is reused and the peer point is never validated"
tools: [sage, python, pari]
related: [ecc-invalid-curve, ecc-montgomery-x-only, ecc-pohlig-hellman, dlp-diffie-hellman-attacks, ecc-toolkit]
---

## TL;DR

For a Montgomery curve `B y^2 = x^3 + A x^2 + x`, the ladder computes `x(dP)` from `x(P)` and
`A` alone -- `B` never appears. Every `x` in `GF(p)` is a valid point on the curve *or* on its
quadratic twist, and the ladder cannot distinguish them. If the twist order
`#E' = 2p + 2 - #E` is smooth, pick twist points of small order, query the oracle, and CRT
the static scalar. Named curves like Curve25519 are chosen to be *twist-secure* precisely to
kill this.

## Recognise it

- The protocol transmits 32 bytes, not 65: only `x`.
- Source has `def ladder(k, x):` with an `a24 = (A + 2) // 4` constant and no `y` anywhere.
- `E.quadratic_twist().order()` factors into small primes.
- Compressed SEC1 points where the parity bit is ignored.
- The challenge says "we only send x, so nothing can go wrong".

## Theory

**The twist.** Over `GF(p)`, the quadratic twist of `E: y^2 = f(x)` by a non-residue `u` is
`E^u: u y^2 = f(x)`, isomorphic to `E` over `GF(p^2)` but not over `GF(p)`. Point counts
satisfy

$$\#E + \#E^u = 2p + 2$$

For each `x`, `f(x)` is either a nonzero square (two points on `E`), zero (one point on both),
or a non-square (two points on `E^u`). So the `x`-line is partitioned between the curve and
its twist, half and half.

**The ladder is twist-blind.** The Montgomery ladder works in projective `(X : Z)` with

$$a_{24} = \frac{A+2}{4}, \quad \text{xDBL and xADD use only } a_{24} \text{ and } x(P-Q)$$

Neither `B` nor `y` enters. Feeding a twist `x` makes the ladder compute the scalar multiple
*in `E^u`*, correctly.

**Attack.** Factor `#E' = 2p + 2 - #E`. For each small prime power `r || #E'`, find `x_T` on
the twist with `ord(T) = r` (take a random twist `x`, ladder-multiply by `#E'/r`). Query
`x(dT)`. Brute-force `j` in `[0, r)` with `x(jT) == x(dT)`; because `x(jT) = x(-jT)` you learn
`d = +/-j (mod r)`. Collect enough `r` and CRT over the `2^t` sign choices, testing each
candidate against the genuine public `x(dG)`.

**Twist security.** A curve is twist-secure when `#E'` has a large prime factor too.
Curve25519: `#E = 8 * l` and `#E' = 4 * l'` with `l, l'` both around `2^252`. That is why
X25519 can safely skip point validation.

## Attack

1. Confirm the interface is `x`-only and the key is static.
2. Compute `#E` (Sage/PARI) and `#E' = 2p + 2 - #E`; factor `#E'`.
3. For each small prime power `r`, build a twist point of order `r` and query the oracle.
4. Brute-force `d mod r` up to sign.
5. CRT over all sign combinations; test candidates against the public key.

## Code

```python
#!/usr/bin/env python3
"""Twist attack against an x-only Montgomery-ladder ECDH oracle."""
import random
from itertools import product
from math import gcd

def factorize(n):
    out, q = {}, 2
    while q * q <= n:
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
        if (r - x) % g:
            return None
        t = ((r - x) // g * pow(m // g, -1, n // g)) % (n // g)
        x, m = x + m * t, m // g * n
    return x % m

# ---- Montgomery x-only arithmetic: B*y^2 = x^3 + A*x^2 + x ---------------

def xDBL(X, Z, a24, p):
    t0 = (X + Z) % p
    t1 = (X - Z) % p
    t2, t3 = t0 * t0 % p, t1 * t1 % p
    t4 = (t2 - t3) % p
    return t2 * t3 % p, t4 * (t3 + a24 * t4) % p

def xADD(XP, ZP, XQ, ZQ, XD, ZD, p):
    """x(P+Q) given x(P), x(Q) and x(P-Q) = XD/ZD."""
    t0 = (XP + ZP) * (XQ - ZQ) % p
    t1 = (XP - ZP) * (XQ + ZQ) % p
    return ZD * pow(t0 + t1, 2, p) % p, XD * pow(t0 - t1, 2, p) % p

def ladder(k, x, a24, p):
    """x(k*P) as a projective (X : Z); Z == 0 means the point at infinity."""
    if k == 0:
        return (1, 0)
    X0, Z0 = 1, 0                     # R0 = infinity
    X1, Z1 = x % p, 1                 # R1 = P, invariant R1 - R0 = P
    for bit in bin(k)[2:]:
        if bit == "0":
            X1, Z1 = xADD(X0, Z0, X1, Z1, x, 1, p)
            X0, Z0 = xDBL(X0, Z0, a24, p)
        else:
            X0, Z0 = xADD(X0, Z0, X1, Z1, x, 1, p)
            X1, Z1 = xDBL(X1, Z1, a24, p)
    return X0, Z0

def xaffine(XZ, p):
    X, Z = XZ
    return None if Z % p == 0 else X * pow(Z, -1, p) % p

def rhs(x, A, p):
    return (x * x * x + A * x * x + x) % p

def counts(p, A):
    """(#E, #E') for B*y^2 = x^3 + A*x^2 + x over GF(p)."""
    qrs = {i * i % p for i in range(1, (p + 1) // 2)}
    n = 1
    for x in range(p):
        v = rhs(x, A, p)
        n += 1 if v == 0 else (2 if v in qrs else 0)
    return n, 2 * p + 2 - n

def twist_point_of_order(p, A, a24, twist_order, r, rng):
    """x of a twist point of exact order r (r must divide twist_order)."""
    for _ in range(500):
        x = rng.randrange(2, p)
        v = rhs(x, A, p)
        if v == 0 or pow(v, (p - 1) // 2, p) != p - 1:
            continue                                  # that x is on the curve, not the twist
        T = ladder(twist_order // r, x, a24, p)
        xt = xaffine(T, p)
        if xt is None:
            continue
        if xaffine(ladder(r, xt, a24, p), p) is None:
            return xt
    return None

class XOracle:
    """Static-key ECDH that only ever sees an x coordinate."""

    def __init__(self, p, a24, d):
        self.p, self.a24, self.d, self.queries = p, a24, d, 0

    def exchange(self, x):
        self.queries += 1
        return xaffine(ladder(self.d, x, self.a24, self.p), self.p)

if __name__ == "__main__":
    rng = random.Random(4)
    p = 30011                                  # small so we can count points naively
    assert p % 4 == 3

    # pick A whose TWIST order is smooth while the curve order keeps a big factor
    for A in range(3, 400):
        if A * A % p == 4:                     # singular Montgomery curve
            continue
        nE, nT = counts(p, A)
        fT = factorize(nT)
        if max(fT) <= 600 and max(factorize(nE)) > 1000:
            break
    a24 = (A + 2) * pow(4, -1, p) % p
    print(f"[ok] A = {A}: #E = {nE} = {factorize(nE)}")
    print(f"     twist #E' = {nT} = {fT}  <- smooth, that is the hole")

    # a base point on the real curve, and a static secret
    while True:
        xg = rng.randrange(2, p)
        v = rhs(xg, A, p)
        if v and pow(v, (p - 1) // 2, p) == 1:
            break
    d = rng.randrange(2, nE)
    xpub = xaffine(ladder(d, xg, a24, p), p)
    oracle = XOracle(p, a24, d)

    # harvest d mod r from twist subgroups
    mods, cands = [], []
    for q, e in sorted(fT.items()):
        r = q ** e
        if r < 3 or r > 4000:
            continue
        xt = twist_point_of_order(p, A, a24, nT, r, rng)
        if xt is None:
            continue
        target = oracle.exchange(xt)
        hits = [j for j in range(r) if xaffine(ladder(j, xt, a24, p), p) == target]
        if not hits:
            continue
        mods.append(r)
        cands.append(sorted(set(hits)))
    M = 1
    for m in mods:
        M *= m
    print(f"[ok] {oracle.queries} queries -> d known modulo {mods} (product {M})")

    # CRT over every sign combination, then test against the public x
    found = None
    for combo in product(*cands):
        c = crt(list(combo), mods)
        if c is None:
            continue
        t = 0
        while c + t * M < nE + M:
            if xaffine(ladder(c + t * M, xg, a24, p), p) == xpub:
                found = c + t * M
                break
            t += 1
        if found is not None:
            break
    assert found is not None
    assert xaffine(ladder(found, xg, a24, p), p) == xpub
    print(f"[ok] recovered scalar {found} (true d = {d}, equal up to sign mod ord)")
    print("all self-tests passed")
```

## Variants and pitfalls

- **You recover `d` only up to sign and only modulo `ord(P)`.** `x(dP) = x(-dP)`, so any
  candidate that reproduces the public `x` is as good as the real key for ECDH purposes.
- **Curve25519-style clamping.** X25519 clears the low 3 bits and sets bit 254, so `d` is a
  multiple of 8 in a fixed range. That kills the low-order twist contributions and leaks
  nothing -- and the twist is large-order anyway.
- **`x = 0`, `x = 1`, `x = -1`.** These are the classic low-order points; on many curves they
  have order 2 or 4. Always probe them first, they are free.
- **Ladder returning `Z == 0`.** That is the point at infinity: it means your `x` had order
  dividing `k`. Useful as an order test, fatal if you forget to check before inverting.
- **Singular Montgomery curve.** `A^2 = 4` makes the curve singular; the ladder still runs
  and produces nonsense. Check it.
- **Short Weierstrass with compressed points.** Same attack: if the server recomputes `y`
  from `x` but accepts an `x` where `f(x)` is a non-residue *and* does the arithmetic in
  `GF(p^2)` or silently in the twist, you are in business.
- **Naive counting does not scale.** `counts()` is `O(p)`. For a 256-bit challenge, get
  `#E` from Sage and subtract: `nT = 2*p + 2 - E.order()`.

## Tools

```python
# SageMath: twist order and its factorisation
E = EllipticCurve(GF(p), [a, b])
Et = E.quadratic_twist()
print(factor(E.order()), factor(Et.order()), E.order() + Et.order() == 2*p + 2)
```

```python
# SageMath: convert Montgomery (A, B) to short Weierstrass to reuse curve tooling
# y^2 = x^3 + A x^2 + x  ->  v^2 = u^3 + a u + b  with u = x + A/3
Fp = GF(p); A = Fp(A)
a = (3 - A**2) / 3
b = (2*A**3 - 9*A) / 27
E = EllipticCurve(Fp, [a, b]); print(factor(E.order()))
```

## References

- https://safecurves.cr.yp.to/twist.html
- Bernstein, "Curve25519: new Diffie-Hellman speed records" (PKC 2006)
- https://en.wikipedia.org/wiki/Twists_of_elliptic_curves
- https://martin.kleppmann.com/papers/curve25519.pdf
