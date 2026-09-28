---
title: "ECC - Recovering Curve Parameters a, b (and p) From Points"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, curve-parameters, recover-a-b, unknown-modulus, gcd, determinant, resultant, linear-system, sanity-check, discriminant, j-invariant, weierstrass, sage, pari, python]
difficulty: easy
summary: "Two points give a linear system for a and b mod p; four points give p itself via a gcd of determinants. Then sanity-check the curve before attacking it."
when_to_use:
  - "A challenge hands you points but omits a, b (or omits p entirely)"
  - "You need to know which ECC attack applies and must first pin down the curve"
  - "A service returns points from a 'secret' curve and you want to rebuild it locally"
  - "You suspect the organisers swapped in a weak curve and want to check order/discriminant"
tools: [sage, pari, python]
related: [ecc-cheatsheet, ecc-singular-curve, ecc-pohlig-hellman, ecc-smart-anomalous, ecc-toolkit]
---

## TL;DR

Every point satisfies `y^2 = x^3 + a*x + b (mod p)`, which is *linear* in the unknowns
`a` and `b`. Two points -> solve a 2x2 system. If `p` is also unknown, three points make a
3x3 determinant vanish over the integers only modulo `p`, so a gcd of several such
determinants is a small multiple of `p`. Once you have `(p, a, b)`, run the sanity checklist
before picking an attack.

## Recognise it

- The challenge prints `P = (x, y)` and `Q = (x, y)` but the source only defines `p`.
- `E = EllipticCurve(GF(p), [a, b])` appears in the source with `a`/`b` read from a file you do not have.
- A remote service exposes "give me a point, I give you `k*P`" with no curve parameters at all.
- The generator is printed but `a` is derived from the flag (a classic: `a = bytes_to_long(flag)`).
- You are told "same curve as last time, we only rotated `b`".

## Theory

Short Weierstrass form: `y^2 = x^3 + a*x + b` over `GF(p)`.

**a, b with p known.** For two points `(x1, y1)`, `(x2, y2)` with `x1 != x2`:

$$a = \frac{(y_1^2 - x_1^3) - (y_2^2 - x_2^3)}{x_1 - x_2} \bmod p, \qquad b = y_1^2 - x_1^3 - a x_1 \bmod p$$

If `x1 == x2` the system is degenerate (the two points are `P` and `-P`); take another pair.

**p unknown.** Write `c_i = y_i^2 - x_i^3`. Each point gives `a*x_i + b - c_i = 0 (mod p)`.
Three points make the vector `(a, b, -1)` a kernel element of

$$M = \begin{pmatrix} x_1 & 1 & c_1 \\ x_2 & 1 & c_2 \\ x_3 & 1 & c_3 \end{pmatrix} \pmod p$$

so `det(M) = 0 (mod p)`. Computed over `ZZ` that determinant is a nonzero multiple of `p`
with overwhelming probability. Take `gcd` over several triples; strip small prime factors
and you are left with `p` (check `is_prime`).

**b only.** If `a` is fixed by the curve family (e.g. `a = 0` on secp256k1-like curves),
one point is enough: `b = y^2 - x^3 mod p`.

**Sanity checklist.** Once you have `(p, a, b)`:

| check | how | what it means |
| --- | --- | --- |
| `p` prime | `is_prime(p)` | if composite, the "curve" is a ring; CRT the problem |
| `4a^3 + 27b^2 != 0` | discriminant | zero -> singular curve, ECDLP is easy |
| `#E` | `E.order()` (Sage) / `ellcard` (PARI) | drives every attack choice |
| `#E == p` | anomalous | Smart's attack, linear time |
| `#E` smooth | `factor(E.order())` | Pohlig-Hellman |
| embedding degree `k` small | order of `p` mod `n` | MOV / Frey-Ruck |
| cofactor `h = #E / n` | small subgroups | invalid-curve / small-subgroup attacks |
| twist order `2p + 2 - #E` | `#E' = 2*(p+1) - #E` | twist attack if the twist is weak |
| `j`-invariant `1728*4a^3/(4a^3+27b^2)` | `j == 0` or `1728` | CM curves, often deliberately built |

## Attack

1. Collect at least 3 points from the service (4 if `p` is unknown, for a cross-check).
2. If `p` is unknown: build the integer determinants, `gcd` them, strip small factors, confirm primality.
3. Solve the 2x2 linear system for `a`, `b` modulo `p`.
4. Verify *every* known point satisfies the equation. If one fails, you mixed up curves.
5. Run the sanity checklist and jump to the matching attack file.

## Code

```python
#!/usr/bin/env python3
"""Recover a, b (and p) of a short Weierstrass curve from sample points."""
from math import gcd
from itertools import combinations
import random

def recover_ab(p, pts):
    """a, b from two points with distinct x. pts = [(x, y), ...]."""
    for (x1, y1), (x2, y2) in combinations(pts, 2):
        if (x1 - x2) % p == 0:
            continue
        c1 = (y1 * y1 - x1 ** 3) % p
        c2 = (y2 * y2 - x2 ** 3) % p
        a = (c1 - c2) * pow(x1 - x2, -1, p) % p
        b = (c1 - a * x1) % p
        if all((y * y - x ** 3 - a * x - b) % p == 0 for x, y in pts):
            return a, b
    raise ValueError("no consistent (a, b) -- are all points on the same curve?")

def _det3(m):
    (a, b, c), (d, e, f), (g, h, i) = m
    return a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)

def recover_p(pts, min_bits=32):
    """Modulus from >= 3 points: gcd of the vanishing 3x3 determinants."""
    rows = [(x, 1, y * y - x ** 3) for x, y in pts]
    g = 0
    for tri in combinations(rows, 3):
        g = gcd(g, _det3(list(tri)))
    if g == 0:
        raise ValueError("degenerate sample -- collect more points")
    g = abs(g)
    for q in range(2, 100000):          # strip the small cofactor the gcd drags in
        while g % q == 0 and (g // q).bit_length() >= min_bits:
            g //= q
    return g

def curve_report(p, a, b):
    """Everything you need before choosing an attack."""
    disc = (-16 * (4 * pow(a, 3, p) + 27 * b * b)) % p
    out = {"p_bits": p.bit_length(), "discriminant": disc, "singular": disc == 0}
    if disc:
        num = 4 * pow(a, 3, p) % p
        out["j_invariant"] = 1728 * num % p * pow((num + 27 * b * b) % p, -1, p) % p
    return out

# ---- a self-contained demo: build a curve, sample it, recover it ----------

def _on_curve(p, a, b, P):
    x, y = P
    return (y * y - x ** 3 - a * x - b) % p == 0

def _add(p, a, P, Q):
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

def _mul(p, a, k, P):
    R, Q = None, P
    while k:
        if k & 1:
            R = _add(p, a, R, Q)
        Q, k = _add(p, a, Q, Q), k >> 1
    return R

def _sqrt_mod(n, p):
    assert p % 4 == 3, "demo uses p = 3 mod 4"
    r = pow(n % p, (p + 1) // 4, p)
    return r if r * r % p == n % p else None

if __name__ == "__main__":
    random.seed(0)
    # secp256r1-like secret curve
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
         0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
    assert _on_curve(p, a, b, G)

    # sample four "public keys" the way a service would hand them out
    pts = [_mul(p, a, random.randrange(2, 1 << 200), G) for _ in range(4)]

    # 1. p was never given: recover it from the points alone
    p_rec = recover_p(pts)
    assert p_rec == p, (hex(p_rec), hex(p))
    print(f"[ok] recovered p = {hex(p_rec)}")

    # 2. a and b from the same points
    a_rec, b_rec = recover_ab(p_rec, pts)
    assert (a_rec, b_rec) == (a, b)
    print(f"[ok] recovered a = {hex(a_rec)}\n[ok] recovered b = {hex(b_rec)}")

    # 3. sanity report
    rep = curve_report(p_rec, a_rec, b_rec)
    assert rep["singular"] is False and rep["p_bits"] == 256
    print("[ok] report:", rep)

    # 4. x-only variant: only x coordinates leaked, lift them first
    xs = [P[0] for P in pts]
    lifted = []
    for x in xs:
        y = _sqrt_mod((x ** 3 + a * x + b) % p, p)
        assert y is not None
        lifted.append((x, y))
    assert recover_ab(p, lifted) == (a, b)
    print("[ok] recovery also works from lifted x-only points")
```

## Variants and pitfalls

- **Only `x` coordinates leaked.** You cannot form `y^2` directly, so you cannot use the
  linear system. But if you already know `p` and one of `a`/`b`, brute force the other:
  the correct value is the one for which every `x` gives a quadratic residue often enough
  (about half the time, so use many samples). Otherwise you need one full point.
- **Two x-coordinates equal.** `P` and `-P` give the same equation; the 2x2 system is
  singular. `recover_ab` above skips such pairs automatically.
- **Montgomery form.** `B*y^2 = x^3 + A*x^2 + x` is linear in `A` and `B` too, but with
  three unknown-ish terms: `B*y^2 - x^3 - x = A*x^2` gives `A` once `B` is fixed (usually `B = 1`).
  Convert to short Weierstrass afterwards (see the Montgomery file).
- **Composite `p`.** If `recover_p` returns a composite, that may be the point of the
  challenge: the group is a product of groups, factor it and CRT the ECDLP.
- **gcd returns a multiple of `p`.** Keep collecting points; every extra triple divides out
  more junk. Stripping small factors up to `10**5` is usually enough.
- **The curve is singular.** `4a^3 + 27b^2 == 0` is not a bug in your recovery, it is the
  challenge: see `ecc-singular-curve`.
- **Points not actually on one curve.** Some services return points from a *twist* on
  purpose. If `recover_ab` fails on a subset, split the samples and solve each group.

## Tools

```python
# SageMath: reconstruct and interrogate the curve in five lines
# sage recover.sage
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
E = EllipticCurve(GF(p), [a, b])
print(E.order(), factor(E.order()), E.j_invariant(), E.discriminant())
print(E.order() == p)                       # anomalous?
Et = E.quadratic_twist(); print(factor(Et.order()))
```

```sh
# PARI/GP: card of the curve without Sage
gp -q -c 'p=2^256-2^224+2^192+2^96-1; E=ellinit([Mod(-3,p),Mod(41058363725152142129326129780047268409114441015993725554835256314039467401291,p)]); print(ellcard(E))'
```

## References

- https://en.wikipedia.org/wiki/Elliptic_curve
- https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/constructor.html
- https://neuromancer.sk/std/ (standard curve parameter database)
