---
title: "ECC - MOV / Frey-Ruck Pairing Attack (Low Embedding Degree)"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, mov-attack, frey-ruck, pairing, weil-pairing, tate-pairing, miller-algorithm, embedding-degree, supersingular, ecdlp, dlp, discrete-log, index-calculus, distortion-map, sage, python]
difficulty: hard
summary: "A pairing maps E(GF(p))[n] into GF(p^k)^*. If the embedding degree k is small, the ECDLP becomes a finite-field DLP that index calculus eats."
when_to_use:
  - "The curve is supersingular (#E == p + 1, trace 0) -- embedding degree is 1, 2, 3, 4 or 6"
  - "The multiplicative order of p modulo n is small (k <= 12 or so)"
  - "Sage says E.is_supersingular() is True"
  - "A pairing-based protocol (BLS, IBE, zk gadget) reuses its curve for plain ECDH"
tools: [sage, python, pari]
related: [ecc-smart-anomalous, ecc-pohlig-hellman, dlp-index-calculus, ecc-toolkit, ecc-cheatsheet]
---

## TL;DR

The Weil and Tate pairings are bilinear maps `E[n] x E[n] -> mu_n <= GF(p^k)^*`, where `k`
is the *embedding degree*: the smallest `k` with `n | p^k - 1`. Bilinearity turns
`Q = k_s * P` into `e(Q, R) = e(P, R)^{k_s}`, i.e. a DLP in `GF(p^k)^*`. For a general curve
`k` is huge and this is useless; for a supersingular or pairing-friendly curve `k` is 2 or 6,
and finite-field index calculus is subexponential where generic ECDLP is exponential.

## Recognise it

- `#E == p + 1` exactly (trace 0) -> supersingular -> `k <= 6`.
- `y^2 = x^3 + x` with `p = 3 mod 4`, or `y^2 = x^3 + b` with `p = 2 mod 3`: the two classic
  supersingular families used in CTFs.
- `E.is_supersingular()` is `True` in Sage.
- Compute `k = multiplicative_order(Mod(p, n))` and find something small.
- The challenge mentions BLS signatures, identity-based encryption, `bn254`, `bls12-381`,
  or hands you `E.weil_pairing` / `E.tate_pairing` in the source.

## Theory

**Embedding degree.** Let `n = ord(P)`. `k` is the least integer with `n | p^k - 1`, i.e. the
multiplicative order of `p` mod `n`. Then `mu_n`, the `n`-th roots of unity, live in
`GF(p^k)` and nowhere smaller.

**Tate pairing.** For `P` of order `n` and `S` in `E(GF(p^k))`,

$$t(P, S) = f_{n,P}(S)^{(p^k - 1)/n} \in \mu_n$$

where `f_{n,P}` is the Miller function with divisor `n(P) - n(O)`. It is bilinear:
`t(aP, bS) = t(P, S)^{ab}`.

**Miller's algorithm** builds `f_{n,P}` by the double-and-add recursion

$$f_{i+j} = f_i \cdot f_j \cdot \frac{\ell_{iP,jP}}{v_{(i+j)P}}$$

with `l` the line through the two points and `v` the vertical through their sum: exactly the
chord-and-tangent construction, evaluated at `S`.

**The reduction.** Pick `S` in `E(GF(p^k))` such that `alpha = t(P, S)` has order `n`. Then

$$t(Q, S) = t(k_s P, S) = \alpha^{k_s}$$

so `k_s` is the discrete log of `t(Q, S)` base `alpha` in `GF(p^k)^*`. Solve it with
Pohlig-Hellman (if `n` is smooth), BSGS/rho (small `n`) or index calculus / NFS-DL
(large `n`, small `k`).

**Getting a good `S`: distortion maps.** On `y^2 = x^3 + x` over `GF(p)` with `p = 3 mod 4`,
the map `phi(x, y) = (-x, i*y)` with `i^2 = -1` sends `E(GF(p))` into `E(GF(p^2))` and is
*not* a multiplication by a scalar, so `t(P, phi(P))` is non-degenerate. That is the
"modified" pairing that makes the attack turnkey on supersingular curves. For ordinary
pairing-friendly curves there is no distortion map; take `S` from the trace-zero subgroup
`E(GF(p^k))[n] \ E(GF(p))[n]` instead.

**MOV vs Frey-Ruck.** MOV uses the Weil pairing (needs `E[n] \subseteq E(GF(p^k))`);
Frey-Ruck uses the Tate pairing (needs only `n | p^k - 1`, so it is strictly more general and
cheaper). Everyone says "MOV" and implements Frey-Ruck.

## Attack

1. Compute `n = ord(P)` and `k = ord of p modulo n`. Bail if `k` is large.
2. Build `GF(p^k)` and the curve over it.
3. Find `S` in `E(GF(p^k))` of order `n` and not in `<P>` (distortion map, or a random point
   multiplied by `#E(GF(p^k)) / n^2`).
4. `alpha = t(P, S)`, `beta = t(Q, S)`. Check `alpha^n == 1` and `alpha != 1`.
5. Solve `beta = alpha^{k_s}` in `GF(p^k)^*`.
6. Verify `k_s * P == Q`.

## Code

```python
#!/usr/bin/env python3
"""Frey-Ruck / MOV: Tate pairing over GF(p^2) on a supersingular curve, pure Python."""
import random
from math import isqrt

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

def embedding_degree(p, n, kmax=64):
    """Least k with n | p^k - 1, or None."""
    acc = p % n
    for k in range(1, kmax + 1):
        if acc == 1:
            return k
        acc = acc * p % n
    return None

# ---- GF(p^2) = GF(p)[i] / (i^2 + 1); valid because p = 3 mod 4 ----------

class F2:
    __slots__ = ("a", "b", "p")

    def __init__(self, a, b, p):
        self.a, self.b, self.p = a % p, b % p, p

    def __eq__(self, o):
        return self.a == o.a and self.b == o.b

    def __hash__(self):
        return hash((self.a, self.b))

    def __add__(self, o):
        return F2(self.a + o.a, self.b + o.b, self.p)

    def __sub__(self, o):
        return F2(self.a - o.a, self.b - o.b, self.p)

    def __neg__(self):
        return F2(-self.a, -self.b, self.p)

    def __mul__(self, o):
        return F2(self.a * o.a - self.b * o.b, self.a * o.b + self.b * o.a, self.p)

    def inverse(self):
        d = pow(self.a * self.a + self.b * self.b, -1, self.p)
        return F2(self.a * d, -self.b * d, self.p)

    def __truediv__(self, o):
        return self * o.inverse()

    def is_zero(self):
        return self.a == 0 and self.b == 0

    def __pow__(self, e):
        r, b = F2(1, 0, self.p), self
        if e < 0:
            b, e = b.inverse(), -e
        while e:
            if e & 1:
                r = r * b
            b, e = b * b, e >> 1
        return r

def one(p):
    return F2(1, 0, p)

# ---- curve arithmetic over GF(p^2) --------------------------------------

def ec_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2).is_zero():
        return None
    if P == Q:
        lam = (F2(3, 0, p) * x1 * x1 + a) / (F2(2, 0, p) * y1)
    else:
        lam = (y2 - y1) / (x2 - x1)
    x3 = lam * lam - x1 - x2
    return (x3, lam * (x1 - x3) - y1)

def ec_mul(k, P, a, p):
    R, S = None, P
    while k:
        if k & 1:
            R = ec_add(R, S, a, p)
        S, k = ec_add(S, S, a, p), k >> 1
    return R

# ---- Miller's algorithm and the reduced Tate pairing --------------------

def line_and_add(A, B, S, a, p):
    """Return (l_{A,B}(S) / v_{A+B}(S), A + B)."""
    if A is None:
        return one(p), B
    if B is None:
        return one(p), A
    x1, y1 = A
    x2, y2 = B
    xs, ys = S
    if x1 == x2 and (y1 + y2).is_zero():
        return xs - x1, None                       # the line is vertical
    if A == B:
        lam = (F2(3, 0, p) * x1 * x1 + a) / (F2(2, 0, p) * y1)
    else:
        lam = (y2 - y1) / (x2 - x1)
    x3 = lam * lam - x1 - x2
    y3 = lam * (x1 - x3) - y1
    return (ys - y1 - lam * (xs - x1)) / (xs - x3), (x3, y3)

def miller(P, S, n, a, p):
    """f_{n,P}(S) by double-and-add over the bits of n."""
    f, T = one(p), P
    for bit in bin(n)[3:]:
        v, T = line_and_add(T, T, S, a, p)
        f = f * f * v
        if bit == "1":
            v, T = line_and_add(T, P, S, a, p)
            f = f * v
    return f

def tate(P, S, n, a, p):
    """Reduced Tate pairing on E(GF(p^2)); value lies in mu_n."""
    return miller(P, S, n, a, p) ** ((p * p - 1) // n)

def bsgs_f2(g, h, order, p):
    """Discrete log in a cyclic subgroup of GF(p^2)^*."""
    m = isqrt(order) + 1
    tab, cur = {}, one(p)
    for j in range(m):
        tab.setdefault((cur.a, cur.b), j)
        cur = cur * g
    step, cur = (g ** m).inverse(), h
    for i in range(m + 1):
        key = (cur.a, cur.b)
        if key in tab:
            return (i * m + tab[key]) % order
        cur = cur * step
    return None

if __name__ == "__main__":
    rng = random.Random(5)

    # supersingular curve y^2 = x^3 + x over GF(p), p = 3 mod 4, #E(GF(p)) = p + 1.
    # Build p so that p + 1 = 4*n with n prime: the interesting subgroup is prime order.
    while True:
        n = rng.randrange(1 << 35, 1 << 36)
        p = 4 * n - 1
        if p % 4 == 3 and is_prime(p) and is_prime(n):
            break
    a, b = F2(1, 0, p), F2(0, 0, p)
    print(f"[ok] p = {p} ({p.bit_length()} bits), #E = p+1 = 4*{n}")
    assert embedding_degree(p, n) == 2, "supersingular with p = 3 mod 4 gives k = 2"
    print("[ok] embedding degree k = 2: the ECDLP lands in GF(p^2)^*")

    # a generator of the order-n subgroup, living in E(GF(p))
    while True:
        x = rng.randrange(p)
        rhs = (x * x * x + x) % p
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p != rhs:
            continue
        P = ec_mul(4, (F2(x, 0, p), F2(y, 0, p)), a, p)
        if P is not None and ec_mul(n, P, a, p) is None:
            break

    secret = rng.randrange(2, n)
    Q = ec_mul(secret, P, a, p)

    # distortion map phi(x, y) = (-x, i*y) lands in E(GF(p^2)) \ E(GF(p))
    phi = lambda R: (-R[0], F2(0, 1, p) * R[1])

    alpha = tate(P, phi(P), n, a, p)
    beta = tate(Q, phi(P), n, a, p)
    assert not (alpha == one(p)) and (alpha ** n) == one(p), "degenerate pairing"
    print("[ok] pairing is non-degenerate and lands in mu_n")

    rec = bsgs_f2(alpha, beta, n, p)
    assert rec == secret and ec_mul(rec, P, a, p) == Q
    print(f"[ok] ECDLP solved through GF(p^2)^*: k = {rec}")

    # bilinearity sanity checks
    assert tate(ec_mul(3, P, a, p), phi(P), n, a, p) == alpha ** 3
    assert tate(P, phi(ec_mul(5, P, a, p)), n, a, p) == alpha ** 5
    print("[ok] bilinearity verified in both arguments")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Degenerate pairing.** `t(P, S) == 1` means `S` is in `<P>` (or the wrong subgroup).
  On supersingular curves use the distortion map; otherwise take `S = ((#E(GF(p^k)))/n^2) * R`
  for a random `R` in `E(GF(p^k))`, and retry until non-degenerate.
- **Weil vs Tate.** The Weil pairing `e(P,Q) = f_{n,P}(Q)/f_{n,Q}(P)` (up to sign) needs two
  Miller loops and `E[n]` fully rational. Tate needs one loop and a final exponentiation.
  Prefer Tate.
- **`n` must be the order of `P`, not `#E`.** Running Miller with a non-multiple of `ord(P)`
  produces garbage.
- **Large `k`.** For a random curve `k ~ n`, so `GF(p^k)` is astronomically large and there is
  no attack. Always compute `k` before writing code.
- **Small `k` but large `n`.** BSGS will not finish. You need index calculus or the number
  field sieve for `GF(p^k)`; at CTF scale organisers keep `n` small or smooth on purpose.
- **Pairing-friendly curves in ZK challenges.** `bn254` and `bls12-381` have `k = 12`, which is
  secure. The bug in those challenges is never the pairing itself -- it is a missing subgroup
  check, a reused `S`, or a linear relation between published group elements.
- **Char 2 and 3.** Supersingular curves over `GF(2^m)` have `k = 4` and over `GF(3^m)` have
  `k = 6`. Same recipe, different field arithmetic.

## Tools

```python
# SageMath: the whole attack in a handful of lines
E = EllipticCurve(GF(p), [1, 0])
P = E.gens()[0]; Q = secret * P
n = P.order()
k = Mod(p, n).multiplicative_order()          # embedding degree
Ek = E.base_extend(GF(p**k, 'z'))
Pk, Qk = Ek(P), Ek(Q)
R = Ek.random_point() * (Ek.order() // n**2)  # an independent order-n point
alpha = Pk.tate_pairing(R, n, k)
beta = Qk.tate_pairing(R, n, k)
print(discrete_log(beta, alpha, ord=n, operation='*'))
```

```python
# SageMath: is it even worth trying?
print(E.is_supersingular(), E.order() == p + 1, Mod(p, P.order()).multiplicative_order())
```

## References

- Menezes, Okamoto, Vanstone, "Reducing elliptic curve logarithms to logarithms in a finite field", IEEE Trans. Inf. Theory 39 (1993)
- Frey, Ruck, "A remark concerning m-divisibility and the discrete logarithm in the divisor class group of curves", Math. Comp. 62 (1994)
- https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_point.html
- https://en.wikipedia.org/wiki/MOV_attack
