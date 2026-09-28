---
title: "ECC - Pohlig-Hellman on Smooth-Order Curves"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, pohlig-hellman, ecdlp, dlp, discrete-log, smooth-order, crt, chinese-remainder-theorem, bsgs, baby-step-giant-step, pollard-rho, cofactor, subgroup, partial-key, sage, pari, python]
difficulty: medium
summary: "If the point order factors into small primes, solve the ECDLP in each prime-power subgroup and CRT the answers. Cost is sum(e_i*sqrt(q_i)), not sqrt(n)."
when_to_use:
  - "factor(E.order()) or factor(P.order()) shows only small primes"
  - "The curve is non-standard and nobody checked the group order"
  - "A large prime factor remains but the smooth part already pins down enough of the key"
  - "You have an oracle that answers on a small-order point (pairs with invalid-curve attacks)"
tools: [sage, pari, python]
related: [dlp-pohlig-hellman, dlp-bsgs-pollard-rho, ecc-invalid-curve, ecc-twist-attack, ecc-toolkit]
---

## TL;DR

The ECDLP in a group of order `n = prod q_i^{e_i}` decomposes: project into each
order-`q_i^{e_i}` subgroup by multiplying by `n / q_i^{e_i}`, solve there (cheap, because the
subgroup is tiny), and glue with CRT. Total work `sum e_i * sqrt(q_i)` instead of `sqrt(n)`.
Smooth order = broken curve.

## Recognise it

- `factor(E.order())` prints a wall of small primes: `2^3 * 3 * 5 * 7 * 11 * ...`.
- The challenge picks `p` and then searches for `a, b` "until the order is nice".
- `P.order()` is much smaller than `#E` (a small-order generator was handed to you).
- A remote ECDH service accepts arbitrary points -- combine with `ecc-invalid-curve`, which
  *manufactures* smooth-order subgroups.
- The cofactor `h = #E / n` is large and you were given a point of order `h`.

## Theory

Let `ord(P) = n = prod_i q_i^{e_i}` and `Q = kP`. Fix a prime power `q^e || n`, set
`m = n / q^e`, and consider `P_i = mP` (order `q^e`) and `Q_i = mQ = k * P_i`. Then
`k mod q^e` is the discrete log of `Q_i` base `P_i` in a group of order `q^e`.

Inside that subgroup, solve digit by digit in base `q`. Write
`k = d_0 + d_1 q + ... + d_{e-1} q^{e-1} (mod q^e)`. Having found `d_0..d_{j-1}` as `x`,

$$\left(\frac{n}{q^{j+1}}\right)\left(Q - xP\right) = d_j \cdot \left(\frac{n}{q}\right)P$$

and both sides live in the order-`q` subgroup, so `d_j` is one BSGS of cost `sqrt(q)`.

Finally CRT the residues `k mod q_i^{e_i}` into `k mod n`.

**Partial Pohlig-Hellman.** If `n = s * L` with `s` smooth and `L` a large prime, you still
recover `k mod s` for free. If `k < s` you are done. If `k` is bigger, write `k = k0 + s*t`
with `k0` known and brute-force / kangaroo `t` over a range of size `n/s`. This is by far
the most common CTF shape: "the order is *mostly* smooth".

**Cost.** `sum_i e_i * (sqrt(q_i) + log n)` group operations. A 256-bit order that factors
into 32-bit primes costs about `8 * 2^16` operations -- milliseconds.

## Attack

1. Get `n = ord(P)`. If you only know `#E`, divide out factors until `n*P = O` is minimal.
2. `factor(n)`. If the largest prime factor exceeds ~`2^50`, this alone will not finish.
3. For each `q^e`, project and solve for `k mod q^e` (digit-by-digit + BSGS).
4. CRT. Verify `k*P == Q`.
5. If a large factor remains, CRT only the smooth part and brute-force the residual range.

## Code

```python
#!/usr/bin/env python3
"""Pohlig-Hellman on an elliptic curve, with the partially-smooth fallback."""
import random
from math import gcd, isqrt

INF = None

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

def neg(p, P):
    return None if P is None else (P[0], (-P[1]) % p)

def mul(p, a, k, P):
    if k < 0:
        return neg(p, mul(p, a, -k, P))
    R, S = None, P
    while k:
        if k & 1:
            R = add(p, a, R, S)
        S, k = add(p, a, S, S), k >> 1
    return R

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
    for b in small:
        x = pow(b, d, n)
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

def crt(rs, ms):
    x, m = 0, 1
    for r, n in zip(rs, ms):
        g = gcd(m, n)
        assert (r - x) % g == 0, "inconsistent residues"
        t = ((r - x) // g * pow(m // g, -1, n // g)) % (n // g)
        x, m = x + m * t, m // g * n
    return x % m

def ec_bsgs(p, a, P, Q, order):
    """Q = k*P with 0 <= k < order, O(sqrt(order))."""
    m = isqrt(order) + 1
    tab, R = {}, None
    for j in range(m):
        tab.setdefault(R, j)
        R = add(p, a, R, P)
    step, S = neg(p, mul(p, a, m, P)), Q
    for i in range(m + 1):
        if S in tab:
            return (i * m + tab[S]) % order
        S = add(p, a, S, step)
    return None

def point_order(p, a, P, multiple):
    """Exact order of P given any multiple of it."""
    n = multiple
    for q, e in factorize(n).items():
        for _ in range(e):
            if mul(p, a, n // q, P) is None:
                n //= q
            else:
                break
    return n

def pohlig_hellman(p, a, P, Q, order, max_prime=1 << 40):
    """Return (k_mod_M, M): k is known modulo M, using only primes <= max_prime."""
    rs, ms = [], []
    for q, e in factorize(order).items():
        if q > max_prime:
            continue                       # too expensive, skip this factor
        x, qk = 0, 1
        gen = mul(p, a, order // q, P)
        for i in range(e):
            Qi = add(p, a, Q, neg(p, mul(p, a, x, P)))
            Qi = mul(p, a, order // q ** (i + 1), Qi)
            d = ec_bsgs(p, a, gen, Qi, q)
            if d is None:
                raise ValueError(f"no log in the order-{q} subgroup")
            x, qk = x + d * qk, qk * q
        rs.append(x % q ** e)
        ms.append(q ** e)
    if not ms:
        raise ValueError("no usable smooth factors")
    M = 1
    for m in ms:
        M *= m
    return crt(rs, ms) % M, M

def finish_by_search(p, a, P, Q, k0, M, limit):
    """k = k0 + M*t; walk t. Uses only additions, so it is fast."""
    R = mul(p, a, k0, P)
    step = mul(p, a, M, P)
    for t in range(limit + 1):
        if R == Q:
            return k0 + M * t
        R = add(p, a, R, step)
    return None

if __name__ == "__main__":
    rng = random.Random(11)

    # ---- 1. fully smooth curve order ----
    # small enough that we can count points exactly with Legendre symbols
    p, a, b = 1000003, 3, 8            # p = 3 mod 4, so square roots are one pow()
    order = 1
    for x in range(p):
        rhs = (x * x * x + a * x + b) % p
        if rhs == 0:
            order += 1
        elif pow(rhs, (p - 1) // 2, p) == 1:
            order += 2
    print(f"[ok] #E = {order} = {factorize(order)}")

    while True:
        x = rng.randrange(p)
        rhs = (x * x * x + a * x + b) % p
        if pow(rhs, (p - 1) // 2, p) != 1:
            continue
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p != rhs:
            continue
        P = (x, y)
        break
    n = point_order(p, a, P, order)
    k = rng.randrange(2, n)
    Q = mul(p, a, k, P)
    rec, M = pohlig_hellman(p, a, P, Q, n)
    assert M == n and rec == k, (rec, k)
    assert mul(p, a, rec, P) == Q
    print(f"[ok] ord(P) = {n}, Pohlig-Hellman recovered k = {k}")

    # ---- 2. partially smooth: a big prime factor we refuse to touch ----
    # Pretend the order-n group has a 'hard' factor by capping max_prime.
    biggest = max(factorize(n))
    rec2, M2 = pohlig_hellman(p, a, P, Q, n, max_prime=biggest - 1)
    assert k % M2 == rec2 and M2 < n
    print(f"[ok] partial run: k known mod {M2} (skipped the prime {biggest})")
    full = finish_by_search(p, a, P, Q, rec2, M2, n // M2)
    assert full is not None and full % n == k
    print(f"[ok] finished by walking {n // M2} steps: k = {full}")
    print("all self-tests passed")
```

## Variants and pitfalls

- **You need `ord(P)`, not `#E`.** Using `#E` when `P` has smaller order makes the projections
  land in the wrong subgroup and the CRT inconsistent. `point_order` above fixes it.
- **Repeated prime factors.** The digit-by-digit loop is mandatory for `q^e` with `e > 1`;
  a single BSGS modulo `q^e` costs `q^{e/2}` instead of `e*sqrt(q)`.
- **`k` larger than the smooth part.** Pohlig-Hellman gives `k mod M`. If `M < ord(P)` you
  must still search `ord(P)/M` candidates -- do it with repeated point additions
  (`finish_by_search`), or with Pollard's kangaroo when that range is large.
- **CRT inconsistency.** Almost always means a wrong order or a point that is not actually in
  the group you think. Re-derive `ord(P)`.
- **Order 1 or 2 subgroups.** `q = 2` needs care: the "BSGS" is just a comparison. The code
  above handles it, but hand-rolled versions often divide by zero here.
- **This is the engine behind other attacks.** Invalid-curve, twist and small-subgroup
  attacks all end in a Pohlig-Hellman over manufactured small subgroups; the difference is
  only how you obtain the small-order points.
- **Large but not huge factors.** A 50-bit factor costs `2^25` operations: minutes in Python,
  seconds with Pollard's rho in Sage. Do not skip it too eagerly.

## Tools

```python
# SageMath: one-liners
E = EllipticCurve(GF(p), [a, b])
print(factor(E.order()))
P = E.gens()[0]; Q = k * P
print(Q.log(P))                          # Pohlig-Hellman + rho, Sage 10.x spelling
print(discrete_log(Q, P, ord=P.order(), operation='+'))
```

```sh
# PARI/GP: curve order and its factorisation without Sage
gp -q -c 'p=1000003; E=ellinit([Mod(3,p),Mod(8,p)]); n=ellcard(E); print(n); print(factor(n))'
```

## References

- https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
- https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_point.html
- https://safecurves.cr.yp.to/ (why real curves have prime order and small cofactor)
