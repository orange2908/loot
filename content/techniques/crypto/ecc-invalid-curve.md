---
title: "ECC - Invalid Curve and Small-Subgroup Attacks on ECDH"
category: crypto
subcategory: ecc
type: technique
tags: [ecc, elliptic-curve, invalid-curve, small-subgroup, ecdh, point-validation, cofactor, crt, chinese-remainder-theorem, pohlig-hellman, key-recovery, static-key, oracle, cve-2015-3193, sage, python]
difficulty: medium
summary: "The group law never uses b. Send a point from a different curve with smooth order, read d mod small primes from the shared secret, CRT the static key."
when_to_use:
  - "An ECDH service accepts a peer public key and never checks it is on the curve"
  - "The server reuses a static private key across sessions"
  - "The implementation only feeds x into the ladder, or ignores the cofactor"
  - "You can submit arbitrary (x, y) and observe the derived secret or a MAC under it"
tools: [sage, python, pari]
related: [ecc-pohlig-hellman, ecc-twist-attack, ecc-montgomery-x-only, dlp-diffie-hellman-attacks, ecc-toolkit]
---

## TL;DR

Short-Weierstrass addition and doubling use `p`, `a` and the input coordinates -- never `b`.
So a point that satisfies `y^2 = x^3 + a x + b'` for some *other* `b'` is multiplied happily
by the victim's static key `d`, but inside the group of the *invalid* curve `E'`. Choose `b'`
so `#E'` has a small prime factor `r`, send a point of order `r`, learn `d mod r`. Repeat
with different `b'` until CRT pins `d`.

## Recognise it

- The handshake parses `(x, y)` and immediately calls `scalar_mult(d, peer_point)`.
- No `assert E.is_on_curve(P)`, no `if not curve.contains(P): abort`.
- `d` is loaded from a file or generated once at import time (static key).
- The response is a deterministic function of the shared secret: a ciphertext, a MAC, a
  "your session key is ..." echo, or simply `x(dP)`.
- The cofactor is not cleared, or the code multiplies by `h` only after the scalar mult.

## Theory

**The group law ignores `b`.**

$$\lambda = \frac{3x_1^2 + a}{2y_1} \quad\text{or}\quad \frac{y_2-y_1}{x_2-x_1}, \qquad
x_3 = \lambda^2 - x_1 - x_2, \qquad y_3 = \lambda(x_1-x_3) - y_1$$

`b` appears nowhere. Every `(x, y)` in `GF(p)^2` lies on exactly one curve of the family
`y^2 = x^3 + a x + b'` with `b' = y^2 - x^3 - a x`, and the formulas implement that curve's
group law.

**Small subgroup.** Pick `b'` until `#E'` (computable: Schoof, or naive counting for small
`p`) has a small prime factor `r`. Find `T` of order `r` by taking a random point `R` on `E'`
and setting `T = (#E' / r) R`. Send `T`. The victim computes `dT`, which lies in the
order-`r` cyclic group `<T>`, so it equals `(d mod r) T`. Try all `r` candidates against the
observed output: you learn `d mod r`.

**Accumulate and CRT.** Gather coprime moduli `r_1, r_2, ...` until `prod r_i > n = ord(G)`.
Then `d = CRT(...)`. If the product is only `M < n`, you still know `d mod M`; finish with a
search over `n/M` values or Pollard's kangaroo.

**Sign ambiguity.** If the oracle only leaks `x(dT)`, you cannot distinguish `d` from `-d`
modulo `r`, so each `r` gives two candidates. With `t` moduli that is `2^t` combinations --
fix it by keeping one modulus unambiguous, or by testing the CRT result against the real
public key `dG` at the end.

**Why it is still relevant.** Real CVEs: unvalidated ECDH points in Bouncy Castle
(CVE-2015-7940), in Java JCE (CVE-2017-10352-era), and in several TLS stacks. NIST SP 800-56A
mandates the public key validation step precisely because of this.

## Attack

1. Confirm no point validation (send garbage, see if it still answers).
2. For `b'` = 1, 2, 3, ...: compute `#E'`, factor it, harvest small prime factors `r` you have
   not used, together with a point `T_r` of order `r`.
3. Query the oracle with each `T_r`, brute-force `j` in `[0, r)` until `j*T_r` matches.
4. CRT all `(j, r)` pairs. Stop when the modulus exceeds `ord(G)`.
5. Verify `d*G == pubkey`.

## Code

```python
#!/usr/bin/env python3
"""Invalid-curve attack on a static-key ECDH oracle, end to end."""
import random
from math import gcd

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
        assert (r - x) % g == 0, "inconsistent residues"
        t = ((r - x) // g * pow(m // g, -1, n // g)) % (n // g)
        x, m = x + m * t, m // g * n
    return x % m

def qr_table(p):
    """Set of quadratic residues mod p -- makes naive point counting fast."""
    return {x * x % p for x in range(1, (p + 1) // 2)}

def count_points(p, a, b, qrs):
    """#E(GF(p)) by Legendre symbols. O(p): small p only."""
    n = 1
    for x in range(p):
        rhs = (x * x * x + a * x + b) % p
        n += 1 if rhs == 0 else (2 if rhs in qrs else 0)
    return n

def random_point(p, a, b, rng):
    while True:
        x = rng.randrange(p)
        rhs = (x * x * x + a * x + b) % p
        y = pow(rhs, (p + 1) // 4, p)        # requires p = 3 mod 4
        if y * y % p == rhs and y:
            return (x, y)

def point_of_order(p, a, b, order, r, rng):
    """A point of exact order r on y^2 = x^3 + a*x + b."""
    for _ in range(200):
        T = mul(p, a, order // r, random_point(p, a, b, rng))
        if T is not None and mul(p, a, r, T) is None:
            return T
    return None

class Oracle:
    """A static-key ECDH peer that forgets to validate the point it is given."""

    def __init__(self, p, a, d):
        self.p, self.a, self.d, self.queries = p, a, d, 0

    def exchange(self, P):
        self.queries += 1
        return mul(self.p, self.a, self.d, P)     # no on-curve check. that is the bug.

def invalid_curve_attack(p, a, b, oracle, target_modulus, rng, max_r=2000):
    """Recover the oracle's static key modulo a product of small primes."""
    qrs = qr_table(p)
    used, rs, ms, M = set(), [], [], 1
    bprime = 0
    while M < target_modulus and bprime < 60:
        bprime += 1
        if bprime == b % p:
            continue                               # that is the real curve
        order = count_points(p, a, bprime, qrs)
        for r, e in factorize(order).items():
            if r in used or r > max_r or r < 3 or r ** e == order:
                continue
            T = point_of_order(p, a, bprime, order, r, rng)
            if T is None:
                continue
            S = oracle.exchange(T)                 # victim computes d*T in E'
            cur, found = None, None
            for j in range(r):
                if cur == S:
                    found = j
                    break
                cur = add(p, a, cur, T)
            if found is None:
                continue
            used.add(r)
            rs.append(found)
            ms.append(r)
            M *= r
            if M >= target_modulus:
                break
    return crt(rs, ms), M, sorted(used)

if __name__ == "__main__":
    rng = random.Random(21)
    # the "real" curve: y^2 = x^3 + 3x + 8 over a prime with p = 3 mod 4
    p, a, b = 1000003, 3, 8
    qrs = qr_table(p)
    n = count_points(p, a, b, qrs)
    G = random_point(p, a, b, rng)
    print(f"[ok] real curve #E = {n} = {factorize(n)}")

    d = rng.randrange(2, n)
    pub = mul(p, a, d, G)
    oracle = Oracle(p, a, d)

    rec, M, primes = invalid_curve_attack(p, a, b, oracle, n, rng)
    print(f"[ok] recovered d mod {M} using small subgroups of order {primes}")
    print(f"    {oracle.queries} oracle queries, no point validation anywhere")

    # CRT may leave a residual range; walk it against the public key
    cand = rec
    while cand < M * (n // M + 2):
        if mul(p, a, cand, G) == pub:
            break
        cand += M
    assert cand % n == d % n, (cand, d)
    print(f"[ok] static private key recovered: d = {d}")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Server validates but ignores the cofactor.** Then you cannot leave the curve, but you can
  still send a point of order `h` (the cofactor) on the *real* curve and learn `d mod h`.
  With `h = 8` that is 3 bits per session -- pair it with a lattice/HNP attack.
- **x-only APIs (Montgomery ladders).** You cannot pick `y`, but every `x` is on either the
  curve or its quadratic twist, so the attack becomes the *twist attack*: see
  `ecc-twist-attack`.
- **Ephemeral keys.** One query per key means one `d_i mod r`, which is worthless. The attack
  needs a static key (or a key reused at least `t` times).
- **The oracle returns a MAC/ciphertext, not the point.** Same thing: derive the candidate
  shared secret for each `j`, run it through the same KDF, compare. Costs `r` KDF calls.
- **Only `x(dT)` leaks.** Each modulus gives `+/-j`. Either keep one unambiguous modulus or
  enumerate `2^t` CRT combinations and test against the public key.
- **Composite `r`.** Using a prime *power* subgroup is fine but the brute force costs `r^e`;
  prefer distinct primes.
- **Big `p`.** `count_points` here is `O(p)`. For real 256-bit challenges use Sage:
  `EllipticCurve(GF(p), [a, bprime]).order()`.
- **Degenerate inputs.** Some implementations blow up on `(0, 0)` or the point at infinity
  encoded as `(0, 0)`. Try those first -- they sometimes leak `d` directly or crash into a
  debug trace.

## Tools

```python
# SageMath: harvest small-order points from invalid curves at 256-bit sizes
E = EllipticCurve(GF(p), [a, b])
found = {}
for bp in range(1, 500):
    Ep = EllipticCurve(GF(p), [a, bp])
    for r, _ in factor(Ep.order()):
        if r < 2**24 and r not in found:
            T = Ep.gens()[0] * (Ep.order() // r)
            if T.order() == r:
                found[r] = (bp, T)
    if prod(found) > E.order():
        break
print(sorted(found))
```

## References

- https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman#Security
- Antipa, Brown, Menezes, Struik, Vanstone, "Validation of Elliptic Curve Public Keys" (PKC 2003)
- NIST SP 800-56A Rev. 3, section 5.6.2.3 (public key validation)
- https://safecurves.cr.yp.to/twist.html
