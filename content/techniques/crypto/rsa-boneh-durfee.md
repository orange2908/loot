---
title: "RSA - Boneh-Durfee (lattice attack on d < n^0.292)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, boneh-durfee, small-d, small-private-exponent, lattice, lll, lattice-reduction, coppersmith, howgrave-graham, bivariate, resultant, sage, sagemath, fpylll, flatter, wiener, delta-292, unravelled-linearization]
difficulty: hard
summary: "Lattice extension of Wiener: recovers d up to n^0.292 by solving 1 + x(A+y) = 0 mod e with LLL and a resultant."
when_to_use:
  - "e is huge (close to n bits) so d is small, but Wiener's attack returned nothing"
  - "d is between n^0.25 and n^0.292 (roughly 250-300 bits for a 1024-bit n)"
  - "The challenge explicitly mentions 'small d', 'fast decryption', delta, or Boneh-Durfee"
  - "You already tried the extended/Dujella continued-fraction search and it timed out"
  - "You have SageMath (or fpylll) available - this attack needs LLL"
tools: [sage, sagemath, fpylll, flatter, python3, rsactftool]
related: [rsa-wiener-small-d, rsa-coppersmith, rsa-partial-key-exposure]
---

## TL;DR

Wiener dies at `d < n^0.25`. Boneh-Durfee pushes the bound to `d < n^0.292` by turning
`e*d = 1 + k*phi(n)` into the small-root problem `f(x, y) = 1 + x*(A + y) = 0 mod e`
with `A = (n+1)/2`, `x = 2k`, `y = -(p+q)/2`, and solving it with an LLL-reduced lattice of
x-shifts and y-shifts, then a resultant. You need Sage (or fpylll) - pure Python LLL is too
slow for the 30-60 dimensional lattices involved.

## Recognise it

- Same fingerprint as Wiener: `e.bit_length()` approx `n.bit_length()`.
- Wiener (and the Dujella extension) returned `None`.
- Generation code: `d = getPrime(int(0.28 * n_bits))` or `delta = 0.28`.
- You are told `d < N^0.28` or similar in the challenge description.
- The modulus is a normal 2-prime RSA modulus with balanced primes (BD assumes that;
  unbalanced primes need a different lattice).

## Theory

Start from $e d = 1 + k\varphi(n)$ with $\varphi(n) = n + 1 - (p+q)$. Write
$A = \frac{n+1}{2}$ and $s = \frac{p+q}{2}$ (both integers because $n$ is odd and $p, q$
are odd). Then

$$e d = 1 + 2k\,(A - s) \quad\Longrightarrow\quad f(x,y) = 1 + x (A + y) \equiv 0 \pmod e$$

with the small root $(x_0, y_0) = (2k,\; -s)$ and bounds
$|x_0| < X \approx 2 n^{\delta}$, $|y_0| < Y \approx n^{0.5}$ (balanced primes).

Coppersmith/Howgrave-Graham: build a lattice from the shift polynomials
$x^i f^k e^{m-k}$ (x-shifts) and $y^j f^k e^{m-k}$ (y-shifts) evaluated at $(xX, yY)$;
LLL gives two short vectors, i.e. two polynomials $h_1, h_2$ that vanish over
$\mathbb{Z}$ at $(x_0, y_0)$. Their resultant in $x$ is a univariate polynomial in $y$
whose integer root is $y_0$. From $y_0$: $p + q = -2 y_0$, and $p, q$ are roots of
$X^2 - (p+q)X + n$.

The "unravelled linearization" trick (substituting $u = xy + 1$) is what lifts the bound
from $0.284$ to $0.292$; every practical implementation uses it.

## Attack

1. Confirm `d` is small: `e` nearly as big as `n`, Wiener failed.
2. Choose lattice parameters: `delta` (your guess for `log_n d`), `m` (4-8), `t ~ floor((1-2*delta)*m)`.
3. Build the x-shift and y-shift lattice for `f = 1 + x*(A+y)` modulo `e`.
4. LLL-reduce; take the two shortest vectors as polynomials `pol1, pol2`.
5. `res = pol1.resultant(pol2, x)`; its integer root is `y0 = -(p+q)/2`.
6. Recover `p + q = -2*y0`, factor `n` via the quadratic, compute `d`.
7. If it fails, increase `m` (and `t`), or increase your `delta` guess.

## Code (SageMath - the real attack)

```python
# boneh_durfee.sage   --   run with:  sage boneh_durfee.sage
# Simplified Boneh-Durfee with unravelled linearization (u = x*y + 1).
# Needs SageMath: LLL over 40+ dimensional lattices and bivariate resultants.

import time


def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """Return (x0, y0) for pol(x, y) = 0 mod modulus with |x0| < XX, |y0| < YY."""
    PR = PolynomialRing(ZZ, names=('u', 'x', 'y'))
    u, x, y = PR.gens()
    Q = PR.quotient(x * y + 1 - u)          # unravelled linearization
    polZ = Q(pol).lift()
    UU = XX * YY + 1

    # ---- x-shifts:  x^i * f^k * e^(m-k) ---------------------------------- #
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            gg.append(x ** ii * modulus ** (mm - kk) * polZ(u, x, y) ** kk)
    gg.sort()

    monomials = []
    for poly in gg:
        for mono in poly.monomials():
            if mono not in monomials:
                monomials.append(mono)
    monomials.sort()

    # ---- y-shifts:  y^j * f^k * e^(m-k) ---------------------------------- #
    for jj in range(1, tt + 1):
        for kk in range(floor(mm / tt) * jj, mm + 1):
            yshift = y ** jj * polZ(u, x, y) ** kk * modulus ** (mm - kk)
            gg.append(Q(yshift).lift())
    for jj in range(1, tt + 1):
        for kk in range(floor(mm / tt) * jj, mm + 1):
            monomials.append(u ** kk * y ** jj)

    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) \
                             * monomials[jj](UU, XX, YY)

    print("[i] lattice dimension:", nn)
    t0 = time.time()
    BB = BB.LLL()
    print("[i] LLL done in %.1fs" % (time.time() - t0))

    # ---- two shortest vectors back to polynomials ------------------------ #
    pol1 = pol2 = 0
    for jj in range(nn):
        pol1 += monomials[jj](u, x, y) * BB[0, jj] / monomials[jj](UU, XX, YY)
        pol2 += monomials[jj](u, x, y) * BB[1, jj] / monomials[jj](UU, XX, YY)

    PRq = PolynomialRing(ZZ, names=('q',))
    (q,) = PRq.gens()
    rr = pol1.resultant(pol2)
    if rr.is_zero() or rr.monomials() == [1]:
        print("[-] resultant degenerate: raise mm/tt or the delta guess")
        return 0, 0
    rr = rr(q, q)
    soly = rr.roots()[0][0]
    ss = pol1(q, q, soly)
    solx = ss.roots()[0][0]
    return solx, soly


def attack(N, e, delta=0.28, m=4):
    A = int((N + 1) / 2)
    P = PolynomialRing(ZZ, names=('x', 'y'))
    x, y = P.gens()
    pol = 1 + x * (A + y)

    XX = 2 * floor(N ** delta)          # |x0| = |2k|
    YY = floor(N ** 0.5)                # |y0| = (p+q)/2
    t = int((1 - 2 * delta) * m)        # optimal t for this delta

    solx, soly = boneh_durfee(pol, e, m, t, XX, YY)
    if solx == 0:
        return None

    s = -soly * 2                       # p + q
    disc = s * s - 4 * N
    r = isqrt(disc)
    assert r * r == disc, "bad root: p+q does not give integer primes"
    p, q = (s + r) // 2, (s - r) // 2
    assert p * q == N
    d = inverse_mod(e, (p - 1) * (q - 1))
    return int(p), int(q), int(d)


if __name__ == '__main__':
    # ---- self-contained demo: generate a small-d key and break it -------- #
    set_random_seed(0)
    nbits, delta = 1024, 0.27
    while True:
        p = random_prime(2 ** (nbits // 2), lbound=2 ** (nbits // 2 - 1))
        q = random_prime(2 ** (nbits // 2), lbound=2 ** (nbits // 2 - 1))
        N = p * q
        phi = (p - 1) * (q - 1)
        d = ZZ.random_element(2 ** int(nbits * delta - 1), 2 ** int(nbits * delta))
        if gcd(d, phi) != 1:
            continue
        e = inverse_mod(d, phi)
        if e.nbits() > nbits - 16:
            break
    print("[i] d has", d.nbits(), "bits, N has", N.nbits())
    res = attack(int(N), int(e), delta=delta + 0.01, m=5)
    print("[+] recovered:", res is not None and res[2] == d)
```

## Code (pure Python fallback - no Sage)

Boneh-Durfee itself needs LLL, but the *cheap* part of the same idea - searching small
integer combinations of consecutive continued-fraction convergents (Dujella /
Verheul-van Tilborg) - is pure Python and already covers `d` a handful of bits above
`n^0.25`. Run this first: it takes two seconds and often removes the need for Sage.

```python
#!/usr/bin/env python3
"""Pure-python small-d recovery: Wiener + Dujella-style convergent combinations.

This is the fallback when SageMath is unavailable. It does NOT reach n^0.292;
it reaches roughly n^0.25 * bound. For the full Boneh-Durfee bound use the Sage
script above, or github.com/mimoo/RSA-and-LLL-attacks / defund/coppersmith.

    python3 bd_fallback.py            # self-test
    python3 bd_fallback.py N E [C]
"""
from __future__ import annotations

import sys
from math import gcd, isqrt

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:
    import random as _r

    def bytes_to_long(b: bytes) -> int:
        return int.from_bytes(b, "big")

    def long_to_bytes(x: int) -> bytes:
        return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")

    def _is_prime(n: int) -> bool:
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
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

    def getPrime(bits: int) -> int:
        while True:
            c = _r.getrandbits(bits) | (1 << (bits - 1)) | 1
            if _is_prime(c):
                return c


def convergents(a: int, b: int, limit: int = 4096):
    cf = []
    while b and len(cf) < limit:
        cf.append(a // b)
        a, b = b, a % b
    p0, p1, q0, q1 = 0, 1, 1, 0
    out = []
    for x in cf:
        p0, p1 = p1, x * p1 + p0
        q0, q1 = q1, x * q1 + q0
        out.append((p1, q1))
    return out


def check_candidate(n: int, e: int, k: int, d: int):
    if k <= 0 or d <= 0 or (e * d - 1) % k:
        return None
    phi = (e * d - 1) // k
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = isqrt(disc)
    if r * r != disc:
        return None
    p, q = (s + r) // 2, (s - r) // 2
    return (p, q, d) if p * q == n else None


def small_d_attack(n: int, e: int, bound: int = 80):
    conv = convergents(e, n)
    for k, d in conv:                                   # plain Wiener first
        hit = check_candidate(n, e, k, d)
        if hit:
            return hit + ("wiener",)
    for i in range(len(conv) - 1):                      # then the extension
        (pa, qa), (pb, qb) = conv[i], conv[i + 1]
        for r in range(bound):
            for s in range(-bound, bound):
                hit = check_candidate(n, e, r * pb + s * pa, r * qb + s * qa)
                if hit:
                    return hit + ("dujella",)
    return None


def _selftest() -> None:
    import random
    import time
    random.seed(99)
    while True:
        p, q = getPrime(512), getPrime(512)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = random.getrandbits(262) | 1                 # ~n^0.256, past Wiener
        if gcd(d, phi) != 1:
            continue
        e = pow(d, -1, phi)
        if e.bit_length() > 1000:
            break
    print(f"[i] n = {n.bit_length()} bits, d = {d.bit_length()} bits "
          f"(n^0.25 = {isqrt(isqrt(n)).bit_length()} bits)")
    t0 = time.time()
    res = small_d_attack(n, e, bound=80)
    assert res is not None, "fallback failed - you need the Sage script"
    assert res[2] == d and {res[0], res[1]} == {p, q}
    print(f"[+] recovered d via {res[3]} in {time.time() - t0:.2f}s")
    flag = b"CTF{small_d_is_a_lattice_away}"
    c = pow(bytes_to_long(flag), e, n)
    assert long_to_bytes(pow(c, d, n)) == flag
    print("[+] decryption round-trip ok")
    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        N, E = int(sys.argv[1], 0), int(sys.argv[2], 0)
        r = small_d_attack(N, E)
        print(r)
        if r and len(sys.argv) > 3:
            print(long_to_bytes(pow(int(sys.argv[3], 0), r[2], N)))
    else:
        _selftest()
```

## Variants & pitfalls

- **Lattice too small** -> the resultant is 0 or a constant. Raise `m` (4 -> 6 -> 8) and
  recompute `t = floor((1-2*delta)*m)`. Dimension grows fast; `m = 8` is already ~60.
- **delta guess too low** -> no root. Guess slightly *above* your estimate of
  `log_n(d)`; too high costs a bigger lattice but still works.
- **Unbalanced primes** break the `Y = n^0.5` bound. If `p` is much smaller than `q`,
  use `Y = 2 * p_upper_bound` or go straight for Fermat/ECM.
- **`helpful vectors` pruning**: the well-known reference implementation deletes rows that
  do not help, which makes `m = 8` tractable. The simplified script above does not - if it
  is too slow, use the reference implementation or `flatter` as the reduction backend.
- **fpylll instead of Sage**: `IntegerMatrix.from_matrix(...)`, `LLL.reduction(...)` gives
  the same lattice step in pure Python; you still need a resultant, e.g. via `sympy.resultant`.
- **Always try Wiener + Dujella first.** They are free, and many "Boneh-Durfee" challenges
  actually sit just above `n^0.25`.
- BD assumes `e < phi(n)`; if `e > n` reduce it first.

## Tools

```bash
# the reference Sage implementation everybody uses
git clone https://github.com/mimoo/RSA-and-LLL-attacks
sage RSA-and-LLL-attacks/boneh_durfee.sage

# generic multivariate Coppersmith in Sage
git clone https://github.com/defund/coppersmith

# RsaCtfTool bundles a boneh_durfee module
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack boneh_durfee

# faster LLL backend for big lattices
#   https://github.com/keeganryan/flatter    (drop-in replacement for fplll)
```

## References

- D. Boneh, G. Durfee, "Cryptanalysis of RSA with Private Key d Less Than N^0.292"
  (EUROCRYPT 1999)
- Herrmann, May, "Maximizing Small Root Bounds by Linearization" (unravelled linearization)
- mimoo/RSA-and-LLL-attacks: https://github.com/mimoo/RSA-and-LLL-attacks
- defund/coppersmith: https://github.com/defund/coppersmith
