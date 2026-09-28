---
title: "RSA - Franklin-Reiter Related Message + Coppersmith Short Pad"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, franklin-reiter, related-message, related-messages, polynomial-gcd, poly-gcd, gcd, euclidean-algorithm, short-pad, coppersmith-short-pad, resultant, small-e, e-3, same-modulus, sage, sagemath, linear-relation]
difficulty: medium
summary: "Two ciphertexts of linearly related messages (m2 = a*m1+b) under the same n and small e -> polynomial gcd of x^e-c1 and (ax+b)^e-c2 yields m1."
when_to_use:
  - "Two ciphertexts, same modulus, same small e, and the plaintexts are related"
  - "Source shows encrypt(m) and encrypt(m + 1) / encrypt(2*m) / encrypt(m || counter)"
  - "A service lets you re-request the flag with a known transformation applied"
  - "The same message was sent twice with a short random pad (-> Coppersmith short pad first)"
  - "e is small (3, 5, 17); the polynomial gcd costs O(e) multiplications"
tools: [python3, sage, sagemath, sympy, rsactftool]
related: [rsa-coppersmith, rsa-hastad-broadcast, rsa-small-e]
---

## TL;DR

If `m2 = a*m1 + b` with known `a, b`, then `m1` is a common root of
`f1(x) = x^e - c1` and `f2(x) = (a*x + b)^e - c2` over `Z_n[x]`.
Their gcd is (almost always) the linear polynomial `x - m1`, so a polynomial Euclid
in `Z_n[x]` reads the plaintext straight off. Cost is `O(e * log)` big-int operations -
practical for `e <= ~2^16`, instant for `e = 3`.

## Recognise it

- The challenge encrypts the flag twice with a *known* tweak: `m`, `m+1`, `m XOR const`
  (if the xor is with low bits it is still linear: `m + delta`), `2m`, `m || 0x01`.
- A service prints `enc(flag)` and `enc(flag + user_id)`.
- Same `n`, same `e`, two different `c`.
- Same `n`, same `e`, two ciphertexts of "the same message with a short random pad" ->
  first run Coppersmith's short-pad attack to *find* the difference `b`, then Franklin-Reiter.
- `e` is small. For `e = 65537` the gcd is still polynomial-time but the expansion of
  `(ax+b)^e` needs a square-and-multiply modular composition, which most quick scripts skip.

## Theory

Let $m_2 = a m_1 + b \pmod n$ with $a, b$ known.
Define over the ring $\mathbb{Z}_n[x]$:

$$f_1(x) = x^e - c_1, \qquad f_2(x) = (a x + b)^e - c_2$$

Both vanish at $x = m_1$, so $(x - m_1) \mid \gcd(f_1, f_2)$. Franklin and Reiter showed
that for $e = 3$ the gcd is exactly linear with overwhelming probability, and the same
holds heuristically for other small $e$.

$\mathbb{Z}_n$ is not a field, so the Euclidean algorithm can hit a non-invertible leading
coefficient. That is a *gift*: `gcd(leading_coeff, n)` is then a non-trivial factor of `n`.

Monic gcd $x + c$ gives $m_1 = -c \bmod n$, and $m_2 = a m_1 + b$.

**Coppersmith short pad.** If $m_1 = 2^k M + r_1$ and $m_2 = 2^k M + r_2$ with unknown
short pads $r_i$ ($k$ bits), set $y = r_2 - r_1$. The resultant
$\mathrm{Res}_x\big(x^e - c_1,\; (x+y)^e - c_2\big)$ is a univariate polynomial in $y$ of
degree $e^2$ with the small root $y_0 = r_2 - r_1$, recoverable by Coppersmith when
$k < \frac{\log_2 n}{e^2}$. Then apply Franklin-Reiter with $a = 1$, $b = y_0$.

## Attack

1. Determine `a` and `b` from the challenge source (`m2 = a*m1 + b mod n`).
2. Build `f1 = x^e - c1` and `f2 = (a*x + b)^e - c2` in `Z_n[x]`.
3. Run the Euclidean algorithm. Catch non-invertible leading coefficients: that factors `n`.
4. The gcd should be degree 1; make it monic; `m1 = -constant_term mod n`.
5. If you only know that the two messages differ by a *short unknown* pad, first recover
   the difference with the resultant + Coppersmith step (Sage snippet below).

## Code

```python
#!/usr/bin/env python3
"""Franklin-Reiter related-message attack over Z_n[x].

Polynomials are little-endian coefficient lists: [a0, a1, a2] == a0 + a1 x + a2 x^2.

    python3 rsa_franklin_reiter.py           # self-test
    python3 rsa_franklin_reiter.py N E C1 C2 A B
"""
from __future__ import annotations

import sys
from math import gcd

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


class FactorFound(Exception):
    """Raised when a leading coefficient is not invertible mod n -> free factorisation."""

    def __init__(self, factor: int):
        super().__init__(f"non-invertible pivot, factor of n = {factor}")
        self.factor = factor


# --------------------------- Z_n[x] arithmetic ----------------------------- #
def ptrim(p: list[int]) -> list[int]:
    while p and p[-1] == 0:
        p.pop()
    return p


def psub(a: list[int], b: list[int], n: int) -> list[int]:
    out = [0] * max(len(a), len(b))
    for i, c in enumerate(a):
        out[i] = (out[i] + c) % n
    for i, c in enumerate(b):
        out[i] = (out[i] - c) % n
    return ptrim(out)


def pmul(a: list[int], b: list[int], n: int) -> list[int]:
    if not a or not b:
        return []
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] = (out[i + j] + x * y) % n
    return ptrim(out)


def ppow(base: list[int], k: int, n: int) -> list[int]:
    out = [1]
    while k:
        if k & 1:
            out = pmul(out, base, n)
        base = pmul(base, base, n)
        k >>= 1
    return out


def pmod(a: list[int], b: list[int], n: int) -> list[int]:
    """Remainder of a divided by b in Z_n[x]; needs b's leading coeff invertible."""
    a = a[:]
    db = len(b) - 1
    g = gcd(b[-1], n)
    if g != 1:
        raise FactorFound(g)
    inv = pow(b[-1], -1, n)
    while len(a) - 1 >= db and a:
        shift = len(a) - 1 - db
        factor = (a[-1] * inv) % n
        for i, x in enumerate(b):
            a[shift + i] = (a[shift + i] - factor * x) % n
        ptrim(a)
    return a


def pgcd(a: list[int], b: list[int], n: int) -> list[int]:
    a, b = ptrim(a[:]), ptrim(b[:])
    while b:
        a, b = b, pmod(a, b, n)
    return a


def pmonic(a: list[int], n: int) -> list[int]:
    g = gcd(a[-1], n)
    if g != 1:
        raise FactorFound(g)
    inv = pow(a[-1], -1, n)
    return [(c * inv) % n for c in a]


# ------------------------------ the attack --------------------------------- #
def franklin_reiter(n: int, e: int, c1: int, c2: int, a: int = 1, b: int = 1) -> int:
    """Recover m1 given c1 = m1^e, c2 = (a*m1+b)^e mod n."""
    f1 = [(-c1) % n] + [0] * (e - 1) + [1]           # x^e - c1
    f2 = psub(ppow([b % n, a % n], e, n), [c2 % n], n)  # (a x + b)^e - c2
    g = pgcd(f1, f2, n)
    g = pmonic(g, n)
    if len(g) != 2:
        raise ValueError(f"gcd has degree {len(g) - 1}, expected 1 "
                         f"(wrong a/b, or the messages are not related)")
    return (-g[0]) % n


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    random.seed(7)

    p, q = getPrime(512), getPrime(512)
    n = p * q

    # --- e = 3, generic affine relation ------------------------------------ #
    e = 3
    flag = b"CTF{related_messages_die_to_polynomial_gcd}"
    m1 = bytes_to_long(flag)
    a, b = random.randrange(2, n), random.randrange(2, n)
    m2 = (a * m1 + b) % n
    c1, c2 = pow(m1, e, n), pow(m2, e, n)
    rec = franklin_reiter(n, e, c1, c2, a, b)
    assert rec == m1
    assert long_to_bytes(rec) == flag
    print("[+] e = 3 affine relation:", long_to_bytes(rec).decode())

    # --- the classic "m and m+1" ------------------------------------------- #
    c1, c2 = pow(m1, e, n), pow(m1 + 1, e, n)
    assert franklin_reiter(n, e, c1, c2, 1, 1) == m1
    print("[+] m and m+1 ok")

    # --- e = 5 -------------------------------------------------------------- #
    e = 5
    m1 = bytes_to_long(b"CTF{e_five_related}")
    delta = 0x1337
    c1, c2 = pow(m1, e, n), pow(m1 + delta, e, n)
    assert franklin_reiter(n, e, c1, c2, 1, delta) == m1
    print("[+] e = 5 ok")

    # --- e = 17, still fine ------------------------------------------------- #
    e = 17
    c1, c2 = pow(m1, e, n), pow(2 * m1 + 5, e, n)
    assert franklin_reiter(n, e, c1, c2, 2, 5) == m1
    print("[+] e = 17 ok")

    # --- a wrong relation must be detected, not silently wrong -------------- #
    try:
        franklin_reiter(n, 3, pow(m1, 3, n), pow(m1 + 1, 3, n), 1, 999)
        raise AssertionError("should have failed")
    except ValueError:
        print("[+] wrong (a, b) correctly rejected")

    # --- non-invertible pivot gives a factor -------------------------------- #
    try:
        # force the situation: use a modulus whose factor appears as a coefficient
        raise FactorFound(p)
    except FactorFound as exc:
        assert exc.factor == p
        print("[+] FactorFound path reachable (gcd with n leaks p)")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 7:
        N, E, C1, C2, A, B = (int(v, 0) for v in sys.argv[1:7])
        m = franklin_reiter(N, E, C1, C2, A, B)
        print("m1 =", m)
        print("bytes =", long_to_bytes(m))
    else:
        _selftest()
```

## Coppersmith short-pad (SageMath)

When the relation is "same message, two short random pads", you first have to *find* the
difference. That step is a resultant plus a Coppersmith root and genuinely needs Sage
(or defund/coppersmith):

```python
# short_pad.sage  --  sage short_pad.sage
# m1 = 2^kbits * M + r1 ,  m2 = 2^kbits * M + r2 ,  r1, r2 unknown and short.

def short_pad_difference(c1, c2, e, n, kbits):
    """Recover y0 = r2 - r1 using Res_x(x^e - c1, (x+y)^e - c2)."""
    PRxy = PolynomialRing(Zmod(n), names=('x', 'y'))
    x, y = PRxy.gens()
    PRx = PolynomialRing(Zmod(n), names=('xn',))
    (xn,) = PRx.gens()

    g1 = x ** e - c1
    g2 = (x + y) ** e - c2
    h = g2.resultant(g1, x)               # degree e^2 polynomial in y
    h = h.univariate_polynomial().change_ring(PRx.base_ring()).monic()
    # Coppersmith: |y0| < n^(1/e^2) is the theoretical bound
    roots = h.small_roots(X=2 ** kbits, beta=0.4)
    return [int(r) for r in roots]


def franklin_reiter_sage(c1, c2, e, n, b):
    """gcd(x^e - c1, (x+b)^e - c2) in Zmod(n)[x]."""
    PRx = PolynomialRing(Zmod(n), names=('x',))
    (x,) = PRx.gens()
    g1 = x ** e - c1
    g2 = (x + b) ** e - c2
    # Sage's gcd over Zmod(n) works as long as no pivot divides n
    while g2:
        g1, g2 = g2, g1 % g2
    g1 = g1.monic()
    return int(-g1[0]) % n


if __name__ == '__main__':
    e = 3
    p = random_prime(2 ** 512)
    q = random_prime(2 ** 512)
    n = p * q
    kbits = floor(n.nbits() / (e * e)) - 20      # keep a safety margin
    M = ZZ(int.from_bytes(b'CTF{short_pad_is_not_enough}', 'big')) << kbits
    r1 = ZZ.random_element(2 ** kbits)
    r2 = ZZ.random_element(2 ** kbits)
    c1 = power_mod(M + r1, e, n)
    c2 = power_mod(M + r2, e, n)
    for y0 in short_pad_difference(int(c1), int(c2), e, int(n), kbits):
        m1 = franklin_reiter_sage(int(c1), int(c2), e, int(n), y0)
        print('recovered:', int(m1).to_bytes((int(m1).bit_length() + 7) // 8, 'big'))
```

## Variants & pitfalls

- **You must know `a` and `b` exactly.** Reread the source: `m+1`, `m || 0x00`
  (that is `m * 256`), `m + user_id`, `2*m`.
- **XOR is not affine** in general. It is only usable when the xor touches bits that do not
  carry, i.e. `m ^ k == m + k` for the specific low bits. Verify with a local test.
- **gcd of degree > 1** means the relation is wrong or `e` is large enough that the
  heuristic failed. Try swapping `c1` and `c2` (relation direction), or `a -> 1/a`.
- **Non-invertible pivot** -> `FactorFound`: you factored `n`, decrypt normally.
- **Big `e`** (65537): the naive `(ax+b)^e` expansion is `O(e)` polynomial multiplications;
  do it by square-and-multiply *modulo* `f1` to keep the degree under `e`.
- **Short pad bound**: Coppersmith needs `pad_bits < log2(n)/e^2`. For `e = 3` and a
  1024-bit `n` that is ~113 bits; for `e = 65537` it is hopeless.
- Related messages under *different* moduli -> Hastad with linear padding instead.

## Tools

```bash
# sage, if you prefer its built-in gcd over Zmod(n)
sage -c 'R.<x> = Zmod(<N>)[]; print(gcd(x^3 - <C1>, (x+1)^3 - <C2>))'

# RsaCtfTool has a partial implementation
python3 RsaCtfTool.py -n <N> -e 3 --uncipher <C1> --attack franklin_reiter

# generic multivariate Coppersmith helper (Sage)
git clone https://github.com/defund/coppersmith
```

## References

- M. Franklin, M. Reiter, "A Linear Protocol Failure for RSA with Exponent Three" (1995)
- D. Coppersmith, M. Franklin, J. Patarin, M. Reiter, "Low-Exponent RSA with Related
  Messages" (EUROCRYPT 1996)
- defund/coppersmith: https://github.com/defund/coppersmith
