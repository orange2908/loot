---
title: "RSA - Wiener's Attack (small private exponent d)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, wiener, small-d, small-private-exponent, continued-fractions, convergents, continued-fraction-expansion, phi, quadratic-formula, discriminant, low-private-exponent, huge-e, rsactftool, owiener, boneh-durfee]
difficulty: medium
summary: "d < n^0.25/3 -> k/d is a convergent of e/n, so continued fractions of e/n recover d without factoring."
when_to_use:
  - "e is enormous (nearly the size of n) - the classic tell for a small d"
  - "Source says d = getPrime(64) / d = randint(small) and then e = inverse(d, phi)"
  - "A signing service is suspiciously fast, or the challenge mentions 'fast decryption'"
  - "n is 1024+ bits so factoring is hopeless but only one (n, e, c) is given"
  - "Wiener fails but d is only slightly above n^0.25 -> extended/Dujella variant, then Boneh-Durfee"
tools: [python3, owiener, rsactftool, sympy]
source:
  name: "Wikipedia - Wiener's attack"
  url: "https://en.wikipedia.org/wiki/Wiener%27s_attack"
related: [rsa-boneh-durfee, rsa-known-phi-known-d, rsa-partial-key-exposure]
---

## TL;DR

If the private exponent satisfies `d < n^(1/4)/3`, the fraction `k/d` (from
`e*d - k*phi = 1`) is one of the continued-fraction convergents of `e/n`.
Enumerate the convergents, test each candidate `d`, and you get the private key
directly - no factoring. Milliseconds, any modulus size.

## Recognise it

- `e` has roughly as many bits as `n`. A "random looking" 1024-bit `e` is the signature
  of `e = inverse(d, phi)` with a tiny `d`.
- The generator code computes `d` first (`d = getPrime(256)` with `n` 2048 bits) and derives `e`.
- Key sizes: `d.bit_length() < n.bit_length() / 4` is the exact usable region.
- Ciphertext + public key only; no oracle, no second modulus.
- Quick check: run Wiener, it either works in 20 ms or it does not.

## Theory

From $e d \equiv 1 \pmod{\varphi(n)}$ we get $e d - k \varphi(n) = 1$ for some integer $k$.
With $\varphi(n) = n - p - q + 1 \approx n$:

$$\left| \frac{e}{n} - \frac{k}{d} \right| = \left| \frac{ed - kn}{nd} \right| \approx \frac{3k}{ d \sqrt{n}}$$

Legendre's theorem says any fraction approximating $e/n$ that closely (better than
$1/(2d^2)$) must be a convergent of the continued fraction expansion of $e/n$. The bound
works out to $d < \tfrac{1}{3} n^{1/4}$.

Verification of a candidate $(k, d)$:
1. $\varphi = (ed - 1)/k$ must be an exact integer.
2. $p + q = n - \varphi + 1$, so $p, q$ are roots of $x^2 - (n-\varphi+1)x + n$.
3. The discriminant $(n-\varphi+1)^2 - 4n$ must be a perfect square. If it is, you have
   the factorisation - a much stronger check than "decrypting looks like ASCII".

## Attack

1. Compute the continued-fraction expansion of `e/n`.
2. For each convergent `k/d`:
   - skip `k == 0`;
   - `phi = (e*d - 1) / k` must divide exactly;
   - solve the quadratic, require a perfect-square discriminant;
   - if `p*q == n`, return `(p, q, d)`.
3. If nothing hits, widen with the Dujella/Verheul-van Tilborg trick: try
   `k/d = (r*p_{i+1} + s*p_i) / (r*q_{i+1} + s*q_i)` for small `r, s`; that buys a few extra
   bits above `n^0.25`. Past that, use Boneh-Durfee (`d < n^0.292`).

## Code

```python
#!/usr/bin/env python3
"""Wiener's attack (+ the Dujella-style extension) on small private exponents.

    python3 rsa_wiener.py            # self-test
    python3 rsa_wiener.py N E [C]    # attack a real instance
"""
from __future__ import annotations

import sys
from math import isqrt

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


def continued_fraction(a: int, b: int, limit: int = 4096) -> list[int]:
    """Partial quotients of a/b."""
    cf = []
    while b and len(cf) < limit:
        cf.append(a // b)
        a, b = b, a % b
    return cf


def convergents(cf: list[int]):
    """Yield (numerator, denominator) for every convergent of the expansion."""
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for x in cf:
        p0, p1 = p1, x * p1 + p0
        q0, q1 = q1, x * q1 + q0
        yield p1, q1


def check_candidate(n: int, e: int, k: int, d: int):
    """If (k, d) is the right pair, return (p, q, d); else None."""
    if k <= 0 or d <= 0:
        return None
    if (e * d - 1) % k:
        return None
    phi = (e * d - 1) // k
    s = n - phi + 1                 # p + q
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = isqrt(disc)
    if r * r != disc:
        return None
    p, q = (s + r) // 2, (s - r) // 2
    if p * q != n:
        return None
    return p, q, d


def wiener(n: int, e: int):
    """Classic Wiener: works for d < n^(1/4)/3."""
    for k, d in convergents(continued_fraction(e, n)):
        hit = check_candidate(n, e, k, d)
        if hit:
            return hit
    return None


def wiener_extended(n: int, e: int, bound: int = 60):
    """Dujella / Verheul-van Tilborg style extension.

    Searches k/d = (r*p_{i+1} + s*p_i) / (r*q_{i+1} + s*q_i) for |r|,|s| <= bound.
    Buys roughly log2(bound) extra bits of d over plain Wiener. Slower but still fast.
    """
    conv = list(convergents(continued_fraction(e, n)))
    for i in range(len(conv) - 1):
        (pa, qa), (pb, qb) = conv[i], conv[i + 1]
        for r in range(bound):
            for s in range(-bound, bound):
                hit = check_candidate(n, e, r * pb + s * pa, r * qb + s * qa)
                if hit:
                    return hit
    return None


def solve(n: int, e: int, c: int | None = None):
    res = wiener(n, e)
    tag = "wiener"
    if res is None:
        res = wiener_extended(n, e)
        tag = "wiener-extended"
    if res is None:
        print("[-] no small d found; try Boneh-Durfee (d < n^0.292)")
        return None
    p, q, d = res
    print(f"[+] {tag}: d = {d}  ({d.bit_length()} bits)")
    print(f"    p = {p}")
    print(f"    q = {q}")
    if c is not None:
        pt = long_to_bytes(pow(c, d, n))
        print(f"    m = {pt!r}")
    return p, q, d


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    import time
    random.seed(2024)

    def make_key(nbits: int, dbits: int):
        while True:
            p, q = getPrime(nbits // 2), getPrime(nbits // 2)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            d = random.getrandbits(dbits) | 1
            if d <= 1 or __import__("math").gcd(d, phi) != 1:
                continue
            e = pow(d, -1, phi)
            if e.bit_length() < nbits - 16:      # make sure e really is huge
                continue
            return n, e, d, p, q

    # --- classic Wiener region: d ~ n^0.2 ---------------------------------- #
    n, e, d, p, q = make_key(1024, 200)
    t0 = time.time()
    res = wiener(n, e)
    assert res is not None, "wiener failed inside its own bound"
    assert res[2] == d and {res[0], res[1]} == {p, q}
    print(f"[+] wiener recovered a {d.bit_length()}-bit d in {(time.time()-t0)*1000:.1f} ms")

    # decryption round-trip
    flag = b"CTF{continued_fractions_are_not_your_friend}"
    c = pow(bytes_to_long(flag), e, n)
    assert long_to_bytes(pow(c, d, n)) == flag
    print("[+] decryption round-trip ok")

    # --- just above n^0.25: plain Wiener fails, extension succeeds --------- #
    n2, e2, d2, p2, q2 = make_key(1024, 258)
    plain = wiener(n2, e2)
    ext = wiener_extended(n2, e2, bound=60)
    print(f"[i] d = {d2.bit_length()} bits, n^0.25 = {isqrt(isqrt(n2)).bit_length()} bits,"
          f" plain wiener: {'ok' if plain else 'FAILED (expected)'}")
    assert ext is not None and ext[2] == d2, "extended wiener failed"
    print("[+] extended (Dujella) wiener recovered d above the classic bound")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        N, E = int(sys.argv[1], 0), int(sys.argv[2], 0)
        C = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
        solve(N, E, C)
    else:
        _selftest()
```

## Variants & pitfalls

- **Use `n`, not `phi`,** in the continued fraction - you do not know `phi` yet.
- **`e/n` vs `n/e`**: expand `e/n`. Getting it backwards yields nothing.
- **Verify by factoring**, not by "the plaintext looks printable": the perfect-square
  discriminant test has no false positives.
- **Multi-prime / CRT-exponent variants**: if `n = p*q*r`, the `phi ~ n` approximation still
  holds, so Wiener often still works; the quadratic step does not, so fall back to
  `factor_from_d` (see `rsa-known-phi-known-d`) once a candidate `d` passes the divisibility test.
- **`lambda(n)` instead of `phi(n)`**: if the key was built with the Carmichael function,
  `e*d - k*lambda = 1` and `phi = g*lambda`; the convergent search still finds a valid `d`
  for decryption even when the quadratic fails. Test `pow(pow(2, e, n), d, n) == 2`.
- **d between n^0.25 and n^0.292** -> Boneh-Durfee (`rsa-boneh-durfee`).
- **Partially known d** -> `rsa-partial-key-exposure`.
- Cheap sanity check without any attack: `e.bit_length()` close to `n.bit_length()`
  means "small d" with very high probability.

## Tools

```bash
# owiener: pip install owiener   (pure python, one call)
python3 -c 'import owiener;print(owiener.attack(<E>, <N>))'

# RsaCtfTool
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack wiener

# sympy continued fraction of e/n (inspect the partial quotients by hand)
python3 -c 'from sympy import continued_fraction_iterator, Rational
import itertools
print(list(itertools.islice(continued_fraction_iterator(Rational(<E>, <N>)), 20)))'
```

## References

- M. Wiener, "Cryptanalysis of Short RSA Secret Exponents" (IEEE IT, 1990)
- Wikipedia: https://en.wikipedia.org/wiki/Wiener%27s_attack
- A. Dujella, "Continued fractions and RSA with small secret exponent" (2004)
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
