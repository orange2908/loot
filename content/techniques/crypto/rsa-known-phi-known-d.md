---
title: "RSA - Multi-prime RSA, and Factoring n from phi or d"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, multi-prime, multiprime, three-primes, known-phi, phi, totient, known-d, private-exponent, factor-from-d, miller-rabin, quadratic-formula, lambda, carmichael, crt-rsa, sum-of-primes, p-plus-q, p-minus-q, rsactftool]
difficulty: medium
summary: "phi(n) or d leaks the factorisation: two primes fall out of a quadratic, any number of primes fall out of the e*d-1 square-root trick."
when_to_use:
  - "The challenge gives you phi(n), or p+q, or p-q, or (p-1)*(q-1)"
  - "You recovered d (Wiener, partial leak) and now need p and q, or n is multi-prime"
  - "n = p*q*r (multi-prime RSA), so the Wiener quadratic step does not apply"
  - "A key file has d but the primes are corrupted"
  - "You need dp/dq/qinv for CRT-RSA from a plain (n, d)"
tools: [python3, sympy, rsactftool, openssl]
related: [rsa-wiener-small-d, rsa-crt-fault-attack, rsa-pollard-rho-ecm, rsa-partial-key-exposure]
---

## TL;DR

- **Given `phi(n)` and `n = p*q`:** `p+q = n - phi + 1`, so `p` and `q` are the roots of
  `x^2 - (n-phi+1)x + n`. One `isqrt`.
- **Given any valid `d`:** `e*d - 1 = 2^s * t` is a multiple of `lambda(n)`. Pick random `g`,
  compute `g^t`, square repeatedly; a non-trivial square root of 1 gives
  `gcd(x-1, n)` = a factor. Works for **any** number of primes and always succeeds after a
  few random bases.
- **Multi-prime RSA** (`n = p*q*r*...`): everything works the same with
  `phi = prod(p_i - 1)`; only the "solve a quadratic" shortcut is 2-prime-specific.

## Recognise it

- A file dump contains `phi`, `totient`, `(p-1)*(q-1)`, or `p+q`.
- You ran Wiener and got `d`, but the quadratic step failed -> `n` has more than 2 primes.
- The handout says `n = p*q*r` or the modulus is 2048 bits with a `getPrime(512)` x4 keygen.
- An openssl key with corrupted `prime1`/`prime2` fields but an intact `privateExponent`.
- `dp`, `dq`, `qinv` are given but `p`, `q` are not (`p = gcd(pow(2, e*dp, n) - 2, n)`).

## Theory

**From phi, two primes.** $\varphi = (p-1)(q-1) = n - (p+q) + 1$, so $s = p+q = n-\varphi+1$
and $p, q = \frac{s \pm \sqrt{s^2 - 4n}}{2}$. The discriminant is a perfect square exactly
when the phi is right - a free correctness check.

**From d, any number of primes.** $ed - 1 = k\lambda(n)$ for some $k$, so for any $g$
coprime to $n$, $g^{ed-1} \equiv 1 \pmod n$. Write $ed-1 = 2^{s} t$ with $t$ odd. Compute
$x = g^{t}$ and square it up to $s$ times. Somewhere in that chain you find $x$ with
$x^2 \equiv 1$ but $x \not\equiv \pm 1 \pmod n$ - a non-trivial square root of unity -
and then $\gcd(x-1, n)$ is a proper factor. Each random $g$ works with probability
$\ge 1/2$, so a handful of tries always suffices. This is exactly the Miller-Rabin
witness computation, reused as a factoring routine.

**Multi-prime.** $\varphi(n) = \prod (p_i - 1)$, $\lambda(n) = \mathrm{lcm}(p_i - 1)$,
$d = e^{-1} \bmod \lambda$. Decryption via CRT over all primes is ~$k^2$ times faster,
which is why multi-prime RSA exists at all. Security drops because the *smallest* prime is
what ECM has to find: a 2048-bit 4-prime modulus has 512-bit primes, still safe; a
2048-bit 16-prime modulus has 128-bit primes, dead.

**From dp (CRT exponent).** $e\,d_p \equiv 1 \pmod{p-1}$, so for any base $a$,
$a^{e d_p} \equiv a \pmod p$, and $\gcd(a^{e d_p} - a \bmod n,\ n) = p$.

## Attack

1. Identify what you have: `phi`, `d`, `dp`, `p+q`, `p-q`, `lambda`.
2. `phi` + 2 primes -> quadratic.
3. `d` (or `k*lambda`) -> the randomized square-root routine below (any prime count).
4. `dp` -> one `pow` and a `gcd`.
5. Once split, recurse on the cofactor until every part is prime (multi-prime case).
6. Rebuild: `phi = prod(p_i - 1)`, `d = pow(e, -1, phi)`, decrypt.

## Code

```python
#!/usr/bin/env python3
"""Factor n from phi, from d, from dp, or from p+q; multi-prime aware.

    python3 rsa_known_phi_d.py                     # self-test
    python3 rsa_known_phi_d.py --phi N E PHI [C]
    python3 rsa_known_phi_d.py --d   N E D   [C]
"""
from __future__ import annotations

import random
import sys
from math import gcd, isqrt

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:
    def bytes_to_long(b: bytes) -> int:
        return int.from_bytes(b, "big")

    def long_to_bytes(x: int) -> bytes:
        return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")

    def getPrime(bits: int) -> int:
        while True:
            c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_probable_prime(c):
                return c


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# --------------------------------------------------------------------------- #
def factor_from_phi(n: int, phi: int):
    """Two-prime case: p and q are roots of x^2 - (n-phi+1)x + n."""
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = isqrt(disc)
    if r * r != disc:
        return None
    p, q = (s + r) // 2, (s - r) // 2
    return (p, q) if p * q == n else None


def factor_from_sum(n: int, p_plus_q: int):
    return factor_from_phi(n, n - p_plus_q + 1)


def factor_from_diff(n: int, p_minus_q: int):
    """p-q known: (p+q)^2 = (p-q)^2 + 4n."""
    s2 = p_minus_q * p_minus_q + 4 * n
    s = isqrt(s2)
    if s * s != s2:
        return None
    p, q = (s + p_minus_q) // 2, (s - p_minus_q) // 2
    return (p, q) if p * q == n else None


def factor_from_d(n: int, e: int, d: int, tries: int = 100, rng=random):
    """Split n using any valid private exponent. Works for any number of primes.

    Returns one non-trivial factor, or None (essentially never).
    """
    k = e * d - 1
    if k <= 0:
        return None
    t, s = k, 0
    while t % 2 == 0:
        t //= 2
        s += 1
    for _ in range(tries):
        g = rng.randrange(2, n - 1)
        if gcd(g, n) > 1:
            return gcd(g, n)
        x = pow(g, t, n)
        for _ in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                f = gcd(x - 1, n)
                if 1 < f < n:
                    return f
            x = y
    return None


def factor_multiprime_from_d(n: int, e: int, d: int, rng=random) -> list[int]:
    """Full factorisation of a multi-prime modulus from d."""
    parts = [n]
    for _ in range(200):
        if all(is_probable_prime(x) for x in parts) and len(parts) > 1:
            break
        newparts = []
        progressed = False
        for x in parts:
            if is_probable_prime(x) or x == 1:
                newparts.append(x)
                continue
            f = factor_from_d(x, e, d, tries=40, rng=rng)
            if f and 1 < f < x:
                newparts += [f, x // f]
                progressed = True
            else:
                newparts.append(x)
        parts = newparts
        if not progressed and all(is_probable_prime(x) for x in parts):
            break
    return sorted(parts)


def factor_from_dp(n: int, e: int, dp: int, bases=(2, 3, 5, 7)):
    """dp = d mod (p-1): gcd(a^(e*dp) - a, n) = p."""
    for a in bases:
        f = gcd(pow(a, e * dp, n) - a, n)
        if 1 < f < n:
            return f, n // f
    return None


def crt_decrypt(c: int, primes: list[int], e: int) -> int:
    """Multi-prime CRT decryption, the reason multi-prime RSA exists."""
    n = 1
    for p in primes:
        n *= p
    m = 0
    for p in primes:
        d_p = pow(e, -1, p - 1)
        m_p = pow(c % p, d_p, p)
        n_p = n // p
        m = (m + m_p * n_p * pow(n_p, -1, p)) % n
    return m


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    random.seed(77)

    # --- phi -> p, q -------------------------------------------------------- #
    p, q = getPrime(512), getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    assert set(factor_from_phi(n, phi)) == {p, q}
    print("[+] factor_from_phi ok")

    # p+q and p-q variants
    assert set(factor_from_sum(n, p + q)) == {p, q}
    assert set(factor_from_diff(n, abs(p - q))) == {p, q}
    print("[+] factor_from_sum / factor_from_diff ok")

    # wrong phi must be rejected, not silently wrong
    assert factor_from_phi(n, phi + 2) is None
    print("[+] a wrong phi is detected")

    # --- d -> p, q ---------------------------------------------------------- #
    e = 65537
    d = pow(e, -1, phi)
    f = factor_from_d(n, e, d)
    assert f in (p, q), "factor_from_d failed"
    print("[+] factor_from_d ok (2 primes)")

    # --- dp -> p ------------------------------------------------------------ #
    dp = d % (p - 1)
    res = factor_from_dp(n, e, dp)
    assert res is not None and set(res) == {p, q}
    print("[+] factor_from_dp ok")

    # --- multi-prime: n = p*q*r*s ------------------------------------------- #
    ps = sorted(getPrime(256) for _ in range(4))
    n4 = 1
    phi4 = 1
    for x in ps:
        n4 *= x
        phi4 *= x - 1
    e = 65537
    d4 = pow(e, -1, phi4)
    got = factor_multiprime_from_d(n4, e, d4)
    assert got == ps, f"multiprime split failed: {[x.bit_length() for x in got]}"
    print(f"[+] factored a {n4.bit_length()}-bit 4-prime modulus from d")

    # the quadratic shortcut must NOT pretend to work here
    assert factor_from_phi(n4, phi4) is None
    print("[+] the 2-prime quadratic correctly refuses a 4-prime modulus")

    # --- multi-prime encryption / CRT decryption round trip ----------------- #
    flag = b"CTF{multi_prime_is_still_rsa}"
    m = bytes_to_long(flag)
    c = pow(m, e, n4)
    assert crt_decrypt(c, ps, e) == m
    assert pow(c, d4, n4) == m
    assert long_to_bytes(crt_decrypt(c, ps, e)) == flag
    print("[+] multi-prime CRT decryption ok:", flag.decode())

    # --- lambda instead of phi ---------------------------------------------- #
    def lcm(a: int, b: int) -> int:
        return a // gcd(a, b) * b

    lam = 1
    for x in ps:
        lam = lcm(lam, x - 1)
    d_lam = pow(e, -1, lam)
    assert pow(c, d_lam, n4) == m
    assert factor_multiprime_from_d(n4, e, d_lam) == ps
    print("[+] works with lambda(n) as well as phi(n)")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 5 and sys.argv[1] in ("--phi", "--d"):
        N, E, V = (int(x, 0) for x in sys.argv[2:5])
        C = int(sys.argv[5], 0) if len(sys.argv) > 5 else None
        if sys.argv[1] == "--phi":
            res = factor_from_phi(N, V)
            print("factors:", res)
            if res and C is not None:
                print(long_to_bytes(pow(C, pow(E, -1, V), N)))
        else:
            fs = factor_multiprime_from_d(N, E, V)
            print("factors:", fs)
            if C is not None:
                print(long_to_bytes(pow(C, V, N)))
    else:
        _selftest()
```

## Variants & pitfalls

- **`phi` vs `lambda`.** If the given "phi" is really `lambda(n) = lcm(p-1, q-1)`, the
  quadratic fails. Try `phi_candidate * k` for small `k` (usually `k = gcd(p-1,q-1)`), or
  just use the `factor_from_d` routine, which does not care.
- **The discriminant check is the verification.** No perfect square -> your `phi` is wrong.
- **`e*d - 1` can be astronomically large** but only its 2-adic valuation and odd part
  matter; the routine is `O(s)` modular squarings.
- **d given but wrong `e`**: the routine silently fails. Try `e = 65537, 3, 17`.
- **Multi-prime with repeated primes** (`n = p^2 * q`): the square-root trick returns
  `p^2` or `p`; keep splitting and test `is_probable_prime` at every step. Also check
  `perfect_power`.
- **phi for `n = p^2 q`** is `p(p-1)(q-1)`, not `(p^2-1)(q-1)` - a classic mistake.
- **dp/dq leaks** are extremely common in "CRT-RSA" challenges; one `pow` + `gcd` is all
  it takes. See also `rsa-crt-fault-attack`.
- If `e` and `phi` are not coprime, `pow(e, -1, phi)` raises - see `rsa-eth-root-amm`.

## Tools

```bash
# extract every field from a private key (n, e, d, p, q, dp, dq, qinv)
openssl rsa -in key.pem -text -noout

# rebuild a PEM from p, q, e with pycryptodome
python3 -c '
from Crypto.PublicKey import RSA
p,q,e = <P>,<Q>,65537
n=p*q; d=pow(e,-1,(p-1)*(q-1))
print(RSA.construct((n,e,d,p,q)).export_key().decode())'

# RsaCtfTool when you have a partial key
python3 RsaCtfTool.py --key key.pem --private --attack all
```

## References

- G. Miller / M. Rabin: the square-root-of-unity trick behind `factor_from_d`
- RFC 8017 section 3.2 (multi-prime RSA): https://www.rfc-editor.org/rfc/rfc8017
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
