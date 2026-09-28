---
title: "RSA - Pollard rho, ECM, and Which Factoring Method to Use"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, pollard-rho, rho, brent, ecm, lenstra, elliptic-curve-factorization, gnfs, siqs, factoring, trial-division, yafu, gmp-ecm, cado-nfs, msieve, factordb, sympy, gmpy2, cycle-detection, smallest-factor]
difficulty: medium
summary: "Decision guide for factoring n: trial division -> factordb -> Fermat -> rho (small factors) -> p-1/p+1 -> ECM (factor < 60 digits) -> SIQS/GNFS."
when_to_use:
  - "You need to factor n and nothing structural (close primes, shared factor, small d) applies"
  - "n has an unbalanced factorisation: one small prime and one huge one"
  - "You want to know whether a factoring attempt is even feasible before burning an hour"
  - "n is under ~100 bits (rho) or has a factor under ~40 digits (ECM)"
  - "The challenge modulus is a multi-prime with several 64-128 bit factors"
tools: [yafu, gmp-ecm, cado-nfs, msieve, sympy, gmpy2, factordb, python3]
source:
  name: "Wikipedia - Pollard's rho algorithm"
  url: "https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm"
related: [rsa-pollard-p-minus-1, rsa-fermat-close-primes, rsa-common-factor-batch-gcd, rsa-known-phi-known-d]
---

## TL;DR

Rho finds a factor `p` in about `sqrt(p)` steps - great up to ~2^60, hopeless beyond.
ECM finds a factor in time depending on the *size of the smallest factor*, not on `n` -
it is the right tool for "one 40-digit prime hiding in a 2048-bit modulus".
GNFS depends on the size of `n` and is the only thing that breaks a balanced RSA modulus,
which in a CTF means the modulus is at most ~330 bits unless the challenge intends a
multi-day run.

## Decision table

| Situation | Method | Cost |
|---|---|---|
| `n < 2^70` | rho / SIQS in sympy | seconds |
| `n` already known publicly | factordb | instant |
| `p ~ q` | Fermat | instant |
| Many moduli | batch gcd | instant |
| `p-1` or `p+1` smooth | Pollard p-1 / Williams p+1 | seconds-minutes |
| smallest factor < 2^80 | Pollard rho | minutes |
| smallest factor < 10^40 | ECM (`gmp-ecm`, yafu) | minutes-hours |
| balanced `n`, < 110 digits | SIQS (`yafu`, `msieve`) | minutes-hours |
| balanced `n`, 110-230 digits | GNFS (`cado-nfs`) | days-months |
| balanced `n`, > 700 bits | not happening - find the real bug | - |

## Recognise it

- No structural weakness in the handout, but `n` is suspiciously small (256-512 bits).
- `n` is a product of several medium primes (multi-prime RSA) - ECM eats those.
- The challenge gives a huge `n` and expects you *not* to factor it: the bug is elsewhere.

## Theory

**Pollard rho.** Iterate $x_{i+1} = x_i^2 + c \bmod n$. Modulo an unknown prime $p$ the
sequence enters a cycle after ~$\sqrt{p}$ steps (birthday paradox), so two indices collide
mod $p$ but not mod $n$, and $\gcd(x_i - x_j, n) = p$. Brent's variant replaces Floyd's
tortoise/hare with a smarter stride and batches the gcds (multiply 100 differences, take
one gcd), roughly 25% fewer operations and far fewer gcd calls.

**ECM (Lenstra).** Same idea as Pollard p-1, but instead of the fixed group
$(\mathbb{Z}/p)^*$ of order $p-1$, use the group of points on a random elliptic curve
$E: y^2 = x^3 + ax + b$ over $\mathbb{Z}/p$, whose order is a *random* number near $p$
(Hasse: $|E| \in [p+1-2\sqrt p, p+1+2\sqrt p]$). Compute $[M]P$ with
$M = \mathrm{lcm}(1..B_1)$; if the curve order is $B_1$-powersmooth, the computation hits
the point at infinity modulo $p$, which in practice means a modular inverse fails and
`gcd(denominator, n)` is a factor. Each new curve is an independent lottery ticket, which
is why ECM scales with the size of the factor, not of `n`.

## Attack

1. Strip small primes by trial division up to 10^6.
2. Ask factordb.
3. Perfect power? (`n = p^k`) - check with integer roots.
4. Fermat (close primes), batch gcd (many moduli).
5. Rho with a step budget; stop it when it is clearly not converging.
6. p-1, p+1.
7. ECM with escalating `B1`: `2e3 (c=25)`, `11e3 (c=90)`, `5e4 (c=300)`, `25e4 (c=700)`,
   `1e6 (c=1800)` - the standard gmp-ecm ladder for 20/25/30/35/40-digit factors.
8. SIQS/GNFS as a last resort, with the right tool (yafu / msieve / cado-nfs).

## Code

```python
#!/usr/bin/env python3
"""Pollard rho (Brent), Lenstra ECM, and a driver that picks a method.

    python3 rsa_rho_ecm.py             # self-test
    python3 rsa_rho_ecm.py N           # try to factor N completely
"""
from __future__ import annotations

import random
import sys
from math import gcd, isqrt

try:
    from Crypto.Util.number import getPrime
except ImportError:
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


def primes_upto(n: int) -> list[int]:
    sieve = bytearray([1]) * (n + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, isqrt(n) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, n + 1, i)))
    return [i for i in range(n + 1) if sieve[i]]


def trial_division(n: int, bound: int = 100000):
    """Return (factors, remaining)."""
    facs = []
    for p in primes_upto(bound):
        while n % p == 0:
            facs.append(p)
            n //= p
        if n == 1:
            break
    return facs, n


def perfect_power(n: int):
    """If n = b^k for k >= 2, return (b, k), else None."""
    for k in range(2, n.bit_length() + 1):
        lo, hi = 1, 1 << (n.bit_length() // k + 1)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if mid ** k <= n:
                lo = mid
            else:
                hi = mid - 1
        if lo > 1 and lo ** k == n:
            return lo, k
    return None


# --------------------------------------------------------------------------- #
# Pollard rho, Brent's variant
# --------------------------------------------------------------------------- #
def pollard_rho_brent(n: int, max_iter: int = 1 << 24, rng=random):
    """Return a non-trivial factor of n (n composite, not a perfect power of 2)."""
    if n % 2 == 0:
        return 2
    if is_probable_prime(n):
        return n
    while True:
        y = rng.randrange(1, n)
        c = rng.randrange(1, n)
        m = 128
        g = r = q = 1
        x = ys = y
        total = 0
        while g == 1 and total < max_iter:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = gcd(q, n)
                k += m
                total += m
            r *= 2
        if g == n:                      # backtrack one step at a time
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = gcd(abs(x - ys), n)
        if g != n and g != 1:
            return g
        if total >= max_iter:
            return None


# --------------------------------------------------------------------------- #
# Lenstra ECM (stage 1, affine Weierstrass, gcd on inversion failure)
# --------------------------------------------------------------------------- #
class _Found(Exception):
    def __init__(self, f: int):
        super().__init__(str(f))
        self.f = f


def _ec_add(P, Q, a: int, n: int):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % n == 0:
        return None                      # point at infinity
    if P == Q:
        num, den = (3 * x1 * x1 + a) % n, (2 * y1) % n
    else:
        num, den = (y2 - y1) % n, (x2 - x1) % n
    g = gcd(den, n)
    if g > 1:
        if g < n:
            raise _Found(g)              # the whole point of ECM
        return None
    lam = num * pow(den, -1, n) % n
    x3 = (lam * lam - x1 - x2) % n
    return x3, (lam * (x1 - x3) - y1) % n


def _ec_mul(k: int, P, a: int, n: int):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, a, n)
        P = _ec_add(P, P, a, n)
        k >>= 1
    return R


def ecm(n: int, B1: int = 10000, curves: int = 40, rng=random):
    """Lenstra ECM stage 1. Good for factors up to ~2^60 with these defaults."""
    if n % 2 == 0:
        return 2
    ps = primes_upto(B1)
    for _ in range(curves):
        x, y, a = (rng.randrange(1, n) for _ in range(3))
        P = (x, y)                       # b is implied: b = y^2 - x^3 - a*x mod n
        try:
            for q in ps:
                e = q
                while e * q <= B1:
                    e *= q
                P = _ec_mul(e, P, a, n)
                if P is None:
                    break
        except _Found as f:
            return f.f
    return None


# --------------------------------------------------------------------------- #
def factor(n: int, verbose: bool = True) -> list[int]:
    """Full factorisation using the ladder above. Returns a sorted prime list."""
    out = []
    small, rest = trial_division(n, 100000)
    out += small
    if rest == 1:
        return sorted(out)
    stack = [rest]
    while stack:
        cur = stack.pop()
        if cur == 1:
            continue
        if is_probable_prime(cur):
            out.append(cur)
            continue
        pp = perfect_power(cur)
        if pp:
            b, k = pp
            if verbose:
                print(f"[i] {cur.bit_length()}-bit perfect power: b^{k}")
            stack += [b] * k
            continue
        f = pollard_rho_brent(cur, max_iter=1 << 20)
        if f is None or f == cur:
            for B1 in (2000, 11000, 50000):
                f = ecm(cur, B1, 40)
                if f:
                    break
        if f is None or f == cur:
            raise RuntimeError(f"could not factor {cur} - escalate to yafu/cado-nfs")
        if verbose:
            print(f"[+] split {cur.bit_length()} bits -> {f.bit_length()} bits")
        stack += [f, cur // f]
    return sorted(out)


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import time
    random.seed(1234)

    # --- rho on a 64-bit semiprime ----------------------------------------- #
    p, q = getPrime(32), getPrime(32)
    n = p * q
    t0 = time.time()
    f = pollard_rho_brent(n)
    assert f in (p, q), f"rho failed: {f}"
    print(f"[+] rho split a {n.bit_length()}-bit semiprime in {time.time()-t0:.2f}s")

    # --- rho on a 48-bit factor inside a 200-bit modulus -------------------- #
    p = getPrime(24)
    q = getPrime(180)
    n = p * q
    f = pollard_rho_brent(n, max_iter=1 << 20)
    assert f in (p, q)
    print("[+] rho found a small factor in a big modulus")

    # --- ECM on a 32-bit factor hidden in a 232-bit modulus ----------------- #
    p = getPrime(32)
    q = getPrime(200)
    n = p * q
    t0 = time.time()
    f = ecm(n, B1=2000, curves=30)
    assert f in (p, q), f"ecm failed: {f}"
    print(f"[+] ecm found a {p.bit_length()}-bit factor in {time.time()-t0:.2f}s")

    # --- multi-prime full factorisation ------------------------------------ #
    ps = sorted(getPrime(28) for _ in range(4))
    n = 1
    for x in ps:
        n *= x
    got = factor(n, verbose=False)
    assert got == ps, f"{got} != {ps}"
    print(f"[+] factored a {n.bit_length()}-bit 4-prime modulus completely")

    # --- perfect power ------------------------------------------------------ #
    p = getPrime(40)
    assert perfect_power(p ** 3) == (p, 3)
    assert perfect_power(p * (p + 2)) is None
    print("[+] perfect-power detection ok")

    # --- trial division ----------------------------------------------------- #
    facs, rest = trial_division(2 * 2 * 3 * 5 * 7 * 101 * getPrime(64))
    assert facs[:6] == [2, 2, 3, 5, 7, 101]
    print("[+] trial division ok")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        N = int(sys.argv[1], 0)
        print(factor(N))
    else:
        _selftest()
```

## Variants & pitfalls

- **Rho on a prime never terminates** - always primality-test first.
- **`g == n` in rho** means both factors collided at once: backtrack step by step
  (the code does) or restart with a new `c`.
- **Rho scaling**: `sqrt(p)` steps. A 64-bit factor is ~2^32 iterations, i.e. hours in pure
  Python, seconds in `gmpy2`/C. Do not run rho on a 512-bit prime.
- **ECM is probabilistic per curve.** One failed curve means nothing. The standard ladder
  (B1, #curves) pairs are: 2e3/25, 11e3/90, 5e4/300, 25e4/700, 1e6/1800, 3e6/5100.
- **ECM in pure Python is 100-1000x slower than `gmp-ecm`.** Use the real thing for
  anything above ~40 bits.
- **Perfect powers**: `n = p^2` or `p^3` appears surprisingly often in CTFs; rho handles it
  badly, so test explicitly.
- **Do not brute-force a balanced 1024-bit modulus.** If the intended solution needed
  factoring, the modulus would be small. Re-read the handout for the real bug.
- **factordb first, always.** Many CTF moduli are already in it (sometimes uploaded by
  another team mid-CTF).

## Tools

```bash
# fastest general purpose: yafu picks the right algorithm itself
echo 'factor(<N>)' | yafu -threads 8

# ECM with the standard escalating ladder
echo <N> | ecm -c 25   2e3
echo <N> | ecm -c 90   11e3
echo <N> | ecm -c 300  5e4
echo <N> | ecm -c 700  25e4
echo <N> | ecm -c 1800 1e6

# SIQS for balanced moduli up to ~110 digits
msieve -v -q <N>

# GNFS for 110+ digits (hours to days)
cado-nfs.py <N>

# python quick shots
python3 -c 'from sympy import factorint;print(factorint(<N>))'
python3 -c 'import gmpy2;print(gmpy2.is_prime(<N>))'

# factordb lookup
curl -s "http://factordb.com/api?query=<N>" | python3 -m json.tool
```

## References

- Wikipedia rho: https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm
- Wikipedia ECM: https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization
- R. Brent, "An improved Monte Carlo factorization algorithm" (BIT, 1980)
- GMP-ECM: https://gitlab.inria.fr/zimmerma/ecm
- cado-nfs: https://gitlab.inria.fr/cado-nfs/cado-nfs
- msieve: https://sourceforge.net/projects/msieve/
- yafu: https://github.com/bbuhrow/yafu
- factordb: http://factordb.com/
