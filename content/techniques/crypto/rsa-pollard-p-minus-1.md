---
title: "RSA - Pollard p-1 and Williams p+1 (smooth prime factors)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, pollard-p-1, p-minus-1, williams-p-plus-1, p-plus-1, smooth, smooth-primes, b-smooth, powersmooth, lucas-sequence, gcd, factoring, stage-2, fermat-little-theorem, safe-primes, gmp-ecm, yafu, factordb]
difficulty: medium
summary: "If p-1 (or p+1) has only small prime factors, a^(B!) - 1 shares p with n, so one gcd factors the modulus."
when_to_use:
  - "Key generation builds a prime as p = 2*3*5*...*k + 1 or from a list of small primes"
  - "The challenge mentions 'smooth', 'B-smooth', 'powersmooth', 'safe primes are boring'"
  - "n resists Fermat and factordb but the primes look structured"
  - "p-1 smooth fails -> try p+1 (Williams) before reaching for ECM"
  - "Any 'we generated our own primes' custom keygen"
tools: [python3, gmpy2, sympy, yafu, gmp-ecm, factordb]
source:
  name: "Wikipedia - Pollard's p-1 algorithm"
  url: "https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm"
related: [rsa-pollard-rho-ecm, rsa-fermat-close-primes, rsa-weak-keygen-roca-e-gcd-phi]
---

## TL;DR

Fermat: `a^(p-1) = 1 mod p`. If `p-1` divides `M = lcm(1..B1)`, then `a^M = 1 mod p`, so
`p | gcd(a^M - 1, n)` - one gcd factors `n`. Williams p+1 is the same idea with Lucas
sequences and the group of order `p+1`. Both are *targeted*: they only work when the prime
has a smooth neighbour, which is exactly what naive "build a prime from small primes"
keygens produce.

## Recognise it

- Keygen source: `p = 2; while p.bit_length() < 512: p *= choice(small_primes); p += 1`.
- The challenge story: "we made our own primes so nobody can factor them".
- `n` is big, Fermat fails, factordb does not know it, rho is hopeless - but a 30 second
  p-1 run with `B1 = 10^6` succeeds.
- Modern library keygen uses *safe* primes (`p = 2q+1`), which are immune; only hand-rolled
  generators are vulnerable.

## Theory

**Pollard p-1.** Let $M = \prod_{q \le B_1} q^{\lfloor \log_q B_1 \rfloor}$
(the "powersmooth" exponent). If every prime power dividing $p-1$ is $\le B_1$, then
$(p-1) \mid M$ and by Fermat

$$a^{M} \equiv 1 \pmod p \quad\Longrightarrow\quad p \mid \gcd(a^{M} - 1,\, n)$$

Compute $a^M \bmod n$ by repeated `pow`, then one gcd. If the gcd is `n`, both primes were
smooth - back off `B1` or change `a`.

**Stage 2.** Usually $p-1 = (\text{smooth part}) \times q$ with one larger prime
$q \in (B_1, B_2]$. After stage 1 you have $x = a^M$; for each prime $q$ in the interval
test $\gcd(x^{q} - 1, n)$. Using the differences $x^{q_{i+1}} = x^{q_i} \cdot x^{q_{i+1}-q_i}$
makes this nearly free, and accumulating the product before a single gcd makes it faster still.

**Williams p+1.** Work in the group of order $p+1$ using the Lucas sequence
$V_k(A, 1)$ with $V_0 = 2, V_1 = A$ and the identities

$$V_{2k} = V_k^2 - 2, \qquad V_{2k+1} = V_k V_{k+1} - A$$

If $(p+1) \mid M$ and $A^2 - 4$ is a quadratic **non-residue** mod $p$, then
$V_M(A) \equiv 2 \pmod p$, so $p \mid \gcd(V_M - 2, n)$. Since you cannot test the residue
condition without knowing `p`, just try several `A` values (each has ~50% chance).

## Attack

1. Try `p-1` with `B1 = 10^4`, then `10^5`, `10^6`, `10^7` - each run reuses nothing, so
   just restart with a bigger bound.
2. Add stage 2 with `B2 = 100 * B1`.
3. If that fails, run Williams `p+1` with several base values `A = 3, 5, 7, ...`.
4. If both fail, the primes are not smooth on either side: go to ECM (`rsa-pollard-rho-ecm`).
5. gcd == n means you went too far: reduce `B1` or restart with a different base.

## Code

```python
#!/usr/bin/env python3
"""Pollard p-1 (stage 1 + stage 2) and Williams p+1.

    python3 rsa_pminus1.py           # self-test
    python3 rsa_pminus1.py N [B1]    # attack a real modulus
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


def primes_upto(n: int) -> list[int]:
    """Simple sieve of Eratosthenes."""
    if n < 2:
        return []
    sieve = bytearray([1]) * (n + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, isqrt(n) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, n + 1, i)))
    return [i for i in range(n + 1) if sieve[i]]


# --------------------------------------------------------------------------- #
# Pollard p-1
# --------------------------------------------------------------------------- #
def pollard_p_minus_1(n: int, B1: int = 100000, B2: int = 0, a: int = 2,
                      verbose: bool = False):
    """Return a non-trivial factor of n, or None.

    B2 > B1 enables the (simple) stage-2 continuation.
    """
    if n % 2 == 0:
        return 2
    ps = primes_upto(B1)
    x = a % n
    # ---- stage 1: x = a ^ lcm(1..B1) ------------------------------------- #
    for q in ps:
        e = q
        while e * q <= B1:
            e *= q
        x = pow(x, e, n)
        if x == 1:                       # unlucky base, everything collapsed
            return None
    g = gcd(x - 1, n)
    if 1 < g < n:
        if verbose:
            print(f"[+] stage 1 hit with B1 = {B1}")
        return g
    if g == n:
        if verbose:
            print("[!] gcd == n: both primes are smooth, lower B1 or change the base")
        return None

    # ---- stage 2: one extra prime q in (B1, B2] --------------------------- #
    if B2 > B1:
        ps2 = [q for q in primes_upto(B2) if q > B1]
        if not ps2:
            return None
        # walk the primes by their gaps so each step is one small power
        cache: dict[int, int] = {}
        prev = ps2[0]
        y = pow(x, prev, n)
        acc = (y - 1) % n
        for q in ps2[1:]:
            d = q - prev
            if d not in cache:
                cache[d] = pow(x, d, n)
            y = y * cache[d] % n
            acc = acc * ((y - 1) % n) % n
            prev = q
            if acc == 0:                  # would make the gcd useless
                break
        g = gcd(acc, n)
        if 1 < g < n:
            if verbose:
                print(f"[+] stage 2 hit with B2 = {B2}")
            return g
    return None


def pollard_p_minus_1_escalating(n: int, bounds=(1000, 10000, 100000, 1000000),
                                 verbose: bool = True):
    for B1 in bounds:
        for a in (2, 3, 5, 7):
            f = pollard_p_minus_1(n, B1, B1 * 100, a, verbose=False)
            if f:
                if verbose:
                    print(f"[+] factor found with B1 = {B1}, a = {a}")
                return f
    return None


# --------------------------------------------------------------------------- #
# Williams p+1
# --------------------------------------------------------------------------- #
def lucas_v(k: int, A: int, n: int) -> int:
    """V_k(A, 1) mod n via the binary Lucas ladder."""
    v0, v1 = 2 % n, A % n
    for bit in bin(k)[2:]:
        if bit == "0":
            v1 = (v0 * v1 - A) % n
            v0 = (v0 * v0 - 2) % n
        else:
            v0 = (v0 * v1 - A) % n
            v1 = (v1 * v1 - 2) % n
    return v0


def williams_p_plus_1(n: int, B1: int = 100000, bases=(3, 5, 7, 9, 11, 13),
                      verbose: bool = False):
    """Return a non-trivial factor of n when p+1 is B1-powersmooth, else None."""
    ps = primes_upto(B1)
    for A in bases:
        v = A % n
        for q in ps:
            e = q
            while e * q <= B1:
                e *= q
            v = lucas_v(e, v, n)
            g = gcd(v - 2, n)
            if 1 < g < n:
                if verbose:
                    print(f"[+] williams p+1 hit with A = {A}, prime {q}")
                return g
            if g == n:
                break                     # this base collapsed, try the next one
    return None


def full_break(n: int, e: int, c: int):
    f = pollard_p_minus_1_escalating(n) or williams_p_plus_1(n, 100000)
    if f is None:
        return None
    p, q = f, n // f
    d = pow(e, -1, (p - 1) * (q - 1))
    return p, q, d, long_to_bytes(pow(c, d, n))


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    import time
    random.seed(23)

    def is_prime(x: int) -> bool:
        try:
            from Crypto.Util.number import isPrime
            return bool(isPrime(x))
        except ImportError:
            for pp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                if x % pp == 0:
                    return x == pp
            d, s = x - 1, 0
            while d % 2 == 0:
                d //= 2
                s += 1
            for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                y = pow(a, d, x)
                if y in (1, x - 1):
                    continue
                for _ in range(s - 1):
                    y = y * y % x
                    if y == x - 1:
                        break
                else:
                    return False
            return True

    def smooth_prime(B: int, bits: int, plus: bool) -> int:
        """Prime p with p-1 (plus=False) or p+1 (plus=True) B-smooth and squarefree."""
        pool = primes_upto(B)
        while True:
            sel = random.sample(pool, min(len(pool), 45))
            v = 2
            for q in sel:
                if v.bit_length() >= bits:
                    break
                v *= q
            if v.bit_length() < bits - 10:
                continue
            cand = v - 1 if plus else v + 1
            if is_prime(cand):
                return cand

    # --- Pollard p-1 -------------------------------------------------------- #
    p = smooth_prime(500, 200, plus=False)
    q = getPrime(200)
    n = p * q
    t0 = time.time()
    f = pollard_p_minus_1(n, B1=600, verbose=True)
    assert f in (p, q), f"p-1 failed: {f}"
    print(f"[+] pollard p-1 factored a {n.bit_length()}-bit n in {time.time()-t0:.2f}s")

    # --- stage 2: p-1 = smooth * one bigger prime --------------------------- #
    pool = primes_upto(250)
    big = 7919                                       # one prime well above B1
    while True:
        sel = random.sample(pool, min(len(pool), 45))
        v = 2
        for q in sel:                                # distinct primes only, so every
            if v.bit_length() >= 170:                # prime power stays below B1
                break
            v *= q
        if v.bit_length() < 150:
            continue
        cand = v * big + 1
        if is_prime(cand):
            p2 = cand
            break
    q2 = getPrime(200)
    n2 = p2 * q2
    assert pollard_p_minus_1(n2, B1=300, B2=0) is None, "stage 1 should not suffice"
    f = pollard_p_minus_1(n2, B1=300, B2=20000, verbose=True)
    assert f in (p2, q2), f"stage 2 failed: {f}"
    print("[+] stage 2 continuation ok")

    # --- Williams p+1 ------------------------------------------------------- #
    p3 = smooth_prime(500, 200, plus=True)
    q3 = getPrime(200)
    n3 = p3 * q3
    t0 = time.time()
    f = williams_p_plus_1(n3, B1=600, verbose=True)
    assert f in (p3, q3), f"williams failed: {f}"
    print(f"[+] williams p+1 factored in {time.time()-t0:.2f}s")
    # ...and p-1 should NOT find it (p-1 is not smooth here)
    assert pollard_p_minus_1(n3, B1=600) is None
    print("[+] p-1 correctly fails where only p+1 is smooth")

    # --- end to end --------------------------------------------------------- #
    e = 65537
    flag = b"CTF{smooth_primes_are_not_primes_enough}"
    c = pow(bytes_to_long(flag), e, n)
    out = full_break(n, e, c)
    assert out is not None and out[3] == flag
    print("[+] decrypted:", out[3].decode())

    # --- lucas ladder sanity ------------------------------------------------ #
    pr = getPrime(64)
    a = random.randrange(2, pr)
    ai = pow(a, -1, pr)
    A = (a + ai) % pr
    for k in (1, 2, 3, 10, 12345):
        assert lucas_v(k, A, pr) == (pow(a, k, pr) + pow(ai, k, pr)) % pr
    print("[+] lucas ladder verified against a^k + a^-k")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        N = int(sys.argv[1], 0)
        B1 = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
        print("p-1:", pollard_p_minus_1(N, B1, B1 * 100, verbose=True))
        print("p+1:", williams_p_plus_1(N, B1, verbose=True))
    else:
        _selftest()
```

## Variants & pitfalls

- **gcd == n**: both factors were smooth simultaneously. Lower `B1`, or redo stage 1 while
  taking a gcd after every prime (binary search on the exponent list).
- **`x == 1` after stage 1**: the base collapsed; switch `a` from 2 to 3, 5, 7.
- **Safe primes are immune**: `p = 2q+1` makes `p-1 = 2q` with `q` huge. Real libraries use
  them, CTF keygens rarely do.
- **p+1 needs the right base.** `A^2-4` must be a non-residue mod `p`; you cannot test that,
  so try ~6 bases before concluding "not p+1 smooth".
- **Powersmooth, not smooth.** The exponent must include prime *powers* (`2^k <= B1`),
  otherwise a `p-1` containing `2^10` is missed.
- **Memory**: `primes_upto(10**7)` is fine, `10**9` is not. Use `gmp-ecm`'s `-pm1` for
  serious bounds.
- **Lucas overflow**: reduce mod `n` at every step; the ladder above does.
- If neither works, the right next step is ECM (finds a factor whose *size* is small,
  regardless of smoothness of `p-1`).

## Tools

```bash
# GMP-ECM does p-1, p+1 and ECM with proper stage 2 - the professional choice
echo <N> | ecm -pm1 1e7          # Pollard p-1 with B1 = 10^7
echo <N> | ecm -pp1 1e7          # Williams p+1
echo <N> | ecm -c 1000 11e6      # ECM, 1000 curves

# yafu tries p-1 / p+1 / ECM automatically in a sensible order
echo 'factor(<N>)' | yafu

# sympy quick check (small factors only)
python3 -c 'from sympy import factorint;print(factorint(<N>, limit=10**6))'

# RsaCtfTool
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack pollard_p_1,williams_p_1
```

## References

- J. M. Pollard, "Theorems on factorization and primality testing" (1974)
- H. C. Williams, "A p+1 method of factoring" (Math. Comp. 1982)
- Wikipedia p-1: https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm
- Wikipedia p+1: https://en.wikipedia.org/wiki/Williams%27s_p_%2B_1_algorithm
- GMP-ECM: https://gitlab.inria.fr/zimmerma/ecm
