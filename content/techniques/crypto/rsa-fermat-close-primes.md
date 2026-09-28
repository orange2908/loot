---
title: "RSA - Fermat Factorisation (close primes, p ~ q)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, fermat, fermat-factorization, close-primes, p-close-to-q, next-prime, isqrt, square-difference, difference-of-squares, balanced-primes, generalized-fermat, multiplier, factoring, sympy, yafu, factordb]
difficulty: easy
summary: "p and q generated close together (p = next_prime(q)) -> n = a^2 - b^2 with tiny b, so scanning a upward from isqrt(n) factors n in microseconds."
when_to_use:
  - "Key generation does q = next_prime(p) or p = getPrime(512); q = next_prime(p)"
  - "n is a perfect-square-ish number: isqrt(n)^2 is very close to n"
  - "The challenge hints at 'twin primes', 'close', 'adjacent', 'nextprime', 'sqrt'"
  - "Factoring a 1024/2048-bit modulus is otherwise hopeless but you have nothing else"
  - "p/q is a simple ratio (2/3, 3/5...) -> generalised Fermat with a multiplier"
tools: [python3, sympy, gmpy2, yafu, factordb]
source:
  name: "Wikipedia - Fermat's factorization method"
  url: "https://en.wikipedia.org/wiki/Fermat%27s_factorization_method"
related: [rsa-pollard-rho-ecm, rsa-common-factor-batch-gcd, rsa-weak-keygen-roca-e-gcd-phi]
---

## TL;DR

Every odd `n = p*q` is a difference of squares: `n = a^2 - b^2` with
`a = (p+q)/2`, `b = (p-q)/2`. If `p` and `q` are close, `b` is tiny, so `a` is barely above
`isqrt(n)`. Start at `a = isqrt(n)+1`, increment, and test whether `a^2 - n` is a perfect
square. The number of steps is about `(p-q)^2 / (4 * sqrt(n))` - instant when the primes
differ in only the low ~100 bits.

## Recognise it

- Generator: `p = getPrime(1024); q = nextprime(p)` or `q = p + 2*k` for small `k`.
- `isqrt(n)` squared is within a few bits of `n`.
- Challenge names: "twins", "close enough", "neighbours", "sqrt".
- `RsaCtfTool --attack fermat` finishes instantly (always worth 5 seconds of your life).
- If `p` and `q` are *independent* 1024-bit primes, `b ~ 2^1023` and Fermat is useless -
  the check below tells you within a second.

## Theory

$$n = pq = \left(\frac{p+q}{2}\right)^2 - \left(\frac{p-q}{2}\right)^2 = a^2 - b^2$$

Scan $a = \lceil \sqrt n \rceil, \lceil \sqrt n \rceil + 1, \dots$ and test whether
$a^2 - n$ is a perfect square. The first hit gives
$p = a + b$, $q = a - b$.

Steps needed: $a$ starts at $\sqrt n$ and must reach $\frac{p+q}{2}$, so

$$\#\text{steps} \approx \frac{p+q}{2} - \sqrt{pq} = \frac{(\sqrt p - \sqrt q)^2}{2}
\approx \frac{(p-q)^2}{8 n^{1/2}}$$

For a 2048-bit `n` with `p - q < 2^500`, that is under a million iterations. For
`p - q ~ 2^1024`, forget it.

**Generalised Fermat.** If $p/q \approx u/v$ for small integers $u, v$, then
$uv \cdot n = (uq)(vp)$ has two nearly equal factors, so run Fermat on $k n$ for
$k = uv = 1, 2, 3, 6, \dots$ and divide the results out. This catches
"q = nextprime(3*p/2)" style generators.

## Attack

1. `a = isqrt(n)`; if `a*a == n` then `p = q = a` (a square modulus - `phi = p*(p-1)`).
2. Loop `a += 1`, `b2 = a*a - n`, `b = isqrt(b2)`, stop when `b*b == b2`.
3. `p, q = a+b, a-b`; assert `p*q == n`.
4. If no hit after your step budget, try the multiplier variant with `k = 1..~100`.
5. With `p, q` in hand: `d = pow(e, -1, (p-1)*(q-1))`.

## Code

```python
#!/usr/bin/env python3
"""Fermat factorisation and its generalised (multiplier) variant.

    python3 rsa_fermat.py            # self-test
    python3 rsa_fermat.py N [STEPS]  # factor a real modulus
"""
from __future__ import annotations

import sys
from math import isqrt, gcd

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


def is_square(x: int) -> tuple[bool, int]:
    if x < 0:
        return False, 0
    r = isqrt(x)
    return r * r == x, r


def fermat(n: int, max_steps: int = 1 << 22, verbose: bool = False):
    """Return (p, q) with p >= q, or None if not found within max_steps."""
    if n % 4 == 2:
        # x^2 - y^2 is never 2 mod 4, so such an n has no Fermat representation
        return None
    a = isqrt(n)
    if a * a == n:
        return a, a                       # perfect square modulus
    a += 1
    for step in range(max_steps):
        b2 = a * a - n
        ok, b = is_square(b2)
        if ok:
            p, q = a + b, a - b
            if p * q == n and q != 1:
                if verbose:
                    print(f"[+] fermat hit after {step} steps, |p-q| = {p - q}")
                return p, q
        a += 1
    return None


def fermat_multiplier(n: int, max_k: int = 100, steps_per_k: int = 1 << 16):
    """Generalised Fermat: run Fermat on k*n for small k.

    Catches moduli where p/q is close to a small rational u/v (k = u*v).
    """
    for k in range(1, max_k + 1):
        N = k * n
        if N % 4 == 2:
            # 2 mod 4 has no difference-of-squares form; scale by 4, which keeps
            # the (u*q, v*p) split balanced (e.g. p/q ~ 2/3 needs k = 4*2*3 = 24)
            N *= 4
        res = fermat(N, steps_per_k)
        if res is None:
            continue
        a, b = res
        for cand in (gcd(a, n), gcd(b, n)):
            if 1 < cand < n:
                return cand, n // cand
    return None


def fermat_feasibility(n: int) -> None:
    """Print how far isqrt(n) is from n - a one-second 'should I bother' check."""
    r = isqrt(n)
    gap = n - r * r
    print(f"[i] n is {n.bit_length()} bits; n - isqrt(n)^2 is {gap.bit_length()} bits")
    if gap.bit_length() < n.bit_length() // 2 - 8:
        print("[+] the primes look close: Fermat should work")
    else:
        print("[!] primes look independent: Fermat will not finish")


def full_break(n: int, e: int, c: int):
    res = fermat(n)
    if res is None:
        res = fermat_multiplier(n)
    if res is None:
        return None
    p, q = res
    d = pow(e, -1, (p - 1) * (q - 1))
    return p, q, d, long_to_bytes(pow(c, d, n))


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    import time
    random.seed(17)

    def next_prime(x: int) -> int:
        x |= 1
        while True:
            x += 2
            try:
                from Crypto.Util.number import isPrime
                if isPrime(x):
                    return x
            except ImportError:
                if _pp(x):
                    return x

    def _pp(n: int) -> bool:
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

    # --- q = next_prime(p): the textbook case ------------------------------ #
    p = getPrime(512)
    q = next_prime(p)
    n = p * q
    t0 = time.time()
    res = fermat(n, verbose=True)
    assert res is not None and set(res) == {p, q}
    print(f"[+] next_prime case: factored a {n.bit_length()}-bit n in "
          f"{time.time() - t0:.3f}s")

    # --- primes differing in the low 80 bits -------------------------------- #
    p = getPrime(512)
    q = next_prime(p + (1 << 80))
    n = p * q
    t0 = time.time()
    res = fermat(n, max_steps=1 << 22)
    assert res is not None and set(res) == {p, q}
    print(f"[+] |p-q| ~ 2^80: factored in {time.time() - t0:.2f}s")

    # --- end-to-end decryption --------------------------------------------- #
    e = 65537
    flag = b"CTF{fermat_eats_close_primes}"
    c = pow(bytes_to_long(flag), e, n)
    out = full_break(n, e, c)
    assert out is not None and out[3] == flag
    print("[+] decrypted:", out[3].decode())

    # --- generalised: q ~ 3p/2 ---------------------------------------------- #
    p = getPrime(256)
    q = next_prime(3 * p // 2)
    n = p * q
    t0 = time.time()
    res = fermat_multiplier(n, max_k=12, steps_per_k=1 << 16)
    assert res is not None and set(res) == {p, q}, f"multiplier variant failed: {res}"
    print(f"[+] generalised Fermat (p/q ~ 2/3) ok in {time.time() - t0:.2f}s")

    # --- independent primes must NOT be 'factored' -------------------------- #
    n = getPrime(256) * getPrime(256)
    assert fermat(n, max_steps=5000) is None
    print("[+] independent primes correctly resist Fermat")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        N = int(sys.argv[1], 0)
        STEPS = int(sys.argv[2]) if len(sys.argv) > 2 else (1 << 22)
        fermat_feasibility(N)
        out = fermat(N, STEPS, verbose=True)
        if out is None:
            out = fermat_multiplier(N)
        print("factors:", out)
    else:
        _selftest()
```

## Variants & pitfalls

- **`isqrt`, never `math.sqrt`.** Floats are wrong above 2^53; `math.isqrt` is exact and fast.
- **Step budget.** 2^22 iterations is a few seconds in Python; with `gmpy2.isqrt` you can do
  2^26. If it has not hit by then, the primes are not close.
- **Multi-prime moduli**: Fermat on `n = p*q*r` finds a split into two nearly equal *factors*,
  not necessarily primes. Recurse on each half.
- **Perfect square modulus** (`n = p^2`): handled by the `isqrt(n)**2 == n` branch; then
  `phi = p*(p-1)`, not `(p-1)^2`.
- **Generalised multiplier**: try `k` in `1..1000` for exotic ratios; each `k` is cheap.
- **`p - q` known**: if the challenge leaks `p - q` or `p + q`, solve the quadratic directly
  instead of scanning.
- Fermat is the *first* thing to try on any modulus you cannot otherwise touch, together
  with factordb and a short ECM run.

## Tools

```bash
# sympy has it built in (uses the same idea plus Pollard rho)
python3 -c 'from sympy import factorint;print(factorint(<N>))'

# RsaCtfTool
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack fermat

# yafu tries Fermat automatically before anything expensive
echo 'factor(<N>)' | yafu

# quick feasibility probe
python3 -c 'from math import isqrt;n=<N>;r=isqrt(n);print((n-r*r).bit_length(), n.bit_length())'
```

## References

- Wikipedia: https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
- factordb: http://factordb.com/
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
