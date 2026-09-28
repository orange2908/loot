---
title: "DLP - Pohlig-Hellman in Z_p* and Finding Smooth p-1"
category: crypto
subcategory: dlp
type: technique
tags: [dlp, discrete-log, discrete-logarithm, pohlig-hellman, smooth, smooth-order, crt, chinese-remainder-theorem, bsgs, baby-step-giant-step, subgroup, safe-prime, generator, partial-recovery, kangaroo, sage, pari, sympy, python]
difficulty: medium
summary: "If p-1 (or the order of g) factors into small primes, the DLP splits into tiny sub-DLPs and CRT glues them back. Cost sum(e_i*sqrt(q_i))."
when_to_use:
  - "factor(p-1) is a product of small primes"
  - "A challenge generates p by multiplying small primes and adding 1"
  - "The generator has small order, or the order is only partly smooth"
  - "You need x mod something even if you cannot get x completely"
tools: [sage, pari, sympy, python]
related: [dlp-bsgs-pollard-rho, dlp-index-calculus, dlp-diffie-hellman-attacks, ecc-pohlig-hellman, ecc-toolkit]
---

## TL;DR

The multiplicative group `Z_p^*` is cyclic of order `p - 1`. If
`p - 1 = prod q_i^{e_i}` with all `q_i` small, the DLP decomposes by the Chinese remainder
theorem into one DLP per prime power, each solvable in `sqrt(q_i)` steps. A 2048-bit `p`
with smooth `p - 1` is as weak as a 30-bit one.

## Recognise it

- `p = 2 * 3 * 5 * 7 * ... * P + 1` or a `while not isPrime(p): p = product_of_small_primes()`
  loop in the generator code.
- `factor(p-1)` returns nothing above a few million.
- The challenge calls `p` a "prime" but never says "safe prime".
- `g` has small order: `pow(g, small, p) == 1`.
- Diffie-Hellman with a group nobody names (not RFC 3526, not a standard MODP group).

## Theory

Let `g` have order `n` (a divisor of `p - 1`), `h = g^x`, and `n = prod q_i^{e_i}`.

**Project.** For a prime power `q^e || n` put `m = n / q^e`. Then `g^m` has order `q^e` and

$$(h)^m = (g^m)^x \Longrightarrow x \bmod q^e \text{ is a DLP in a group of order } q^e$$

**Digits.** Inside that subgroup write `x = d_0 + d_1 q + ... + d_{e-1} q^{e-1} (mod q^e)`.
Having `x_j = d_0 + ... + d_{j-1} q^{j-1}`,

$$\left(h g^{-x_j}\right)^{n/q^{j+1}} = \left(g^{n/q}\right)^{d_j}$$

both sides in the order-`q` subgroup, so `d_j` costs one BSGS of `sqrt(q)` steps.

**Recombine.** CRT the residues `x mod q_i^{e_i}`. Done.

**Cost.** `sum_i e_i (sqrt(q_i) + log n)`. The *largest* prime factor of `n` dictates
everything; a single 128-bit factor makes the whole thing hopeless.

**Partial Pohlig-Hellman.** Write `n = S * L` with `S` the smooth part. You always get
`x mod S` cheaply. Then:

- if `x < S`, you are done;
- if `L` is small enough, finish with BSGS/rho over `n/S` candidates;
- if `x` is known to lie in a narrow interval, kangaroo the residual;
- if the secret is a flag of `k` bytes and `S > 2^{8k}`, you are done regardless of `L`.

**Finding smooth `p - 1`.** It is also how you *build* such a challenge: multiply primes from
a list until the product has the right size, add 1, test primality. Recognising the shape in
reverse is the whole skill.

## Attack

1. Compute `n = ord(g)` (divide `p - 1` down until `g^n = 1` minimally).
2. Factor `n`. Trial division plus Pollard rho is enough for CTF sizes.
3. Solve each prime-power DLP digit by digit.
4. CRT, then verify `g^x == h mod p`.
5. If a large factor blocked you, decide between brute force, kangaroo and giving up.

## Code

```python
#!/usr/bin/env python3
"""Pohlig-Hellman in Z_p^*, with order detection, factoring and partial recovery."""
import random
from math import gcd, isqrt

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
    """{prime: exponent}; trial division then Pollard rho."""
    out, q = {}, 2
    while q < 1000000 and q * q <= n:
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

def element_order(g, p, group_order=None):
    """Exact multiplicative order of g modulo p."""
    n = group_order if group_order is not None else p - 1
    for q, e in factorize(n).items():
        for _ in range(e):
            if pow(g, n // q, p) == 1:
                n //= q
            else:
                break
    return n

def bsgs(g, h, n, p):
    m = isqrt(n - 1) + 1
    table, cur = {}, 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    factor, cur = pow(g, -m, p), h % p
    for i in range(m + 1):
        if cur in table:
            x = i * m + table[cur]
            if x < n and pow(g, x, p) == h % p:
                return x
        cur = cur * factor % p
    return None

def pohlig_hellman(g, h, p, n=None, max_prime=1 << 44):
    """Return (x mod M, M). M is the product of the prime powers actually used."""
    n = n if n is not None else element_order(g, p)
    rs, ms = [], []
    for q, e in factorize(n).items():
        if q > max_prime:
            continue
        x, qk, gen = 0, 1, pow(g, n // q, p)
        for i in range(e):
            hi = pow(h * pow(g, -x, p) % p, n // q ** (i + 1), p)
            d = bsgs(gen, hi, q, p)
            if d is None:
                raise ValueError(f"no log in the order-{q} subgroup")
            x, qk = x + d * qk, qk * q
        rs.append(x % q ** e)
        ms.append(q ** e)
    if not ms:
        raise ValueError("nothing smooth enough to use")
    M = 1
    for m in ms:
        M *= m
    return crt(rs, ms) % M, M

def smooth_prime(bits, bound=1000, rng=random):
    """Build p with p-1 bound-smooth: the shape a vulnerable challenge generates."""
    primes = [q for q in range(2, bound) if is_prime(q)]
    while True:
        m = 2
        while m.bit_length() < bits:
            m *= rng.choice(primes)
        if is_prime(m + 1):
            return m + 1

if __name__ == "__main__":
    rng = random.Random(31)

    # --- 1. fully smooth p-1: a 256-bit modulus that falls in a second ---
    p = smooth_prime(256, 2000, rng)
    facs = factorize(p - 1)
    print(f"[ok] p is {p.bit_length()} bits, p-1 is {max(facs)}-smooth")
    print(f"    p-1 = {facs}")

    g = 2
    while element_order(g, p) != p - 1:
        g += 1
    x = rng.randrange(2, p - 1)
    h = pow(g, x, p)
    rec, M = pohlig_hellman(g, h, p)
    assert M == p - 1 and rec == x
    print(f"[ok] recovered a 256-bit discrete log exactly: x = {hex(x)[:20]}...")

    # --- 2. generator of small order: x is only determined modulo ord(g) ---
    small_ord = max(q for q in facs if q < 10**6)
    g2 = pow(g, (p - 1) // small_ord, p)
    assert element_order(g2, p) == small_ord
    x2 = rng.randrange(2, p - 1)
    h2 = pow(g2, x2, p)
    rec2, M2 = pohlig_hellman(g2, h2, p)
    assert M2 == small_ord and rec2 == x2 % small_ord
    print(f"[ok] small-order generator leaks only x mod {small_ord}")

    # --- 3. partly smooth: pretend one prime factor is out of reach ---
    biggest = max(facs)
    rec3, M3 = pohlig_hellman(g, h, p, max_prime=biggest - 1)
    assert M3 < p - 1 and x % M3 == rec3
    print(f"[ok] partial run: x known mod {M3.bit_length()} bits (skipped {biggest})")

    # finish the residual with a short search, as you would in a real challenge
    span = (p - 1) // M3
    step = pow(g, M3, p)
    cur = pow(g, rec3, p)
    for t in range(span + 1):
        if cur == h:
            assert rec3 + t * M3 == x
            print(f"[ok] finished by walking {t} steps of size 2^{M3.bit_length()}")
            break
        cur = cur * step % p
    else:
        raise AssertionError("residual search failed")

    # --- 4. a short secret needs only the smooth part ---
    flag_int = int.from_bytes(b"ctf{sm00th}", "big")
    h4 = pow(g, flag_int, p)
    rec4, M4 = pohlig_hellman(g, h4, p, max_prime=biggest - 1)
    assert M4 > flag_int and rec4 == flag_int
    print(f"[ok] an {flag_int.bit_length()}-bit secret is fully determined by the smooth part")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Order of `g`, not `p - 1`.** If `g` is not a primitive root, `x` is only defined modulo
  `ord(g)`. Reporting `x mod (p-1)` then fails verification.
- **`q^e` with `e > 1`.** The digit loop is required; a single BSGS over `q^e` costs
  `q^{e/2}`. For `2^{50} || p-1` that is the difference between instant and impossible.
- **`q = 2`.** The order-2 subgroup is `{1, -1}`; BSGS still works but many hand-rolled
  implementations mis-handle it. Test with a toy case.
- **Composite `p`.** In `Z_n^*` with `n` composite, factor `n` first and CRT per prime power;
  the group is not cyclic in general, so `discrete_log` may need the full structure.
- **Sub-group confinement in DH.** Pohlig-Hellman is the engine behind the small-subgroup
  attacks in `dlp-diffie-hellman-attacks`: you *force* the shared secret into a small
  subgroup, then read off `x mod q`.
- **Smooth `p + 1` instead.** Some challenges use the order-`(p+1)` subgroup of `GF(p^2)^*`
  (Lucas sequences, "LUC" cryptosystem, singular curves with a non-split node). Same idea,
  different group.
- **The factorisation is the bottleneck.** If `p - 1` has a 90-bit factor, Pollard rho will
  not find it. Use ECM (`sage: ecm.factor`) or accept the partial result.

## Tools

```python
# SageMath
p = ...; g = ...; h = ...
F = GF(p)
print(factor(p - 1))
print(F(g).multiplicative_order())
print(discrete_log(F(h), F(g)))                 # Pohlig-Hellman automatically
print(discrete_log(F(h), F(g), ord=F(g).multiplicative_order()))
```

```sh
# PARI/GP: factor p-1 and take the log
gp -q -c 'p=...; print(factor(p-1)); print(znlog(Mod(h,p), Mod(g,p)))'
```

```python
# sympy (optional dependency) if you prefer it to a hand-rolled factoriser
from sympy import factorint, discrete_log
print(factorint(p - 1))
print(discrete_log(p, h, g))
```

## References

- Pohlig, Hellman, "An improved algorithm for computing logarithms over GF(p)", IEEE Trans. Inf. Theory 24 (1978)
- https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
- https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html
