---
title: "RSA - Partial Key Exposure (known bits of p, q or d)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, partial-key-exposure, known-high-bits, known-low-bits, msb, lsb, partial-p, partial-q, partial-d, coppersmith, lattice, lll, boneh-durfee-frankel, factoring-with-hints, memory-dump, truncated-key, brute-force-bridge, sage, fpylll]
difficulty: hard
summary: "Half the bits of p factor n via Coppersmith; a quarter of the low bits of d do the same when e is small."
when_to_use:
  - "A memory dump, log, or corrupted PEM leaks part of a prime"
  - "The challenge prints p with the low bits masked (p >> 200 << 200) or the high bits gone"
  - "You know d mod 2^k for k >= n_bits/4 and e is small"
  - "A side channel gave you the top bits of p"
  - "You have slightly fewer bits than Coppersmith needs -> brute force the gap"
tools: [sage, sagemath, fpylll, python3, rsactftool]
source:
  name: "Wikipedia - Coppersmith's attack"
  url: "https://en.wikipedia.org/wiki/Coppersmith%27s_attack"
related: [rsa-coppersmith, rsa-boneh-durfee, rsa-known-phi-known-d, rsa-weak-keygen-roca-e-gcd-phi]
---

## TL;DR

| You know | Condition | Method |
|---|---|---|
| high bits of `p` | `unknown < n^0.25` | Coppersmith on `f(x) = p_high + x` |
| low bits of `p` | `unknown < n^0.25` | Coppersmith on `f(x) = x*2^k + p_low` (monic-ised) |
| low bits of `d` | `k >= n_bits/4`, small `e` | solve `e*d = 1 + k*phi` mod `2^k`, then Coppersmith |
| high bits of `d` | `e` small | `d ~ (1 + k*phi)/e` over `k < e` - enumerate `k` |
| `dp` (CRT) | full | `gcd(2^(e*dp) - 2, n)` |
| a few bits missing | anything | brute force the gap and re-run |

Half of `p` breaks RSA. That is the headline.

## Recognise it

- The handout shows a prime with `...` or zeros: `p = 0xdeadbeef00000000...`.
- A `heapdump`, `core`, or `swap` file contains a partial key.
- `openssl rsa -text` output is truncated mid-prime.
- The challenge explicitly prints `p >> 256` or `p % 2**256` or `bin(d)[-300:]`.
- Source: `print("hint:", p >> 200)`.

## Theory

**Known high bits of p.** Write $p = \tilde p + x_0$ with $\tilde p$ known and
$|x_0| < X$. Then $f(x) = \tilde p + x$ has the root $x_0$ modulo the *unknown divisor* $p$
of $N$, with $p \ge N^{0.5}$. Coppersmith's beta-version finds $x_0$ whenever
$X < N^{\beta^2/\deg f} = N^{0.25}$. So knowing the top half of a 512-bit prime in a
1024-bit modulus is enough.

**Known low bits of p.** $p = 2^k x_0 + p_{\text{low}}$. Multiply by $(2^k)^{-1} \bmod N$
to make the polynomial monic: $f(x) = x + p_{\text{low}} \cdot 2^{-k}$, same bound.

**Known low bits of d (Boneh-Durfee-Frankel).** From $ed = 1 + k\varphi(n)$ with
$1 \le k \le e$:

$$e\,d_{\text{low}} \equiv 1 + k(N - s + 1) \pmod{2^{k_{\text{bits}}}}, \quad s = p + q$$

For each candidate $k$ (there are fewer than $e$), solve for $s \bmod 2^{k_{\text{bits}}}$,
which gives $p \bmod 2^{k_{\text{bits}}}$ up to a quadratic; feed that into the
known-low-bits Coppersmith. Requires $k_{\text{bits}} \ge \frac{1}{4}\log_2 N$ and a small
$e$ (the work is $O(e)$ lattice reductions).

**Bridging a gap.** If you are `g` bits short of the Coppersmith bound, enumerate the
`2^g` possibilities for the missing bits and run the lattice each time. `g <= 12` is
comfortable; beyond that, find more bits.

## Attack

1. Normalise what you know into `p_high << unknown_bits` or `p_low` with a bit count.
2. Check the bound: `unknown_bits < n.bit_length() // 4`.
3. Run Coppersmith (`small_roots` with `beta = 0.5`).
4. `gcd(candidate, n)` must be a non-trivial factor.
5. If it is 1, raise `m`/`t`, or brute-force the few bits you are missing.

## Code

```python
#!/usr/bin/env python3
"""Partial key exposure: recover p from its high or low bits, and d from its low bits.

Self-contained (integer LLL + Coppersmith). Sizes in the self-test are small so it
finishes in seconds; for 1024/2048-bit moduli use Sage or fpylll (see the notes).

    python3 rsa_partial_key.py       # self-test
"""
from __future__ import annotations

import random
from math import gcd, isqrt

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:
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
            c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if _is_prime(c):
                return c


# ----------------------- exact integer LLL (Cohen 2.6.7) -------------------- #
def lll(basis: list[list[int]]) -> list[list[int]]:
    try:
        from fpylll import IntegerMatrix, LLL as FPLLL
        A = IntegerMatrix.from_matrix([[int(v) for v in row] for row in basis])
        FPLLL.reduction(A)
        return [[A[i, j] for j in range(A.ncols)] for i in range(A.nrows)]
    except ImportError:
        pass
    b = [None] + [list(map(int, r)) for r in basis]
    n = len(basis)
    d = [0] * (n + 2)
    d[0] = 1
    lam = [[0] * (n + 1) for _ in range(n + 1)]

    def dot(u, v):
        return sum(x * y for x, y in zip(u, v))

    def red(k, l):
        if abs(2 * lam[k][l]) > d[l]:
            q = (2 * lam[k][l] + d[l]) // (2 * d[l])
            b[k] = [b[k][i] - q * b[l][i] for i in range(len(b[k]))]
            lam[k][l] -= q * d[l]
            for i in range(1, l):
                lam[k][i] -= q * lam[l][i]

    def swap(k, kmax):
        b[k], b[k - 1] = b[k - 1], b[k]
        if k > 2:
            for j in range(1, k - 1):
                lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
        l = lam[k][k - 1]
        B = (d[k - 2] * d[k] + l * l) // d[k - 1]
        for i in range(k + 1, kmax + 1):
            t = lam[i][k]
            lam[i][k] = (d[k] * lam[i][k - 1] - l * t) // d[k - 1]
            lam[i][k - 1] = (B * t + l * lam[i][k]) // d[k]
        d[k - 1] = B

    d[1] = dot(b[1], b[1])
    k, kmax = 2, 1
    while k <= n:
        if k > kmax:
            kmax = k
            for j in range(1, k + 1):
                u = dot(b[k], b[j])
                for i in range(1, j):
                    u = (d[i] * u - lam[k][i] * lam[j][i]) // d[i - 1]
                if j < k:
                    lam[k][j] = u
                else:
                    d[k] = u
                    if d[k] == 0:
                        raise ValueError("dependent basis")
        while True:
            red(k, k - 1)
            if 4 * d[k] * d[k - 2] < 3 * d[k - 1] * d[k - 1] - 4 * lam[k][k - 1] ** 2:
                swap(k, kmax)
                k = max(2, k - 1)
            else:
                for l in range(k - 2, 0, -1):
                    red(k, l)
                k += 1
                break
    return [b[i] for i in range(1, n + 1)]


def pmul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] += x * y
    return out


def peval(p: list[int], x: int) -> int:
    v = 0
    for c in reversed(p):
        v = v * x + c
    return v


def int_roots(p: list[int], X: int) -> list[int]:
    p = p[:]
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    if len(p) <= 1:
        return []
    dp = [i * c for i, c in enumerate(p)][1:]
    found = set()
    for s in (0, 1, -1, X, -X, X // 2, -X // 2, isqrt(X) if X > 0 else 0):
        x = s
        for _ in range(400):
            fx = peval(p, x)
            if fx == 0:
                break
            d1 = peval(dp, x)
            if d1 == 0:
                break
            nx = x - fx // d1
            if nx == x:
                break
            x = nx
        for cand in range(x - 3, x + 4):
            if abs(cand) <= X and peval(p, cand) == 0:
                found.add(cand)
    return sorted(found)


def small_roots(f: list[int], N: int, X: int, m: int = 3, t: int = 3) -> list[int]:
    d = len(f) - 1
    fp = [[1]]
    for _ in range(m):
        fp.append(pmul(fp[-1], f))          # integer powers - do NOT reduce mod N
    shifts = []
    for i in range(m):
        for j in range(d):
            shifts.append([0] * j + [c * N ** (m - i) for c in fp[i]])
    for i in range(t + 1):
        shifts.append([0] * i + list(fp[m]))
    dim = max(len(s) for s in shifts)
    B = [[(s[k] * X ** k if k < len(s) else 0) for k in range(dim)] for s in shifts]
    out = []
    for row in lll(B):
        pol = [row[k] // X ** k for k in range(dim)]
        for r in int_roots(pol, X):
            if r not in out:
                out.append(r)
        if out:
            break
    return out


# --------------------------------------------------------------------------- #
def factor_known_high_bits(N: int, p_high: int, unknown_bits: int,
                           m: int = 3, t: int = 3, brute: int = 0):
    """p = p_high + x, 0 <= x < 2^unknown_bits. `brute` extra bits are enumerated."""
    for extra in range(1 << brute):
        base = p_high + (extra << unknown_bits)
        for r in small_roots([base % N, 1], N, 1 << unknown_bits, m, t):
            g = gcd(base + r, N)
            if 1 < g < N:
                return g, N // g
    return None


def factor_known_low_bits(N: int, p_low: int, known_bits: int, unknown_bits: int,
                          m: int = 3, t: int = 3):
    """p = x * 2^known_bits + p_low."""
    inv = pow(pow(2, known_bits, N), -1, N)
    f = [(p_low * inv) % N, 1]
    for r in small_roots(f, N, 1 << unknown_bits, m, t):
        cand = (r << known_bits) + p_low
        g = gcd(cand, N)
        if 1 < g < N:
            return g, N // g
    return None


def factor_known_low_bits_of_d(N: int, e: int, d_low: int, k_bits: int,
                               m: int = 3, t: int = 3):
    """Boneh-Durfee-Frankel: d mod 2^k_bits known, e small.

    e*d = 1 + k*(N - s + 1) with 1 <= k < e and s = p+q.
    Modulo 2^k_bits this gives s, hence p mod 2^k_bits via a quadratic;
    Coppersmith finishes the job.
    """
    B0 = None
    for k in range(1, e):
        # e*d_low - 1 = k*(N + 1 - s)  (mod 2^k_bits), with s = p + q.
        # k may be even, so divide the 2-adic valuation out of both sides.
        v = (k & -k).bit_length() - 1              # v2(k)
        if (e * d_low - 1) % (1 << v):
            continue
        bits = k_bits - v
        mod = 1 << bits
        kk = k >> v
        B0 = (e * d_low - 1) >> v
        s = (N + 1 - B0 * pow(kk, -1, mod)) % mod
        # solve p^2 - s*p + N = 0 (mod 2^bits) by lifting bit by bit
        roots = [1]                                 # p is odd
        for bit in range(1, bits):
            mo = 1 << (bit + 1)
            roots = list(dict.fromkeys(
                r + add for r in roots for add in (0, 1 << bit)
                if (( r + add) ** 2 - s * (r + add) + N) % mo == 0))
            if not roots:
                break
        unknown_bits = (N.bit_length() // 2) - bits + 1
        for p_low in roots:
            res = factor_known_low_bits(N, p_low, bits, unknown_bits, m, t)
            if res:
                return res
    return None


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import time
    random.seed(4711)

    # --- known high bits of p ---------------------------------------------- #
    p, q = getPrime(256), getPrime(256)
    N = p * q
    unknown = 64                       # bound is 512/4 = 128 bits
    p_high = (p >> unknown) << unknown
    t0 = time.time()
    res = factor_known_high_bits(N, p_high, unknown, m=3, t=3)
    assert res is not None and set(res) == {p, q}
    print(f"[+] top {256-unknown} bits of p -> factored in {time.time()-t0:.2f}s")

    # --- known low bits of p ------------------------------------------------ #
    known_bits = 256 - 64
    p_low = p % (1 << known_bits)
    t0 = time.time()
    res = factor_known_low_bits(N, p_low, known_bits, 64, m=3, t=3)
    assert res is not None and set(res) == {p, q}
    print(f"[+] low {known_bits} bits of p -> factored in {time.time()-t0:.2f}s")

    # --- bridging a gap by brute force -------------------------------------- #
    # pretend we know 3 bits FEWER than the lattice needs and enumerate them
    unknown, extra_bits = 64, 3
    p_high = (p >> (unknown + extra_bits)) << (unknown + extra_bits)
    t0 = time.time()
    res = factor_known_high_bits(N, p_high, unknown, m=3, t=3, brute=extra_bits)
    assert res is not None and set(res) == {p, q}
    print(f"[+] brute-forced {extra_bits} missing bits + Coppersmith in "
          f"{time.time()-t0:.2f}s")

    # --- known low bits of d ------------------------------------------------ #
    p, q = getPrime(128), getPrime(128)
    N = p * q
    e = 3
    while True:
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break
        p, q = getPrime(128), getPrime(128)
        N = p * q
    d = pow(e, -1, phi)
    k_bits = 96                        # >= N.bit_length()/4 = 64
    d_low = d % (1 << k_bits)
    t0 = time.time()
    res = factor_known_low_bits_of_d(N, e, d_low, k_bits, m=3, t=3)
    assert res is not None and set(res) == {p, q}, f"d-exposure failed: {res}"
    print(f"[+] low {k_bits} bits of d (e = 3) -> factored in {time.time()-t0:.2f}s")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    _selftest()
```

## Variants & pitfalls

- **Count the bits carefully.** "I know the top half of p" means `unknown_bits =
  p.bit_length() // 2`, and the bound is `N.bit_length() // 4` - for balanced primes those
  are the same number, with zero margin. Always keep a few bits of slack.
- **The known part must be aligned.** `p_high` has to be shifted into place
  (`(p >> u) << u`), not the raw truncated integer.
- **Low bits of `p` need the monic fix** (`* inverse(2^k, N)`), otherwise the lattice is
  built for the wrong polynomial.
- **`e` large kills the d-exposure attack**: the loop is `O(e)` lattice reductions. For
  `e = 65537` you need 65536 of them; parallelise or find another leak.
- **Leaked `d` high bits**: with small `e`, `d` is within `e` candidates of
  `(1 + k*N)/e`; just enumerate `k` and test `pow(pow(2, e, N), d_cand, N) == 2`.
- **Unknown bits in the middle** of `p` -> bivariate Coppersmith (`defund/coppersmith`).
- **Pure-python LLL is slow**: for a 2048-bit modulus with `m = 8` use Sage, fpylll, or
  `flatter`. The maths above is identical.

## Tools

```bash
# Sage, the practical route
sage -c 'R.<x> = Zmod(<N>)[]; f = x + <P_HIGH>; r = f.small_roots(X=2^250, beta=0.5); \
         print([gcd(int(<P_HIGH>+i), <N>) for i in r])'

# RsaCtfTool: partial_q / partial_p style attacks
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack partial_q

# carve key material out of a dump
strings -n 40 core.dump | grep -E '^[0-9a-fA-F]{40,}$'
```

## References

- Boneh, Durfee, Frankel, "An Attack on RSA Given a Small Fraction of the Private Key Bits"
  (ASIACRYPT 1998)
- Coppersmith, "Finding a Small Root of a Bivariate Integer Equation; Factoring with High
  Bits Known" (EUROCRYPT 1996)
- Wikipedia: https://en.wikipedia.org/wiki/Coppersmith%27s_attack
