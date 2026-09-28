---
title: "RSA - Coppersmith: Stereotyped Message, Short Pad, Known Bits of p"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, coppersmith, small-roots, howgrave-graham, lattice, lll, lattice-reduction, stereotyped-message, known-plaintext-prefix, partial-p, known-high-bits, factoring-with-hints, univariate, beta, sage, sagemath, fpylll, flatter, defund-coppersmith]
difficulty: hard
summary: "LLL finds small roots of a modular polynomial: recovers a stereotyped message (known prefix, few unknown bytes) or factors n from half the bits of p."
when_to_use:
  - "You know most of the plaintext and only a few unknown bytes (flag{...} with 8 random chars)"
  - "You know the top (or bottom) half of p - from a memory dump, a truncated key, a log"
  - "e is small and the message is padded with a fixed, known pattern"
  - "Two ciphertexts of the same message with short unknown pads (short-pad + Franklin-Reiter)"
  - "Any 'small unknown x satisfies f(x) = 0 mod N' where x < N^(1/deg)"
tools: [sage, sagemath, fpylll, flatter, python3, defund-coppersmith, rsactftool]
source:
  name: "Wikipedia - Coppersmith's attack"
  url: "https://en.wikipedia.org/wiki/Coppersmith%27s_attack"
related: [rsa-partial-key-exposure, rsa-franklin-reiter, rsa-hastad-broadcast, rsa-boneh-durfee]
---

## TL;DR

Coppersmith's method finds roots `x0` of a monic polynomial `f(x) = 0 mod N` when
`|x0| < N^(1/deg f)` (or `< N^(beta^2/deg)` if you only need `f(x0) = 0 mod b` for a
divisor `b >= N^beta`). Two CTF staples:

- **Stereotyped message**: `f(x) = (known + x)^e - c`, degree `e`, so up to `log2(N)/e`
  unknown bits are recoverable (~341 bits for `e = 3`, 1024-bit `N`).
- **Known high bits of p**: `f(x) = p_high + x mod N` with `beta = 0.5`, degree 1, so up to
  `log2(N)/4` unknown bits, i.e. **half of p** is enough to factor `N`.

## Recognise it

- The flag format is known and only a handful of characters are random:
  `CTF{` + 8 hex chars + `}`, with `e = 3`.
- The challenge prints `p` with some bits masked: `p & ~0xffffffffffffffff`, `p >> 200 << 200`,
  or "here is the top half of p".
- A hex dump / core dump / partially corrupted PEM gives you part of a prime.
- `e` is small and the padding is deterministic and known.
- The word "stereotyped", "partial", "leak", "truncated" in the challenge text.

## Theory

**Howgrave-Graham.** Let $h(x) = \sum h_i x^i$ with $|x_0| \le X$ and
$\lVert h(xX) \rVert < \frac{N^m}{\sqrt{\dim}}$. If $h(x_0) \equiv 0 \pmod{N^m}$, then
$h(x_0) = 0$ over $\mathbb{Z}$ - a *modular* root becomes an *integer* root, which you can
find with Newton/bisection.

**The lattice.** For monic $f$ of degree $d$ modulo $N$, take the shift polynomials

$$g_{i,j}(x) = N^{m-i}\, x^{j} f(x)^{i}, \quad 0 \le i < m,\ 0 \le j < d
\qquad h_{i}(x) = x^{i} f(x)^{m}, \quad 0 \le i \le t$$

Every one of them vanishes at $x_0$ modulo $N^m$. Write their coefficient vectors scaled by
$X^k$ as the rows of a matrix, LLL-reduce, and the shortest vector is a polynomial short
enough for Howgrave-Graham. Its integer roots include $x_0$.

**beta.** If you only need $f(x_0) \equiv 0 \bmod b$ where $b \mid N$, $b \ge N^{\beta}$,
the same construction works with the condition $\lVert h \rVert < b^m$, giving the bound
$|x_0| < N^{\beta^2/d}$. For a balanced RSA modulus, $\beta = 0.5$ and $d = 1$ give
$N^{0.25}$ - exactly "half the bits of p".

**Critical implementation detail:** the shift polynomials $f^i$ must be expanded *over the
integers*. Reducing their coefficients mod $N$ breaks the $\bmod N^m$ property and the
attack silently fails.

## Attack

1. Express the unknown as a small root: `f(x) = 0 mod N` (or mod `p`).
2. Make `f` monic: multiply by `inverse(leading_coeff, N)`.
3. Pick `m` and `t`. Rule of thumb from Sage: `m = ceil(max(beta^2/(d*eps), 7*beta/d))`,
   `t = floor(d*m*(1/beta - 1))`. In practice: start `m = 3, t = 3` and raise until it works.
4. Build the lattice, LLL-reduce, take row 0 (and a few more rows as backup).
5. Divide out the `X^k` scaling, find integer roots of the resulting polynomial.
6. Verify: `f(x0) % N == 0` (beta = 1) or `1 < gcd(f(x0), N) < N` (beta < 1 -> factor found).

## Code (pure Python, no Sage)

Exact integer LLL (Cohen 2.6.7) + Howgrave-Graham. This really runs - the self-test below
breaks a stereotyped message and factors a modulus from the top bits of `p`. It is slow for
big lattices; for 2048-bit production-size instances use Sage or fpylll (see below).

```python
#!/usr/bin/env python3
"""Coppersmith small_roots in pure Python (exact integer LLL, no Sage).

    python3 coppersmith.py      # self-test: stereotyped message + partial p

fpylll is used automatically if installed (much faster); otherwise the built-in
exact integer LLL is used, which is fine for small/medium lattices.
"""
from __future__ import annotations

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


# --------------------------------------------------------------------------- #
# exact integer LLL  (Cohen, "A Course in Computational Algebraic Number
# Theory", Algorithm 2.6.7).  All divisions below are exact.
# --------------------------------------------------------------------------- #
def lll(basis: list[list[int]]) -> list[list[int]]:
    try:                                  # use fpylll when available
        from fpylll import IntegerMatrix, LLL as FPLLL
        A = IntegerMatrix.from_matrix([[int(v) for v in row] for row in basis])
        FPLLL.reduction(A)
        return [[A[i, j] for j in range(A.ncols)] for i in range(A.nrows)]
    except ImportError:
        pass

    b = [None] + [list(map(int, r)) for r in basis]     # 1-indexed
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
                        raise ValueError("input basis is not linearly independent")
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


# ------------------------------ polynomials -------------------------------- #
def pmul(a: list[int], b: list[int]) -> list[int]:
    """Multiply OVER THE INTEGERS. Never reduce mod N here - it breaks the attack."""
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
    """Integer roots of p in [-X, X] via big-integer Newton from several seeds."""
    p = p[:]
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    if len(p) <= 1:
        return []
    dp = [i * c for i, c in enumerate(p)][1:]
    found = set()
    seeds = [0, 1, -1, X, -X, X // 2, -X // 2, X // 3, -X // 3, isqrt(X) if X > 0 else 0]
    for s in seeds:
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


def small_roots(f: list[int], N: int, X: int, m: int = 3, t: int = 1) -> list[int]:
    """Roots x0 of monic f(x) = 0 mod N (or mod a divisor) with |x0| <= X.

    f is little-endian: [a0, a1, ..., 1]. Raise m/t if nothing is found.
    """
    d = len(f) - 1
    assert f[-1] % N == 1 % N, "f must be monic mod N"
    fp = [[1]]
    for _ in range(m):
        fp.append(pmul(fp[-1], f))                  # integer powers, on purpose
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
# application 1: stereotyped message
# --------------------------------------------------------------------------- #
def stereotyped_message(N: int, e: int, c: int, known: int, shift: int,
                        unknown_bits: int, m: int = 4, t: int = 2) -> int | None:
    """m = known + x * 2^shift with x < 2^unknown_bits. Returns x (not m)."""
    base = [known % N, pow(2, shift, N)]
    f = [1]
    for _ in range(e):
        f = [v % N for v in pmul(f, base)]
    f[0] = (f[0] - c) % N
    inv = pow(f[-1] % N, -1, N)
    f = [(v * inv) % N for v in f]
    roots = small_roots(f, N, 1 << unknown_bits, m, t)
    for r in roots:
        if pow((known + (r << shift)) % N, e, N) == c % N:
            return r
    return roots[0] if roots else None


# --------------------------------------------------------------------------- #
# application 2: factoring with known high bits of p
# --------------------------------------------------------------------------- #
def factor_known_high_bits(N: int, p_high: int, unknown_bits: int,
                           m: int = 3, t: int = 3) -> int | None:
    """p = p_high + x with 0 <= x < 2^unknown_bits (p_high already shifted)."""
    f = [p_high % N, 1]                 # already monic
    for r in small_roots(f, N, 1 << unknown_bits, m, t):
        g = gcd(p_high + r, N)
        if 1 < g < N:
            return g
    return None


def factor_known_low_bits(N: int, p_low: int, known_bits: int,
                          unknown_bits: int, m: int = 3, t: int = 3) -> int | None:
    """p = x * 2^known_bits + p_low. Monic-ise by multiplying with inv(2^known_bits)."""
    inv = pow(pow(2, known_bits, N), -1, N)
    f = [(p_low * inv) % N, 1]
    for r in small_roots(f, N, 1 << unknown_bits, m, t):
        cand = (r << known_bits) + p_low
        g = gcd(cand, N)
        if 1 < g < N:
            return g
    return None


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    import time
    random.seed(2026)

    # --- stereotyped message ----------------------------------------------- #
    p, q = getPrime(256), getPrime(256)
    N = p * q
    e = 3
    secret = random.getrandbits(48)
    msg = b"CTF{" + secret.to_bytes(6, "big") + b"}"
    mm = bytes_to_long(msg)
    c = pow(mm, e, N)
    known = bytes_to_long(b"CTF{" + b"\x00" * 6 + b"}")
    t0 = time.time()
    x = stereotyped_message(N, e, c, known, 8, 50, m=4, t=2)
    assert x == secret, f"stereotyped failed: {x} != {secret}"
    print(f"[+] stereotyped message: recovered 48 unknown bits in {time.time()-t0:.2f}s")
    assert long_to_bytes(known + (x << 8)) == msg

    # --- factoring from the top bits of p ---------------------------------- #
    p, q = getPrime(256), getPrime(256)
    N = p * q
    unknown = 64
    p_high = (p >> unknown) << unknown
    t0 = time.time()
    f = factor_known_high_bits(N, p_high, unknown, m=3, t=3)
    assert f in (p, q), "high-bits factoring failed"
    print(f"[+] known high bits: factored a 512-bit N from p>>64 in {time.time()-t0:.2f}s")

    # --- factoring from the low bits of p ---------------------------------- #
    known_bits = 256 - 64
    p_low = p % (1 << known_bits)
    t0 = time.time()
    f = factor_known_low_bits(N, p_low, known_bits, 64, m=3, t=3)
    assert f in (p, q), "low-bits factoring failed"
    print(f"[+] known low bits: factored in {time.time()-t0:.2f}s")

    # --- LLL sanity: a planted short vector must be found ------------------- #
    basis = [[1, 0, 12345678901234567890], [0, 1, 98765432109876543210]]
    red = lll(basis)
    assert min(sum(x * x for x in r) for r in red) < sum(x * x for x in basis[0])
    print("[+] LLL reduces a planted basis")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    _selftest()
```

## Code (SageMath one-liners - use these for real sizes)

```python
# coppersmith.sage   --   sage coppersmith.sage
# Sage's small_roots is the same algorithm with a fast fplll backend.

def stereotyped(N, e, c, known_int, unknown_bytes):
    """m = known_int + x, x < 256^unknown_bytes."""
    P = PolynomialRing(Zmod(N), names=('x',))
    (x,) = P.gens()
    f = (known_int + x) ** e - c
    f = f.monic()
    return f.small_roots(X=256 ** unknown_bytes, beta=1.0, epsilon=1 / 30)


def partial_p(N, p_high, unknown_bits):
    """p = p_high + x, x < 2^unknown_bits, unknown_bits < N.nbits()/4."""
    P = PolynomialRing(Zmod(N), names=('x',))
    (x,) = P.gens()
    f = x + p_high
    roots = f.small_roots(X=2 ** unknown_bits, beta=0.5, epsilon=1 / 30)
    return [gcd(int(p_high + r), N) for r in roots]


if __name__ == '__main__':
    p = random_prime(2 ** 512, lbound=2 ** 511)
    q = random_prime(2 ** 512, lbound=2 ** 511)
    N = p * q
    # half of p is enough for a 1024-bit modulus
    unknown = 250
    p_high = (p >> unknown) << unknown
    print('factor:', partial_p(int(N), int(p_high), unknown))
```

## Variants & pitfalls

- **Never reduce `f^i` mod N** when building the shifts (pure-python implementations get
  this wrong and then "Coppersmith does not work").
- **Monic or nothing.** Multiply by `inverse(lead, N)`; if that inverse does not exist,
  `gcd(lead, N)` factored `N`.
- **Bounds are hard limits.** Degree `e = 3` with a 1024-bit `N` gives ~341 unknown bits
  and no more. If you need more, find another leak.
- **`beta` for divisors.** Factoring with known bits uses `beta = 0.5`; if `p` is *unbalanced*
  (say 256 bits inside a 1024-bit N), use `beta = 0.25` and the bound improves.
- **Unknown bits in the middle** of `p` -> bivariate Coppersmith, use `defund/coppersmith`.
- **`epsilon` too small in Sage** blows up the lattice dimension; `1/30` or `1/20` is a
  sensible start, lower it only if the root is not found.
- **Sage's `small_roots` returns `[]`** silently when the bound is exceeded - that is not an
  error, it means "no root within X".
- Combine with brute force: if you have `bound + 8` unknown bits, brute the top byte and run
  Coppersmith 256 times.
- For lattices above dimension ~60, install `flatter` and use it as the reduction backend.

## Tools

```bash
# Sage: the practical route for real-size instances
sage -c 'R.<x> = Zmod(<N>)[]; f = x + <P_HIGH>; print(f.small_roots(X=2^250, beta=0.5))'

# defund/coppersmith: multivariate small_roots in Sage
git clone https://github.com/defund/coppersmith

# fpylll: LLL/BKZ from python, no Sage needed
pip install fpylll

# RsaCtfTool wraps several Coppersmith variants
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack partial_q,stereotyped
```

## References

- D. Coppersmith, "Small Solutions to Polynomial Equations, and Low Exponent RSA
  Vulnerabilities" (J. Cryptology, 1997)
- N. Howgrave-Graham, "Finding Small Roots of Univariate Modular Equations Revisited" (1997)
- Wikipedia: https://en.wikipedia.org/wiki/Coppersmith%27s_attack
- defund/coppersmith: https://github.com/defund/coppersmith
- flatter (fast lattice reduction): https://github.com/keeganryan/flatter
