---
title: "Lattices - The Hidden Number Problem: A Template You Can Reuse"
category: crypto
subcategory: lattice
type: technique
tags: [lattice, lll, lattice-reduction, bkz, hnp, hidden-number-problem, boneh-venkatesan, msb-leak, lsb-leak, ecdsa, biased-nonce, truncated-lcg, partial-key-leak, recentring, fpylll, sage, python]
difficulty: hard
summary: "One lattice solves them all: whenever alpha*t_i - u_i is small mod n for known t_i, u_i, LLL recovers alpha. ECDSA bias, truncated LCG and MSB oracles are the same problem."
when_to_use:
  - "You know that some linear function of a secret is small modulo n, for several samples"
  - "An oracle leaks the top (or bottom) bits of alpha*t mod n"
  - "ECDSA nonces are short, or a PRNG only publishes high bits of its state"
  - "You have partial bits of a Diffie-Hellman shared secret"
tools: [sage, fpylll, flatter, python]
related: [lattice-lll-fundamentals, ecdsa-biased-nonce-lll, lattice-linear-relations, lattice-cvp-babai-scaling, lattice-toolkit]
---

## TL;DR

**HNP:** recover `alpha` given many pairs `(t_i, u_i)` with

$$|(\alpha t_i - u_i) \bmod n| < K$$

Build one lattice, run LLL, read `alpha` from a coordinate. It needs
`m * log2(n/K) > log2(n)` -- total leaked bits must exceed the secret size. Everything from
biased ECDSA nonces to truncated LCGs to MSB oracles is this problem in disguise.

## Recognise it

- "the top `B` bits of the secret product are revealed".
- Nonces, states or exponents that are short compared with the modulus.
- Many samples, each giving *one* linear relation with a small residue.
- You can write `secret * known_i - known_i' = small_i (mod n)`.

## Theory

**Definition (Boneh-Venkatesan 1996).** Given `n`, and `m` pairs `(t_i, u_i)` such that
`alpha t_i - u_i mod n` lies in `[0, K)` for an unknown `alpha`, find `alpha`.

**The lattice.** Take the `(m+2) x (m+2)` integer basis

$$B = \begin{pmatrix}
n^2 & & & & \\
& \ddots & & & \\
& & n^2 & & \\
n t_1 & \cdots & n t_m & K & 0 \\
n u_1 & \cdots & n u_m & 0 & nK
\end{pmatrix}$$

The vector

$$v = \alpha \cdot \text{row}_{m+1} - \text{row}_{m+2} - \sum_i c_i \,\text{row}_i
    = (n k_1, \ldots, n k_m, \alpha K, -nK)$$

is in the lattice (the `c_i` absorb the reductions mod `n`), with `k_i = (alpha t_i - u_i) mod n < K`.
Its norm is about `nK sqrt(m+1)`.

**Why LLL finds it.** `det(B) = n^{2m} \cdot K \cdot nK = n^{2m+1} K^2`, dimension
`d = m + 2`, so the Gaussian heuristic gives

$$\lambda_1 \approx \sqrt{\tfrac{d}{2\pi e}} \left(n^{2m+1}K^2\right)^{1/d}$$

The target beats that when `K` is small enough, i.e. when the *total* number of leaked bits
`m * log2(n/K)` comfortably exceeds `log2(n)`. Aim for a factor 1.5-2 of margin.

**Recentring.** If `k_i in [0, K)`, substitute `u_i <- u_i + K/2`, which puts `k_i` in
`(-K/2, K/2)` and halves the target norm. Free extra bit; always do it.

**Reading the answer.** Any reduced row `v` with `v[m] != 0` gives the candidate
`alpha = v[m] * K^{-1} mod n`. Try both signs, and verify.

**LSB / affine leaks.** If `k_i = 2^B k_i' + z_i` with `z_i` known, set
`t_i' = t_i 2^{-B}`, `u_i' = (u_i + z_i) 2^{-B}` and the problem is back in standard form.
More generally, any `k_i = a_i x_i + b_i` with `a_i, b_i` known folds in the same way.

**The three canonical instantiations.**

| problem | `t_i` | `u_i` | `alpha` |
| --- | --- | --- | --- |
| biased ECDSA nonce | `s_i^{-1} r_i` | `-s_i^{-1} h_i` | private key `d` |
| truncated LCG (prime modulus) | `A_i = a^i` | `y_i 2^B - B_i` | seed `s_0` |
| MSB oracle on `alpha*t` | the query `t_i` | the returned MSBs | the hidden number |

## Attack

1. Put the problem in the form `alpha t_i - u_i = small_i (mod n)`.
2. Determine the bound `K` honestly: overestimating `K` kills the attack.
3. Recentre.
4. Build the basis, LLL (BKZ if marginal).
5. Scan every row, both signs; verify against the original relations.

## Code

```python
#!/usr/bin/env python3
"""One HNP solver, three applications: MSB oracle, biased ECDSA, truncated LCG."""
from fractions import Fraction
import hashlib
import random

def dot(u, v):
    return sum(a * b for a, b in zip(u, v))

def rnd(x):
    return int(x + Fraction(1, 2)) if x >= 0 else -int(-x + Fraction(1, 2))

def lll(basis, delta=Fraction(99, 100)):
    """Exact LLL (Cohen, Algorithm 2.6.3)."""
    b = [[int(x) for x in row] for row in basis]
    n = len(b)
    if n < 2:
        return b
    mu = [[Fraction(0)] * n for _ in range(n)]
    bs, B = [None] * n, [Fraction(0)] * n
    bs[0] = [Fraction(x) for x in b[0]]
    B[0] = dot(bs[0], bs[0])
    kmax, k = 0, 1

    def red(i, j):
        if abs(mu[i][j]) <= Fraction(1, 2):
            return
        q = rnd(mu[i][j])
        b[i] = [x - q * y for x, y in zip(b[i], b[j])]
        mu[i][j] -= q
        for t in range(j):
            mu[i][t] -= q * mu[j][t]

    while k < n:
        if k > kmax:
            kmax = k
            row = [Fraction(x) for x in b[k]]
            v = list(row)
            for j in range(k):
                mu[k][j] = Fraction(0) if B[j] == 0 else dot(row, bs[j]) / B[j]
                v = [a - mu[k][j] * c for a, c in zip(v, bs[j])]
            bs[k], B[k] = v, dot(v, v)
        red(k, k - 1)
        if B[k] < (delta - mu[k][k - 1] ** 2) * B[k - 1]:
            m_ = mu[k][k - 1]
            BB = B[k] + m_ * m_ * B[k - 1]
            b[k], b[k - 1] = b[k - 1], b[k]
            mu[k][k - 1] = m_ * B[k - 1] / BB
            old = bs[k - 1]
            bs[k - 1] = [x + m_ * y for x, y in zip(bs[k], old)]
            bs[k] = [-mu[k][k - 1] * x + (B[k] / BB) * y for x, y in zip(bs[k], old)]
            B[k], B[k - 1] = B[k - 1] * B[k] / BB, BB
            for j in range(k - 1):
                mu[k][j], mu[k - 1][j] = mu[k - 1][j], mu[k][j]
            for i in range(k + 1, kmax + 1):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - m_ * t
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
            k = max(1, k - 1)
        else:
            for j in range(k - 2, -1, -1):
                red(k, j)
            k += 1
    return b

# ---- the reusable template ---------------------------------------------

def hnp_candidates(ts, us, n, bound, recentre=True):
    """Yield candidate alpha with (alpha*t_i - u_i) mod n < bound."""
    m = len(ts)
    if recentre:
        us = [(u + bound // 2) % n for u in us]
        bound = bound // 2 + 1
    dim = m + 2
    M = [[0] * dim for _ in range(dim)]
    for i in range(m):
        M[i][i] = n * n
        M[m][i] = n * ts[i] % (n * n)
        M[m + 1][i] = n * us[i] % (n * n)
    M[m][m] = bound
    M[m + 1][m + 1] = n * bound
    inv = pow(bound, -1, n)
    for row in lll(M):
        if row[m] == 0:
            continue
        yield (row[m] * inv) % n
        yield (-row[m] * inv) % n

def hnp(ts, us, n, bound, check=None):
    """Return the alpha that passes `check` (default: all residues below bound)."""
    if check is None:
        check = lambda a: all((a * t - u) % n < bound for t, u in zip(ts, us))
    for cand in hnp_candidates(ts, us, n, bound):
        if cand and check(cand):
            return cand
    return None

# ---- application 1: a plain MSB oracle ---------------------------------

def msb_oracle_demo(rng, nbits=128, leak=32, samples=8):
    n = (1 << nbits) - 159                  # a prime: 2^128 - 159
    alpha = rng.randrange(1, n)
    K = 1 << (nbits - leak)
    ts, us = [], []
    for _ in range(samples):
        t = rng.randrange(1, n)
        prod = alpha * t % n
        us.append(prod - (prod % K))        # the oracle returns the top `leak` bits
        ts.append(t)
    return n, alpha, ts, us, K

# ---- application 2: biased ECDSA nonces --------------------------------

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def ec_add(A, B):
    if A is None:
        return B
    if B is None:
        return A
    (x1, y1), (x2, y2) = A, B
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    lam = ((3 * x1 * x1) * pow(2 * y1 % P, -1, P) if A == B
           else (y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def ec_mul(k, A):
    R, S, k = None, A, k % N
    while k:
        if k & 1:
            R = ec_add(R, S)
        S, k = ec_add(S, S), k >> 1
    return R

def ecdsa_hnp_demo(rng, bias=64, samples=8):
    d = rng.randrange(1, N)
    K = 1 << (N.bit_length() - bias)
    ts, us = [], []
    for i in range(samples):
        h = int.from_bytes(hashlib.sha256(f"m{i}".encode()).digest(), "big") % N
        k = rng.randrange(1, K)
        r = ec_mul(k, G)[0] % N
        s = pow(k, -1, N) * (h + r * d) % N
        si = pow(s, -1, N)
        ts.append(si * r % N)
        us.append(-si * h % N)
    return d, ts, us, K

# ---- application 3: truncated LCG with a prime modulus -----------------

def truncated_lcg_demo(rng, mbits=64, hidden=24, samples=6):
    m = (1 << mbits) - 59                   # 2^64 - 59 is prime
    a = rng.randrange(2, m)
    c = rng.randrange(1, m)
    s0 = rng.randrange(1, m)
    # s_i = A_i*s0 + B_i (mod m); outputs are the top bits of s_i
    A, Bc, s = 1, 0, s0
    ts, us = [], []
    for _ in range(samples):
        y = s >> hidden                     # published: the high bits only
        ts.append(A)
        us.append((y << hidden) - Bc)
        A, Bc = A * a % m, (Bc * a + c) % m
        s = (a * s + c) % m
    return m, s0, ts, us, 1 << hidden

if __name__ == "__main__":
    rng = random.Random(1001)

    # 1. MSB oracle
    n, alpha, ts, us, K = msb_oracle_demo(rng)
    got = hnp(ts, us, n, K)
    assert got == alpha, "MSB-oracle HNP failed"
    print(f"[ok] MSB oracle: 128-bit secret from 8 samples of 32 leaked bits")

    # 2. biased ECDSA nonces
    d, ts, us, K = ecdsa_hnp_demo(rng)
    got = hnp(ts, us, N, K, check=lambda a: ec_mul(a, G) == ec_mul(d, G))
    assert got == d, "ECDSA HNP failed"
    print(f"[ok] ECDSA: 256-bit key from 8 signatures with 64-bit nonce bias")

    # 3. truncated LCG
    m, s0, ts, us, K = truncated_lcg_demo(rng)
    got = hnp(ts, us, m, K)
    assert got == s0, "truncated-LCG HNP failed"
    print(f"[ok] truncated LCG: seed recovered from 6 outputs missing 24 low bits")

    # 4. the margin check that tells you in advance whether it will work
    for name, (mm, nn, kk) in [("ECDSA", (8, N, 1 << 192)),
                               ("LCG", (6, m, 1 << 24))]:
        leaked = mm * (nn.bit_length() - kk.bit_length())
        print(f"    {name}: {leaked} leaked bits vs {nn.bit_length()}-bit secret "
              f"-> margin {leaked / nn.bit_length():.1f}x")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Bound too loose.** `K` must be a real bound on `|alpha t_i - u_i|`. Using `K = n/2` says
  nothing and the lattice has no short vector.
- **Not enough samples.** Compute the margin first. Below `1.2x` expect failure with LLL;
  BKZ buys you a little.
- **Bad samples mixed in.** One sample whose residue is *not* small destroys the whole
  lattice. If you suspect a few, run on random subsets.
- **`gcd(K, n) != 1`.** The template inverts `K` mod `n`. With a power-of-two modulus (an
  ordinary LCG) that fails; use the dedicated construction in `lattice-linear-relations`.
- **Sign of `u_i`.** `alpha t_i - u_i` small, not `u_i - alpha t_i`. Off-by-a-sign looks
  exactly like "not enough samples".
- **Alternative basis.** Many write-ups use an `(m+1)`-dimensional basis with a rational
  `K/n` entry. The integer version above avoids floating point entirely.
- **Very small `K`.** When the residues are *tiny* the target is extremely short and even a
  2-sample lattice works. Try small `m` first; it is much faster.
- **Dimension.** Each sample adds a dimension. At `m = 100` (needed for 3-bit bias on a
  256-bit key) use `fpylll`/`flatter`, not pure Python.

## Tools

```python
# SageMath: the same basis, with BKZ
M = Matrix(ZZ, m + 2, m + 2)
for i in range(m):
    M[i, i] = n * n
    M[m, i] = n * ts[i]
    M[m + 1, i] = n * us[i]
M[m, m] = K
M[m + 1, m + 1] = n * K
for row in M.BKZ(block_size=25):
    if row[m]:
        print(ZZ(row[m] / K) % n)
```

```python
# fpylll outside Sage
from fpylll import IntegerMatrix, LLL
A = IntegerMatrix.from_matrix(rows)
LLL.reduction(A)
```

## References

- Boneh, Venkatesan, "Hardness of computing the most significant bits of secret keys in Diffie-Hellman and related schemes" (CRYPTO 1996)
- Nguyen, Shparlinski, "The insecurity of the Digital Signature Algorithm with partially known nonces", J. Cryptology 15 (2002)
- Howgrave-Graham, Smart, "Lattice attacks on digital signature schemes", Designs Codes and Cryptography 23 (2001)
- https://github.com/fplll/fpylll
