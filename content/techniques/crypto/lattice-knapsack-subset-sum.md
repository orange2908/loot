---
title: "Lattices - Knapsack / Subset-Sum (Merkle-Hellman, Low Density)"
category: crypto
subcategory: lattice
type: technique
tags: [lattice, lll, lattice-reduction, knapsack, subset-sum, merkle-hellman, low-density, lagarias-odlyzko, cjloss, coster-joux, superincreasing, density, modular-multiplier, meet-in-the-middle, fpylll, sage, python]
difficulty: medium
summary: "Subset-sum with density below 0.94 is a short-vector problem. Build the CJLOSS basis, run LLL, read the 0/1 vector out of a +/-1 row."
when_to_use:
  - "A challenge gives weights a_1..a_n and a sum s and asks which subset produced it"
  - "Merkle-Hellman / 'knapsack cryptosystem' appears anywhere"
  - "The flag bits are encoded as a subset-sum over large random weights"
  - "Density d = n / log2(max a_i) is below about 0.9"
tools: [sage, fpylll, python]
related: [lattice-lll-fundamentals, lattice-hidden-number-problem, lattice-cvp-babai-scaling, lattice-toolkit, lattice-cheatsheet]
---

## TL;DR

Subset-sum is NP-hard in general but trivial when the weights are much larger than the number
of them. The measure is the **density** `d = n / log2(max a_i)`. Lagarias-Odlyzko breaks
`d < 0.6463`, Coster-Joux-LaMacchia-Odlyzko-Schnorr-Stern (CJLOSS) breaks `d < 0.9408`. Both
are one LLL call on a basis you can write in six lines.

## Recognise it

- `enc = sum(a[i] for i in range(n) if bits[i])` in the source.
- A public key that is a list of `n` big integers plus one target.
- "Merkle-Hellman", "superincreasing", "trapdoor knapsack".
- A flag encoded bit by bit, one weight per bit.
- `n` around 100-300 and weights of 200-600 bits -- i.e. density well under 1.

## Theory

**The problem.** Given `a_1..a_n` and `s = sum e_i a_i` with `e_i in {0,1}`, find `e`.

**Density.** `d = n / log2(max_i a_i)`. Low density means the `a_i` are "spread out" so the
solution vector is an unusually short lattice vector.

**Lagarias-Odlyzko basis** (dimension `n+1`, rows):

$$\begin{pmatrix} I_n & N\,a \\ 0 & N\,s \end{pmatrix}$$

The combination `sum e_i row_i - row_{n+1}` is `(e_1, ..., e_n, 0)` with norm at most
`sqrt(n)`. Works for `d < 0.6463`.

**CJLOSS basis** -- the one to use. Replace the identity by `2 I_n` and the last row's
identity part by all-ones:

$$\begin{pmatrix} 2 I_n & N\,a \\ 1 \cdots 1 & N\,s \end{pmatrix}$$

Now `sum e_i row_i - row_{n+1} = (2e_1 - 1, ..., 2e_n - 1, 0)`, every coordinate `+/-1`, norm
exactly `sqrt(n)`. Centring the entries around zero halves the norm compared with LO, which
pushes the breakable density up to `0.9408`. Take `N > sqrt(n)/2`; `N = n` is always safe.

**Reading the answer.** Scan the reduced rows for one whose last coordinate is `0` and whose
first `n` coordinates are all `+/-1`. Negate if necessary, then `e_i = (v_i + 1)/2`. Verify
the sum.

**Merkle-Hellman.** The trapdoor: pick a superincreasing sequence `b_1 < b_2 < ...` with
`b_i > sum_{j<i} b_j`, a modulus `q > sum b_i` and a multiplier `r` coprime to `q`. Publish
`a_i = r b_i mod q`. Decryption multiplies the ciphertext by `r^{-1} mod q` and greedily
peels off the superincreasing sequence.

Two independent breaks:

1. **Low density.** The public `a_i` still form a low-density knapsack (density around `n/n^2`
   for the original parameters), so LLL reads the plaintext straight off, no key needed.
2. **Shamir's attack.** Recover a usable `(q', r')` pair from the public key by finding the
   `r/q` ratio through simultaneous Diophantine approximation, then decrypt everything.
   In CTFs the LLL route is nearly always enough.

**When it fails.** Density near or above `1` (weights barely larger than `n` bits) means many
subsets hit the same sum, and no lattice can pick yours. Fall back to meet-in-the-middle:
`O(2^{n/2})` time and memory, feasible to `n ~ 50`.

## Attack

1. Compute the density. Above `0.94`, stop and think meet-in-the-middle.
2. Build the CJLOSS basis with `N = n`.
3. LLL (BKZ if `n > 80` and LLL is marginal).
4. Scan rows and both signs for an all-`+/-1` prefix with a zero last coordinate.
5. Recover the bits, verify the sum, decode.

## Code

```python
#!/usr/bin/env python3
"""Low-density subset sum with the CJLOSS lattice, plus a full Merkle-Hellman break."""
from fractions import Fraction
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

def density(weights):
    """d = n / log2(max a_i). LLL wins below ~0.9408 with the CJLOSS basis."""
    return len(weights) / max(w.bit_length() for w in weights)

def subset_sum_lo(weights, target):
    """Lagarias-Odlyzko basis: identity block, solution appears as a 0/1 vector."""
    n = len(weights)
    N = n + 1
    M = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        M[i][i] = 1
        M[i][n] = N * weights[i]
    M[n][n] = N * target
    for row in lll(M):
        if row[n] != 0:
            continue
        for v in (row, [-x for x in row]):
            if all(x in (0, 1) for x in v[:n]):
                if sum(b * w for b, w in zip(v[:n], weights)) == target:
                    return v[:n]
    return None

def subset_sum_cjloss(weights, target):
    """CJLOSS basis: centred entries, solution appears as a +/-1 vector."""
    n = len(weights)
    N = n + 1
    M = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        M[i][i] = 2
        M[i][n] = N * weights[i]
    for i in range(n):
        M[n][i] = 1
    M[n][n] = N * target
    for row in lll(M):
        if row[n] != 0:
            continue
        for v in (row, [-x for x in row]):
            if all(x in (1, -1) for x in v[:n]):
                e = [(x + 1) // 2 for x in v[:n]]
                if sum(b * w for b, w in zip(e, weights)) == target:
                    return e
    return None

# ---- Merkle-Hellman ------------------------------------------------------

def mh_keygen(n, rng, start_bits=96):
    """Superincreasing private key -> public key a_i = r*b_i mod q."""
    b, total = [], 0
    for _ in range(n):
        v = total + rng.randrange(1, 1 << start_bits) + 1
        b.append(v)
        total += v
    q = total + rng.randrange(1, 1 << start_bits) + 1
    r = rng.randrange(2, q)
    while True:
        try:
            pow(r, -1, q)
            break
        except ValueError:
            r = rng.randrange(2, q)
    a = [r * bi % q for bi in b]
    return a, (b, q, r)

def mh_encrypt(pub, bits):
    return sum(w for w, e in zip(pub, bits) if e)

def mh_decrypt(priv, c):
    b, q, r = priv
    t = c * pow(r, -1, q) % q
    out = [0] * len(b)
    for i in reversed(range(len(b))):
        if b[i] <= t:
            out[i] = 1
            t -= b[i]
    assert t == 0, "not a valid ciphertext"
    return out

if __name__ == "__main__":
    rng = random.Random(3)

    # --- 1. a plain low-density subset sum ---
    n = 22
    weights = [rng.randrange(1 << 150, 1 << 151) for _ in range(n)]
    secret = [rng.randrange(2) for _ in range(n)]
    s = sum(e * w for e, w in zip(secret, weights))
    print(f"[ok] n = {n}, density = {density(weights):.4f} (CJLOSS works below 0.9408)")
    assert subset_sum_cjloss(weights, s) == secret
    print("[ok] CJLOSS basis recovered the subset")
    assert subset_sum_lo(weights, s) == secret
    print("[ok] Lagarias-Odlyzko basis agreed (this density is low enough for both)")

    # --- 2. a Merkle-Hellman instance broken without the private key ---
    nbits = 20
    pub, priv = mh_keygen(nbits, rng)
    msg = [rng.randrange(2) for _ in range(nbits)]
    ct = mh_encrypt(pub, msg)
    assert mh_decrypt(priv, ct) == msg, "sanity: the legitimate trapdoor works"
    print(f"[ok] Merkle-Hellman with n = {nbits}, public density = {density(pub):.4f}")
    cracked = subset_sum_cjloss(pub, ct)
    assert cracked == msg
    print("[ok] plaintext recovered from the PUBLIC key alone, no trapdoor needed")

    # --- 3. a flag encoded bit by bit ---
    flag = b"ctf{knap}"
    bits = [(int.from_bytes(flag, "big") >> i) & 1 for i in range(len(flag) * 8)]
    bits = bits[:24]                                   # keep the demo fast
    w2 = [rng.randrange(1 << 160, 1 << 161) for _ in range(len(bits))]
    s2 = sum(e * w for e, w in zip(bits, w2))
    assert subset_sum_cjloss(w2, s2) == bits
    print(f"[ok] recovered {len(bits)} flag bits from a single sum")

    # --- 4. high density: the lattice stops working, as predicted ---
    hd = [rng.randrange(1 << 12, 1 << 13) for _ in range(20)]
    print(f"    a density-{density(hd):.2f} instance is out of reach for LLL; "
          "meet-in-the-middle is the fallback")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Wrong `N`.** Too small and the last coordinate does not dominate, so LLL returns junk
  rows with nonzero last entry. `N = n + 1` is fine; some write-ups use `N = ceil(sqrt(n))`.
- **Only checking row 0.** The `+/-1` vector often appears in the middle of the reduced
  basis. Scan everything.
- **Sign.** `v` and `-v` are both in the lattice; check both.
- **Weights with a common factor.** Divide it out of the weights and the target first, it
  lowers the effective bit length and therefore the density.
- **Multiple solutions.** At density near 1 there can be many subsets with the same sum; the
  lattice finds *a* short vector, not necessarily yours. Verify against extra constraints
  (printable ASCII, a known prefix).
- **Non-binary coefficients.** If `e_i in {0..k}` the vector is longer; scale the identity
  block by `2k` and centre by `k`, or accept a lower breakable density.
- **Dimension.** `n = 100` with 600-bit weights is dimension 101 with huge entries: use
  `fpylll` or `flatter`, not pure Python.
- **Meet-in-the-middle fallback.** Split the weights in half, enumerate `2^{n/2}` sums of each
  half into a dict, and look for `s - x`. Memory is the limit.

## Tools

```python
# SageMath: CJLOSS in a dozen lines
n = len(a); N = n + 1
M = Matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = 2
    M[i, n] = N * a[i]
    M[n, i] = 1
M[n, n] = N * s
for row in M.LLL():
    if row[n] == 0 and all(x in (1, -1) for x in row[:n]):
        e = [(x + 1) // 2 for x in row[:n]]
        if sum(ei * ai for ei, ai in zip(e, a)) == s:
            print(e); break
```

```python
# fpylll for the bigger instances
from fpylll import IntegerMatrix, LLL, BKZ
A = IntegerMatrix.from_matrix(rows)
BKZ.reduction(A, BKZ.Param(block_size=20))
```

## References

- Merkle, Hellman, "Hiding information and signatures in trapdoor knapsacks", IEEE Trans. Inf. Theory 24 (1978)
- Lagarias, Odlyzko, "Solving low-density subset sum problems", JACM 32 (1985)
- Coster, Joux, LaMacchia, Odlyzko, Schnorr, Stern, "Improved low-density subset sum algorithms", Computational Complexity 2 (1992)
- Shamir, "A polynomial time algorithm for breaking the basic Merkle-Hellman cryptosystem" (CRYPTO 1982)
