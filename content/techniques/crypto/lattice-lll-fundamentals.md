---
title: "Lattices - LLL From Zero: Bases, Guarantees and How to Build One"
category: crypto
subcategory: lattice
type: technique
tags: [lattice, lll, lattice-reduction, bkz, svp, cvp, gram-schmidt, determinant, hermite-factor, gaussian-heuristic, successive-minima, basis-construction, fpylll, flatter, sage, python]
difficulty: medium
summary: "What a lattice is, what LLL actually promises, and the recipe for turning 'these unknowns are small' into a basis whose short vector is your answer."
when_to_use:
  - "A challenge has small unknowns tied together by modular linear equations"
  - "You keep seeing 'run LLL on this matrix' and want to know why it works"
  - "You need to decide between LLL, BKZ and giving up"
  - "Your lattice 'does not work' and you need to check the size heuristics"
tools: [sage, fpylll, flatter, python]
related: [lattice-hidden-number-problem, lattice-knapsack-subset-sum, lattice-cvp-babai-scaling, lattice-coppersmith-small-roots, lattice-toolkit, lattice-cheatsheet]
---

## TL;DR

A lattice is the set of *integer* combinations of some basis vectors. Different bases
describe the same lattice; LLL turns a bad basis into one that is nearly orthogonal and whose
first vector is short. If you can arrange for your secret to be a short vector of a lattice
you can write down, LLL finds it.

## Recognise it

- Unknowns are small compared with the modulus (`k < 2^64` while `n ~ 2^256`).
- The relations are linear modulo something: `a*x + b*y = c (mod n)`.
- The challenge mentions "lattice", "LLL", "short vector", "CVP", "SVP", "BKZ".
- You have more equations than unknowns but everything is modular.
- Coppersmith, knapsack, HNP, truncated LCG, RSA partial-key -- all of them end here.

## Theory

**Lattice.** Given linearly independent `b_1, ..., b_n` in `R^m`,

$$L = \left\{ \sum_{i=1}^{n} x_i b_i \;:\; x_i \in \mathbb{Z} \right\}$$

The `b_i` form a *basis*. Any `U b` with `U` an integer matrix of determinant `+/-1`
(unimodular) is another basis of the same lattice.

**Determinant (covolume).** `det(L) = sqrt(det(B B^T))`, and for a square basis just
`|det(B)|`. It is basis-independent: that is why LLL cannot make everything short at once.

**Successive minima.** `lambda_1` is the length of the shortest nonzero vector, `lambda_2`
the shortest independent of the first, and so on. Minkowski:
`lambda_1 <= sqrt(n) det(L)^{1/n}`.

**Gaussian heuristic.** For a "random" lattice,

$$\lambda_1 \approx \sqrt{\frac{n}{2\pi e}} \, \det(L)^{1/n}$$

This is your sanity check: if the vector you are hoping for is *longer* than this, it is not
special and LLL will not single it out. If it is much shorter, LLL will find it.

**Gram-Schmidt.** `b*_1 = b_1`, `b*_i = b_i - sum_{j<i} mu_{ij} b*_j` with
`mu_{ij} = <b_i, b*_j> / <b*_j, b*_j>`. The `b*_i` are orthogonal but *not* in the lattice.
`det(L) = prod ||b*_i||`.

**LLL-reduced.** A basis is LLL-reduced with parameter `delta` in `(1/4, 1)` when

1. size reduced: `|mu_{ij}| <= 1/2` for all `j < i`;
2. Lovasz condition: `delta ||b*_{i-1}||^2 <= ||b*_i||^2 + mu_{i,i-1}^2 ||b*_{i-1}||^2`.

**What you are promised.** With `delta = 3/4`:

$$\|b_1\| \le 2^{(n-1)/4} \det(L)^{1/n}, \qquad \|b_1\| \le 2^{(n-1)/2} \lambda_1$$

Exponential in `n` in theory. In practice LLL behaves like a Hermite factor of about
`1.02^n`, which is why dimension 40 lattices routinely give the exact shortest vector and
dimension 200 ones do not. `delta = 0.99` is the usual CTF setting: slower, better output.

**BKZ.** Block Korkine-Zolotarev runs an exact SVP oracle on blocks of size `beta`. Hermite
factor drops to roughly `beta^{1/(2 beta)}` per dimension; `beta = 20..40` is cheap,
`beta = 60+` gets expensive fast. Reach for it when LLL is *just* short of working.

**Building a basis: the recipe.** You want a lattice whose vectors encode "the residues are
small".

1. Write every relation as `sum_j c_j x_j = t (mod n)` with the `x_j` your small unknowns.
2. Make one row per unknown, one row per constant term, and one row `n * e_i` per modular
   relation -- the `n`-rows let the reduction subtract off the modulus.
3. Scale columns so that every coordinate of the *target* vector has roughly the same size.
   An unknown bounded by `X_j` gets its column multiplied by `C / X_j` for a common `C`.
4. Check the target's norm against the Gaussian heuristic. If it is not clearly smaller, you
   need more relations or tighter bounds.
5. Reduce, then scan **every** row and both signs for something that satisfies the original
   equations.

**Row convention.** Sage, fpylll and this file all use *rows* as basis vectors. Papers often
use columns. Transposing a basis by mistake is the single most common beginner bug.

## Attack

1. Identify the small unknowns and their bounds.
2. Write the modular relations.
3. Build the basis by the recipe; scale.
4. `LLL` (then `BKZ` if needed).
5. Scan the rows, undo the scaling, verify against the original problem.

## Code

```python
#!/usr/bin/env python3
"""LLL from scratch: Gram-Schmidt, reduction, and the guarantees, all verified."""
from fractions import Fraction
import math
import random

def dot(u, v):
    return sum(a * b for a, b in zip(u, v))

def rnd(x):
    return int(x + Fraction(1, 2)) if x >= 0 else -int(-x + Fraction(1, 2))

def gram_schmidt(basis):
    """Exact GSO. Returns (orthogonal rows b*, coefficients mu)."""
    bs, mu = [], [[Fraction(0)] * len(basis) for _ in basis]
    for i, row in enumerate(basis):
        r = [Fraction(x) for x in row]
        v = list(r)
        for j in range(i):
            d = dot(bs[j], bs[j])
            mu[i][j] = Fraction(0) if d == 0 else dot(r, bs[j]) / d
            v = [a - mu[i][j] * c for a, c in zip(v, bs[j])]
        bs.append(v)
    return bs, mu

def lll(basis, delta=Fraction(99, 100)):
    """LLL with exact rational arithmetic (Cohen, Algorithm 2.6.3)."""
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

def det_exact(m):
    """Exact determinant of a square integer matrix by fraction-free elimination."""
    a = [[Fraction(x) for x in row] for row in m]
    n, sign, d = len(a), 1, Fraction(1)
    for c in range(n):
        piv = next((r for r in range(c, n) if a[r][c] != 0), None)
        if piv is None:
            return 0
        if piv != c:
            a[c], a[piv] = a[piv], a[c]
            sign = -sign
        d *= a[c][c]
        inv = a[c][c]
        for r in range(c + 1, n):
            f = a[r][c] / inv
            a[r] = [x - f * y for x, y in zip(a[r], a[c])]
    return sign * d

def is_lll_reduced(basis, delta=Fraction(99, 100)):
    bs, mu = gram_schmidt(basis)
    for i in range(len(basis)):
        for j in range(i):
            if abs(mu[i][j]) > Fraction(1, 2):
                return False
    for i in range(1, len(basis)):
        lhs = dot(bs[i], bs[i]) + mu[i][i - 1] ** 2 * dot(bs[i - 1], bs[i - 1])
        if lhs < delta * dot(bs[i - 1], bs[i - 1]):
            return False
    return True

def gaussian_heuristic(n, det):
    return math.sqrt(n / (2 * math.pi * math.e)) * det ** (1.0 / n)

if __name__ == "__main__":
    rng = random.Random(8)

    # --- 1. reduction keeps the lattice (determinant) and shortens the basis ---
    n = 8
    B = [[rng.randrange(-10**4, 10**4) for _ in range(n)] for _ in range(n)]
    R = lll(B)
    assert abs(det_exact(B)) == abs(det_exact(R)), "LLL must preserve the determinant"
    assert is_lll_reduced(R), "output must satisfy both LLL conditions"
    before = min(dot(r, r) for r in B)
    after = dot(R[0], R[0])
    assert after <= before
    print(f"[ok] dim {n}: |det| unchanged, shortest norm^2 {before} -> b1 norm^2 {after}")

    # --- 2. the theoretical guarantee holds (and is very loose) ---
    d = abs(det_exact(R))
    bound = 2 ** ((n - 1) / 4) * d ** (1 / n)
    got = math.sqrt(after)
    assert got <= bound
    gh = gaussian_heuristic(n, d)
    print(f"[ok] ||b1|| = {got:.1f} <= 2^((n-1)/4) det^(1/n) = {bound:.1f}")
    print(f"    Gaussian heuristic predicts lambda_1 ~ {gh:.1f}; ratio {got / gh:.2f}")

    # --- 3. the recipe: 'these unknowns are small' -> a basis ---
    # x and y are small; we know a*x + b*y = c (mod m). Build the lattice
    # generated by (1, 0, a), (0, 1, b), (0, 0, m) and look for (x, y, c - k*m).
    m = 10**9 + 7
    x, y = rng.randrange(1, 1000), rng.randrange(1, 1000)
    a, b = rng.randrange(1, m), rng.randrange(1, m)
    c = (a * x + b * y) % m
    K = 10**6                      # scale the last column so the residual dominates
    basis = [[1, 0, a * K], [0, 1, b * K], [0, 0, m * K]]
    # Kannan embedding: append the target as an extra row with a 1 in a new column,
    # so the short vector (x, y, 0, -1) appears directly in the reduced basis.
    emb = [row + [0] for row in basis] + [[0, 0, c * K, 1]]
    found = None
    for row in lll(emb):
        if abs(row[3]) != 1 or row[2] != 0:
            continue
        cand = (-row[0] * row[3], -row[1] * row[3])
        if 0 < cand[0] < 10**4 and 0 < cand[1] < 10**4 and (a * cand[0] + b * cand[1]) % m == c:
            found = cand
            break
    assert found == (x, y), (found, (x, y))
    print(f"[ok] recovered the small unknowns (x, y) = {found} from one modular relation")

    # --- 4. why it works: the target is far below the Gaussian heuristic ---
    dd = float(m) * K            # det of the 3-dim lattice above (rows 1,2 have det 1)
    print(f"    target norm ~ {math.hypot(x, y):.1f} vs heuristic "
          f"{gaussian_heuristic(3, dd):.1f}: orders of magnitude shorter, so LLL finds it")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Rows vs columns.** Everything here is row-based. If you copy a basis out of a paper,
  transpose it.
- **Unbalanced columns.** If one coordinate of the target is `2^200` and another is `2^10`,
  LLL optimises the big one and ignores the small one. Scale. See
  `lattice-cvp-babai-scaling`.
- **Target not actually short.** Compare against the Gaussian heuristic *before* debugging
  your code. If the target is longer, no amount of BKZ helps -- you need more relations.
- **Scanning only `b_1`.** The answer is often in row 2 or 3, or is the negation of a row.
  Always loop over all rows and both signs.
- **Dimension too high for exact arithmetic.** Pure-Python `Fraction` LLL is comfortable to
  dimension ~40 with big entries. Past that use `fpylll`, Sage or `flatter`.
- **delta.** `0.75` is fast and weak, `0.99` is the practical default, `1.0` is not allowed.
- **LLL is not an SVP solver.** It approximates. When you need the true shortest vector in
  dimension <= 50, use `fpylll`'s `SVP.shortest_vector` or Sage's `IntegerLattice(...).shortest_vector()`.

## Tools

```python
# SageMath
M = Matrix(ZZ, rows)
R = M.LLL()                              # delta defaults to 0.99 in Sage
R = M.BKZ(block_size=30)
from sage.modules.free_module_integer import IntegerLattice
print(IntegerLattice(M).shortest_vector())
```

```python
# fpylll
from fpylll import IntegerMatrix, LLL, BKZ, SVP
A = IntegerMatrix.from_matrix(rows)
LLL.reduction(A)
BKZ.reduction(A, BKZ.Param(block_size=30))
print(SVP.shortest_vector(A))
```

```sh
# flatter: much faster reduction for large bases
flatter < basis.txt > reduced.txt
```

## References

- Lenstra, Lenstra, Lovasz, "Factoring polynomials with rational coefficients", Math. Ann. 261 (1982)
- Cohen, *A Course in Computational Algebraic Number Theory*, Algorithm 2.6.3
- Galbraith, *Mathematics of Public Key Cryptography*, chapters 16-18, https://www.math.auckland.ac.nz/~sgal018/crypto-book/crypto-book.html
- https://github.com/fplll/fpylll
- https://github.com/keeganryan/flatter
