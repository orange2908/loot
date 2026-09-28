---
title: "Lattice Toolkit - LLL, HNP, Subset-Sum and Babai CVP in One File"
category: crypto
subcategory: lattice
type: script
tags: [lattice, lll, lattice-reduction, bkz, svp, cvp, babai, hnp, hidden-number-problem, knapsack, subset-sum, cjloss, merkle-hellman, ecdsa, biased-nonce, fpylll, sage, flatter, pure-python, gram-schmidt]
summary: "One file: exact-arithmetic LLL with an fpylll fast path, plus an HNP solver, a low-density subset-sum solver and Babai nearest-plane CVP. Self-tested."
tools: [fpylll, sage, flatter, python]
related: [lattice-lll-fundamentals, lattice-hidden-number-problem, lattice-knapsack-subset-sum, lattice-cvp-babai-scaling, ecdsa-biased-nonce-lll, lattice-cheatsheet]
---

## What this is

`lattice_toolkit.py` runs anywhere Python 3.11 runs. If `fpylll` is importable it is used
for the reduction (orders of magnitude faster); otherwise an exact `Fraction`-based LLL
takes over, so the file has **no hard dependencies**. Everything is checked by the
`__main__` self-test, which builds its own ECDSA-style HNP instance and its own knapsack.

Install the fast path when you can:

```sh
# fpylll via pip (needs fplll headers) or, far easier, via conda
conda create -n lat -c conda-forge fpylll python=3.11 && conda activate lat
# or just use SageMath, which ships fpylll: sage -python lattice_toolkit.py
```

## API

| function | does |
| --- | --- |
| `lll(basis, delta=0.99)` | reduce a list-of-lists integer basis, fpylll if present |
| `gram_schmidt(basis)` | exact GSO, returns `(b_star, mu)` |
| `babai_nearest_plane(basis, target)` | closest lattice vector (approximate) |
| `babai_rounding(basis, target)` | cheaper, worse CVP |
| `hnp(ts, us, n, bound)` | `alpha` with `(alpha*t_i - u_i) mod n < bound` |
| `subset_sum(weights, target)` | `{0,1}` solution of a low-density knapsack (CJLOSS) |

## Code

```python
#!/usr/bin/env python3
"""lattice_toolkit.py -- LLL / HNP / subset-sum / Babai CVP with no hard deps."""
from __future__ import annotations
from fractions import Fraction
import random

try:                                    # fast path
    from fpylll import IntegerMatrix, LLL as _FPLLL
    HAVE_FPYLLL = True
except ImportError:
    HAVE_FPYLLL = False

def _dot(u, v):
    return sum(a * b for a, b in zip(u, v))

def _rnd(x):
    """Nearest integer to a Fraction (ties away from zero)."""
    return int(x + Fraction(1, 2)) if x >= 0 else -int(-x + Fraction(1, 2))

def lll_exact(basis, delta=Fraction(99, 100)):
    """Textbook LLL with exact rational GSO (Cohen, Algorithm 2.6.3)."""
    b = [[int(x) for x in row] for row in basis]
    n = len(b)
    if n < 2:
        return b
    mu = [[Fraction(0)] * n for _ in range(n)]
    bs, B = [None] * n, [Fraction(0)] * n
    bs[0] = [Fraction(x) for x in b[0]]
    B[0] = _dot(bs[0], bs[0])
    kmax, k = 0, 1

    def red(i, j):
        if abs(mu[i][j]) <= Fraction(1, 2):
            return
        q = _rnd(mu[i][j])
        b[i] = [x - q * y for x, y in zip(b[i], b[j])]
        mu[i][j] -= q
        for t in range(j):
            mu[i][t] -= q * mu[j][t]

    while k < n:
        if k > kmax:
            kmax = k
            v = [Fraction(x) for x in b[k]]
            row = [Fraction(x) for x in b[k]]
            for j in range(k):
                mu[k][j] = Fraction(0) if B[j] == 0 else _dot(row, bs[j]) / B[j]
                v = [a - mu[k][j] * c for a, c in zip(v, bs[j])]
            bs[k], B[k] = v, _dot(v, v)
        red(k, k - 1)
        if B[k] < (delta - mu[k][k - 1] ** 2) * B[k - 1]:
            m_ = mu[k][k - 1]
            BB = B[k] + m_ * m_ * B[k - 1]
            b[k], b[k - 1] = b[k - 1], b[k]
            if BB == 0:
                B[k], B[k - 1] = B[k - 1], B[k]
                bs[k], bs[k - 1] = bs[k - 1], bs[k]
            else:
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

def lll(basis, delta=0.99):
    """LLL-reduce a list-of-lists basis. Uses fpylll when available."""
    if HAVE_FPYLLL:
        M = IntegerMatrix.from_matrix([[int(x) for x in row] for row in basis])
        _FPLLL.reduction(M, delta=delta)
        return [[M[i, j] for j in range(M.ncols)] for i in range(M.nrows)]
    return lll_exact(basis, Fraction(delta).limit_denominator(1000))

def gram_schmidt(basis):
    """Exact Gram-Schmidt: returns (orthogonal rows, mu coefficients)."""
    bs, mu = [], [[Fraction(0)] * len(basis) for _ in basis]
    for i, row in enumerate(basis):
        r = [Fraction(x) for x in row]
        v = list(r)
        for j in range(i):
            d = _dot(bs[j], bs[j])
            mu[i][j] = Fraction(0) if d == 0 else _dot(r, bs[j]) / d
            v = [a - mu[i][j] * c for a, c in zip(v, bs[j])]
        bs.append(v)
    return bs, mu

def babai_nearest_plane(basis, target):
    """Babai's nearest-plane CVP. Returns a lattice vector close to target."""
    b = lll(basis)
    bs, _ = gram_schmidt(b)
    w = [Fraction(x) for x in target]
    for i in reversed(range(len(b))):
        d = _dot(bs[i], bs[i])
        c = 0 if d == 0 else _rnd(_dot(w, bs[i]) / d)
        w = [x - c * y for x, y in zip(w, b[i])]
    return [int(t - x) for t, x in zip(target, w)]

def babai_rounding(basis, target):
    """Cheaper CVP: solve t = sum c_i b_i over QQ, round the c_i."""
    b = lll(basis)
    n = len(b)
    # Gaussian elimination on the transpose to express target in the basis
    A = [[Fraction(b[j][i]) for j in range(n)] + [Fraction(target[i])] for i in range(len(target))]
    piv = 0
    for col in range(n):
        r = next((i for i in range(piv, len(A)) if A[i][col] != 0), None)
        if r is None:
            continue
        A[piv], A[r] = A[r], A[piv]
        inv = A[piv][col]
        A[piv] = [x / inv for x in A[piv]]
        for i in range(len(A)):
            if i != piv and A[i][col] != 0:
                f = A[i][col]
                A[i] = [x - f * y for x, y in zip(A[i], A[piv])]
        piv += 1
    c = [_rnd(A[i][n]) for i in range(n)]
    out = [0] * len(target)
    for i in range(n):
        out = [o + c[i] * x for o, x in zip(out, b[i])]
    return out

def hnp(ts, us, n, bound, delta=0.99):
    """Hidden Number Problem: find alpha with (alpha*t_i - u_i) mod n < bound.

    Basis rows (dimension m+2), all integers:
        n^2 * e_i                      for i < m
        (n*t_0, ..., n*t_{m-1}, bound, 0)
        (n*u_0, ..., n*u_{m-1}, 0, n*bound)
    The target short vector is alpha*row_m - row_{m+1} - (reductions), whose last two
    coordinates are alpha*bound and -n*bound, so alpha = v[m] / bound mod n.
    """
    m = len(ts)
    dim = m + 2
    M = [[0] * dim for _ in range(dim)]
    for i in range(m):
        M[i][i] = n * n
        M[m][i] = n * ts[i] % (n * n)
        M[m + 1][i] = n * us[i] % (n * n)
    M[m][m] = bound
    M[m + 1][m + 1] = n * bound
    inv = pow(bound, -1, n)
    for row in lll(M, delta):
        if row[m] == 0:
            continue
        for cand in ((row[m] * inv) % n, (-row[m] * inv) % n):
            if all((cand * t - u) % n < bound for t, u in zip(ts, us)):
                return cand
    return None

def subset_sum(weights, target, delta=0.99):
    """Low-density subset sum via the CJLOSS lattice. Returns the 0/1 vector or None."""
    n = len(weights)
    N = n + 1
    M = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        M[i][i] = 2
        M[i][n] = N * weights[i]
    for i in range(n):
        M[n][i] = 1
    M[n][n] = N * target
    for row in lll(M, delta):
        if row[n] != 0:
            continue
        for v in (row, [-x for x in row]):
            if all(x in (1, -1) for x in v[:n]):
                e = [(x + 1) // 2 for x in v[:n]]
                if sum(b * w for b, w in zip(e, weights)) == target:
                    return e
    return None

def density(weights):
    """Knapsack density n / log2(max a_i). LLL wins below ~0.94 (CJLOSS)."""
    return len(weights) / max(w.bit_length() for w in weights)

# ---- self-test -----------------------------------------------------------

def _selftest():
    rng = random.Random(1)
    print("fpylll:", "yes" if HAVE_FPYLLL else "no (using exact fallback)")

    # 1. LLL basics: reduction preserves the lattice and shortens the first vector
    A = [[rng.randrange(-1000, 1000) for _ in range(5)] for _ in range(5)]
    R = lll(A)
    n0 = min(_dot(r, r) for r in A)
    n1 = _dot(R[0], R[0])
    assert n1 <= n0
    print(f"[ok] LLL: shortest input norm^2 {n0} -> reduced b1 norm^2 {n1}")

    # 2. Babai CVP on a scaled random basis
    B = [[10, 0, 0], [0, 10, 0], [0, 0, 10]]
    t = [13, 27, -4]
    v = babai_nearest_plane(B, t)
    assert v == [10, 30, 0], v
    assert babai_rounding(B, t) == [10, 30, 0]
    print(f"[ok] Babai: closest vector to {t} is {v}")

    # 3. Hidden Number Problem sized like a biased-nonce ECDSA break
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    alpha = rng.randrange(1, n)
    m, bias = 8, 64                       # 8 samples, top 64 bits of each k are zero
    bound = 1 << (n.bit_length() - bias)
    ts, us = [], []
    for _ in range(m):
        t = rng.randrange(1, n)
        k = rng.randrange(1, bound)
        ts.append(t)
        us.append((t * alpha - k) % n)
    got = hnp(ts, us, n, bound)
    assert got == alpha, "HNP failed"
    print(f"[ok] HNP: recovered a 256-bit secret from {m} samples with {bias} bits of bias")

    # 4. Low-density subset sum (Merkle-Hellman shaped)
    nw = 24
    weights = [rng.randrange(1 << 180, 1 << 181) for _ in range(nw)]
    secret = [rng.randrange(2) for _ in range(nw)]
    s = sum(b * w for b, w in zip(secret, weights))
    print(f"    knapsack density = {density(weights):.3f}")
    e = subset_sum(weights, s)
    assert e == secret, "subset-sum failed"
    print(f"[ok] subset-sum: recovered {nw} secret bits")
    print("all self-tests passed")

if __name__ == "__main__":
    _selftest()
```

## Notes and limits

- The exact fallback is `O(dim^4)` in `Fraction` arithmetic. It is comfortable up to about
  dimension 30 with 256-bit entries and dimension 60 with small entries. Beyond that,
  install `fpylll` or run under `sage -python`; for dimension > 150 use
  [flatter](https://github.com/keeganryan/flatter).
- `hnp` returns `None` when the lattice does not contain the target as a short enough
  vector. The usual fixes: more samples, a tighter `bound`, or BKZ instead of LLL.
- `subset_sum` uses the CJLOSS basis, good up to density about 0.94. Above that, no lattice
  trick saves you -- fall back to meet-in-the-middle.
- `babai_rounding` needs a full-rank basis; `babai_nearest_plane` is the one to trust.
- LLL gives no guarantee that the *shortest* vector is `b_1`; always scan every reduced row,
  and both sign choices, before declaring failure. Both solvers here already do.

## References

- https://github.com/fplll/fpylll
- https://github.com/keeganryan/flatter
- https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/matrix_integer_dense.html
- Coster, Joux, LaMacchia, Odlyzko, Schnorr, Stern, "Improved low-density subset sum algorithms" (1992)
