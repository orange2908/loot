---
title: "Lattices - CVP, Babai, Kannan Embedding and the Column-Scaling Trick"
category: crypto
subcategory: lattice
type: technique
tags: [lattice, lll, lattice-reduction, cvp, svp, babai, nearest-plane, rounding, kannan-embedding, scaling, weighting, unbalanced, modular-equations, gram-schmidt, fpylll, sage, python]
difficulty: hard
summary: "Modular equation systems become CVP. Babai solves CVP approximately, Kannan turns it into SVP, and column scaling is what makes unbalanced unknowns findable."
when_to_use:
  - "Several modular equations with several small unknowns"
  - "Your unknowns have very different sizes and LLL returns the wrong vector"
  - "You need the lattice point closest to a target, not the shortest vector"
  - "An HNP-style lattice 'almost' works and you suspect the weighting"
tools: [sage, fpylll, flatter, python]
related: [lattice-lll-fundamentals, lattice-hidden-number-problem, lattice-linear-relations, lattice-toolkit, lattice-cheatsheet]
---

## TL;DR

SVP asks for the shortest lattice vector; CVP asks for the lattice vector closest to a target
`t`. Babai's algorithms solve CVP approximately from an LLL basis (rounding: cheap and crude;
nearest-plane: better). Kannan's embedding converts CVP into SVP by appending the target as
an extra row. And the single most useful practical trick: **scale each column so that the
coordinates of the vector you want are all about the same size**, otherwise LLL optimises the
large coordinate and throws away the small one.

## Recognise it

- You have `k` congruences `sum_j a_{ij} x_j = c_i (mod n_i)` and the `x_j` are small.
- "The answer is almost right but one unknown is garbage."
- Your bounds differ by many orders of magnitude (`x < 2^16`, `y < 2^200`).
- The target of your lattice is a *shifted* short vector, not a short vector.

## Theory

**CVP.** Given a basis `B` and a target `t` in the span, find `v` in `L(B)` minimising
`||t - v||`. NP-hard exactly; we only need a good approximation.

**Babai rounding.** Solve `t = sum c_i b_i` over the rationals, round each `c_i` to the
nearest integer. Approximation factor is exponential and it is sensitive to how skewed the
basis is -- but with an LLL-reduced basis it is usually fine and it is two lines of code.

**Babai nearest plane.** Using the Gram-Schmidt vectors `b*_i`, work from `i = n` down to `1`:

$$c_i = \left\lceil \frac{\langle w, b^*_i \rangle}{\langle b^*_i, b^*_i \rangle} \right\rfloor,
\qquad w \leftarrow w - c_i b_i$$

Returns a vector within `2^{n/2}` of optimal from an LLL basis, and in practice far better
than rounding. Prefer it.

**Kannan embedding (CVP -> SVP).** Build the `(n+1) x (m+1)` matrix

$$B' = \begin{pmatrix} B & 0 \\ t & M \end{pmatrix}$$

with `M` roughly the expected distance `||t - v||`. Then `(t - v, M)` is a short vector of
`L(B')`, so an SVP/LLL call on `B'` solves the CVP. Choosing `M = 1` is standard when the
error is tiny; choose `M` near the error norm to avoid the trivial vector dominating.

**Modular equation systems as lattices.** For `sum_j a_j x_j = c (mod n)` with `|x_j| < X_j`:

rows `e_j` extended by `a_j` in a last column, one row `n` in that last column, and the target
`(0, ..., 0, c)`. The lattice point closest to the target is `(x_1, ..., x_k, c)` -- a CVP.
With the Kannan embedding it becomes the short vector `(x_1, ..., x_k, 0, -1)`.

**The scaling trick.** Suppose the target is `(x_1, ..., x_k)` with `|x_j| <= X_j`. LLL
minimises the Euclidean norm, which is dominated by the largest coordinate. Multiply column
`j` by

$$w_j = \frac{C}{X_j} \quad \text{for a common } C$$

so every coordinate of the (scaled) target is about `C`. Now the target really is the
shortest vector, instead of merely being short in one direction. Afterwards divide coordinate
`j` by `w_j` to recover `x_j`. Use integer weights (`C` a common multiple) so the lattice
stays integral.

The same reasoning explains the `K` and `nK` entries in the HNP basis and the `X^k` column
scaling in Coppersmith: they are all the same trick.

**How to tell scaling is your problem.** Compute the norm of the *expected* answer and
compare with the Gaussian heuristic. If the expected answer is longer than the heuristic in
the unscaled lattice but shorter in the scaled one, you found the bug.

## Attack

1. Write the system, list the bound `X_j` for each unknown.
2. Build the basis with one row per unknown, one row per modulus.
3. Scale column `j` by `C / X_j` with `C = lcm` or simply `C = prod X_j`.
4. Either Babai (nearest plane) against the scaled target, or Kannan-embed and LLL.
5. Unscale, verify in the original congruences.
6. If it fails: tighten bounds, add equations, switch to BKZ.

## Code

```python
#!/usr/bin/env python3
"""CVP by Babai and by Kannan embedding, and a demo where scaling decides success."""
from fractions import Fraction
import math
import random

def dot(u, v):
    return sum(a * b for a, b in zip(u, v))

def rnd(x):
    return int(x + Fraction(1, 2)) if x >= 0 else -int(-x + Fraction(1, 2))

def lll(basis, delta=Fraction(99, 100)):
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

def gram_schmidt(basis):
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

def babai_nearest_plane(basis, target):
    """Babai's nearest-plane CVP. Returns the closest lattice vector found."""
    b = lll(basis)
    bs, _ = gram_schmidt(b)
    w = [Fraction(x) for x in target]
    for i in reversed(range(len(b))):
        d = dot(bs[i], bs[i])
        c = 0 if d == 0 else rnd(dot(w, bs[i]) / d)
        w = [x - c * y for x, y in zip(w, b[i])]
    return [int(t - x) for t, x in zip(target, w)]

def babai_rounding(basis, target):
    """Cheaper CVP: express the target in the reduced basis and round."""
    b = lll(basis)
    n, m = len(b), len(target)
    A = [[Fraction(b[j][i]) for j in range(n)] + [Fraction(target[i])] for i in range(m)]
    piv = 0
    for col in range(n):
        r = next((i for i in range(piv, m) if A[i][col] != 0), None)
        if r is None:
            continue
        A[piv], A[r] = A[r], A[piv]
        inv = A[piv][col]
        A[piv] = [x / inv for x in A[piv]]
        for i in range(m):
            if i != piv and A[i][col] != 0:
                f = A[i][col]
                A[i] = [x - f * y for x, y in zip(A[i], A[piv])]
        piv += 1
    c = [rnd(A[i][n]) for i in range(n)]
    out = [0] * m
    for i in range(n):
        out = [o + c[i] * x for o, x in zip(out, b[i])]
    return out

def kannan_cvp(basis, target, M=None):
    """CVP by embedding: append (target, M) and look for a short vector.

    M must be comparable to the expected distance ||t - v||; with M far too small the
    reduction just recombines the target row and the embedding degenerates.
    """
    if M is None:
        v = babai_nearest_plane(basis, target)
        M = max(1, math.isqrt(sum((a - b) ** 2 for a, b in zip(target, v))))
    emb = [row + [0] for row in basis] + [list(target) + [M]]
    for row in lll(emb):
        if abs(row[-1]) != M:
            continue
        sign = 1 if row[-1] == M else -1
        diff = [sign * x for x in row[:-1]]
        return [t - d for t, d in zip(target, diff)]
    return None

def gaussian_heuristic(n, det):
    return math.sqrt(n / (2 * math.pi * math.e)) * det ** (1.0 / n)

def solve_modular(a, c, n, bounds, scale=True):
    """Find small x_j with sum a_j*x_j == c (mod n). Column scaling optional."""
    k = len(a)
    C = 1
    for X in bounds:
        C *= X
    w = [C // X for X in bounds] if scale else [1] * k
    # the embedding constant must match the expected size of the answer's coordinates,
    # otherwise LLL just reuses the target row and the embedding collapses
    M = max(wj * Xj for wj, Xj in zip(w, bounds))
    # the congruence column gets a big weight W so that a nonzero residual is never worth it
    W = M << 16
    rows = []
    for j in range(k):
        row = [0] * k + [a[j] * W]
        row[j] = w[j]
        rows.append(row)
    rows.append([0] * k + [n * W])
    target = [0] * k + [c * W]
    emb = [r + [0] for r in rows] + [target + [M]]
    for row in lll(emb):
        if abs(row[-1]) != M or row[-2] != 0:
            continue
        sign = 1 if row[-1] == -M else -1
        cand = []
        ok = True
        for j in range(k):
            v = sign * row[j]
            if v % w[j]:
                ok = False
                break
            cand.append(v // w[j])
        if ok and sum(ai * xi for ai, xi in zip(a, cand)) % n == c % n:
            if all(abs(x) <= b for x, b in zip(cand, bounds)):
                return cand
    return None

if __name__ == "__main__":
    rng = random.Random(12)

    # --- 1. Babai on a simple lattice ---
    B = [[7, 0, 0], [0, 11, 0], [0, 0, 13]]
    t = [10, 30, 6]
    np_ = babai_nearest_plane(B, t)
    assert np_ == [7, 33, 0], np_
    assert babai_rounding(B, t) == [7, 33, 0]
    assert kannan_cvp(B, t) == [7, 33, 0]
    print(f"[ok] CVP for {t}: nearest plane, rounding and Kannan all give {np_}")

    # --- 2. the scaling trick decides the outcome ---
    # one congruence a*x + b*y = c (mod n) with wildly different bounds
    n = (1 << 115) - 59
    X, Y = 1 << 20, 1 << 80
    x, y = rng.randrange(1, X), rng.randrange(1, Y)
    a, b = rng.randrange(1, n), rng.randrange(1, n)
    c = (a * x + b * y) % n

    unscaled = solve_modular([a, b], c, n, [X, Y], scale=False)
    scaled = solve_modular([a, b], c, n, [X, Y], scale=True)
    print(f"    unknowns: x < 2^{X.bit_length() - 1}, y < 2^{Y.bit_length() - 1}, "
          f"modulus 2^{n.bit_length()}")
    print(f"    without scaling -> {unscaled}")
    assert unscaled != [x, y], "this instance is meant to fail unscaled"
    assert scaled == [x, y], f"scaled solve failed: {scaled}"
    print(f"[ok] with column scaling -> recovered (x, y) exactly")

    # why: compare the target norm with the Gaussian heuristic in both lattices
    raw = math.hypot(x, y)
    gh_raw = gaussian_heuristic(2, float(n))
    C = X * Y
    wx, wy = C // X, C // Y
    sc = math.hypot(wx * x, wy * y)
    gh_sc = gaussian_heuristic(2, float(n) * wx * wy)
    print(f"    unscaled: target ~2^{math.log2(raw):.0f} vs heuristic "
          f"2^{math.log2(gh_raw):.0f} -> target is NOT the shortest vector")
    print(f"    scaled:   target ~2^{math.log2(sc):.0f} vs heuristic "
          f"2^{math.log2(gh_sc):.0f} -> target IS the shortest vector")

    # --- 3. a small system of two congruences, three unknowns ---
    n2 = (1 << 90) - 33
    bounds = [1 << 12, 1 << 12, 1 << 12]
    xs = [rng.randrange(1, Bd) for Bd in bounds]
    aa = [rng.randrange(1, n2) for _ in range(3)]
    cc = sum(ai * xi for ai, xi in zip(aa, xs)) % n2
    got = solve_modular(aa, cc, n2, bounds)
    assert got == xs, (got, xs)
    print(f"[ok] 3 balanced unknowns from 1 congruence mod 2^90: {got}")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Weights must be integers.** Use `C = prod X_j` (or an lcm) so `C / X_j` is an integer and
  the lattice stays in `ZZ`. Non-integer weights silently corrupt the lattice.
- **Unscale carefully.** After reduction, coordinate `j` is `w_j x_j`; if it is not divisible
  by `w_j`, that row is not your answer -- skip it.
- **Babai rounding vs nearest plane.** Rounding fails on skewed bases; if rounding gives a
  bad answer, try nearest plane before blaming the lattice.
- **Kannan `M`.** With `M = 1` the embedded vector is `(t - v, 1)`; if `||t - v||` is huge
  compared to 1, LLL may prefer a vector with last coordinate 0. Set `M` near the expected
  error.
- **Sign.** The embedding can return `-(t - v)`; handle both, as the code does.
- **Bounds that are too loose** inflate the weights and shrink the margin. Tighten them.
- **More equations than unknowns.** Add one modulus row per congruence and one extra column
  per congruence; scale each congruence column too if the moduli differ wildly.
- **Centre your unknowns.** If `0 <= x_j < X_j`, subtracting `X_j/2` halves the norm, exactly
  as in the HNP recentring trick.

## Tools

```python
# SageMath: CVP via the IntegerLattice helper (uses Babai internally)
from sage.modules.free_module_integer import IntegerLattice
L = IntegerLattice(Matrix(ZZ, rows))
print(L.closest_vector(vector(ZZ, target)))
```

```python
# fpylll: explicit Babai and CVP
from fpylll import IntegerMatrix, LLL, CVP, GSO
A = IntegerMatrix.from_matrix(rows)
LLL.reduction(A)
print(CVP.closest_vector(A, target))
M = GSO.Mat(A); M.update_gso()
print(M.babai(target))
```

## References

- Babai, "On Lovasz' lattice reduction and the nearest lattice point problem", Combinatorica 6 (1986)
- Kannan, "Minkowski's convex body theorem and integer programming", Math. of OR 12 (1987)
- Galbraith, *Mathematics of Public Key Cryptography*, chapter 18
- https://github.com/fplll/fpylll
