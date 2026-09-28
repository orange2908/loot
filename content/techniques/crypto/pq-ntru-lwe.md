---
title: "Post-Quantum - NTRU and LWE in CTFs: Parameter Smells and Lattice Attacks"
category: crypto
subcategory: pq
type: technique
tags: [post-quantum, pqc, ntru, lwe, rlwe, kyber, lattice, lll, lattice-reduction, bkz, bdd, primal-attack, dual-attack, binary-secret, arora-ge, linear-algebra, coppersmith-shamir, fpylll, sage, python]
difficulty: hard
summary: "Toy NTRU and LWE parameters fall to one LLL call. Learn the smells: tiny n, small q/error ratio, no noise, binary secrets, too many samples."
when_to_use:
  - "A challenge implements 'post-quantum' encryption with hand-picked small parameters"
  - "You see a public key that is a ratio of small polynomials modulo q"
  - "An LWE instance has no error, a binary secret, or far more samples than dimensions"
  - "Kyber/NTRU-like code with n < 64 or q < 2^16"
tools: [sage, fpylll, flatter, python]
related: [lattice-lll-fundamentals, lattice-cvp-babai-scaling, pq-isogeny-sidh, lattice-toolkit, lattice-cheatsheet]
---

## TL;DR

Real NTRU and Kyber are fine. CTF versions are not: their parameters are shrunk so the
challenge runs in a script, which puts the secret inside LLL range. NTRU's public key is a
ratio of two short polynomials, so `(f, g)` is a short vector of an explicit `2N`-dimensional
lattice. LWE is bounded-distance decoding: the secret is a lattice point close to `b`. And
if the error is zero, or the secret is binary with enough samples, plain linear algebra wins.

## Recognise it

**Parameter smells.**

| smell | why it breaks |
| --- | --- |
| `n < 64` (LWE) or `N < 64` (NTRU) | LLL/BKZ handle dimension `2N` directly |
| error `e` with `|e| <= 1` and `q` small | BDD distance is tiny relative to `det^{1/n}` |
| no error at all | it is a linear system mod `q`; Gaussian elimination |
| secret in `{0,1}^n` or `{-1,0,1}^n` | secret itself is short: put it in the lattice |
| many more samples `m` than `n` | more rows, better lattice, and Arora-Ge becomes possible |
| the same randomness reused for two ciphertexts | subtract them, the error cancels partly |
| `q` a prime you can factor the ring modulus over | RLWE splits by CRT into small pieces |

## Theory

**LWE.** Public `A` in `Z_q^{m x n}` and `b = A s + e mod q` with `e` small. Recovering `s`
is bounded-distance decoding in the `q`-ary lattice

$$\Lambda_q(A) = \{ y \in \mathbb{Z}^m : y \equiv A x \pmod q \text{ for some } x \}$$

`b` lies within `||e||` of the lattice point `A s`. Run Babai/LLL (the *primal* attack) to get
the closest vector, subtract to get `e`, then solve `A s = b - e (mod q)` by linear algebra.
The attack succeeds when `||e|| << det(Lambda)^{1/m} = q^{(m-n)/m}` -- which is exactly why
small `q` and small error are fatal.

A **basis** for `Lambda_q(A)` when the top `n x n` block `A_1` is invertible mod `q`: write
`B = A_2 A_1^{-1} mod q` and take the rows

$$\begin{pmatrix} I_n & B^T \\ 0 & q I_{m-n} \end{pmatrix}$$

**Dual attack.** Find short `v` with `v^T A = 0 (mod q)`; then `v^T b = v^T e` is small,
distinguishing LWE from uniform. Used for distinguishing, and for key recovery with many
short duals.

**No error.** `b = A s mod q` with `m >= n` is a linear system. Gaussian elimination mod `q`
(prime) or Smith normal form (composite) recovers `s`. This is the single most common CTF
"post-quantum" bug.

**Arora-Ge / linearisation.** If the error is bounded by `B` and you have enough samples,
each sample gives the polynomial equation `prod_{j=-B}^{B} (b_i - <a_i, s> - j) = 0`, which
linearises to a solvable system when `m` is about `n^{2B+1}`. Practical only for tiny `B`.

**NTRU.** Ring `R = Z[x]/(x^N - 1)`. Private: short `f, g` (ternary). Public:
`h = f^{-1} g mod q`. Then `f h = g (mod q)`, i.e.

$$(f, g) \cdot \begin{pmatrix} I_N & H \\ 0 & q I_N \end{pmatrix} \text{-lattice contains } (f, g)$$

where `H` is the circulant matrix of `h`. This is the **Coppersmith-Shamir** lattice: it has
dimension `2N`, determinant `q^N`, so the Gaussian heuristic gives
`sqrt(2N/(2 pi e)) sqrt(q)`, while `(f, g)` has norm about `sqrt(2N * 2/3)` for ternary
coefficients. Short enough whenever `q` is not tiny -- and every rotation `(x^i f, x^i g)` is
also a solution, so there are `2N` targets, which makes LLL's job even easier.

Real NTRU uses `N = 509..821` and relies on `2N ~ 1000+` being out of BKZ range. A CTF `N`
of 11-64 is broken by a single LLL call.

## Attack

1. Identify the scheme and read off `n`/`N`, `q`, the error/ternary bounds.
2. LWE with no error -> Gaussian elimination mod `q`.
3. LWE with error -> build `Lambda_q(A)`, Babai against `b`, recover `e` then `s`.
4. Binary/ternary secret -> put `s` in the lattice too (one column per secret coordinate,
   scaled), which shortens the target a lot.
5. NTRU -> Coppersmith-Shamir lattice, LLL, scan rows for a ternary `(f, g)` pair.
6. Verify by decrypting a known ciphertext.

## Code

```python
#!/usr/bin/env python3
"""Toy LWE and NTRU broken with a hand-rolled LLL: no fpylll, no Sage."""
from fractions import Fraction
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

def babai(basis, target):
    b = lll(basis)
    bs, _ = gram_schmidt(b)
    w = [Fraction(x) for x in target]
    for i in reversed(range(len(b))):
        d = dot(bs[i], bs[i])
        c = 0 if d == 0 else rnd(dot(w, bs[i]) / d)
        w = [x - c * y for x, y in zip(w, b[i])]
    return [int(t - x) for t, x in zip(target, w)]

# ---- linear algebra mod a prime q ---------------------------------------

def solve_mod(A, b, q):
    """Solve A x = b (mod q) for prime q. Returns one solution or None."""
    m, n = len(A), len(A[0])
    M = [row[:] + [bi] for row, bi in zip(A, b)]
    piv = {}
    r = 0
    for c in range(n):
        pr = next((i for i in range(r, m) if M[i][c] % q), None)
        if pr is None:
            continue
        M[r], M[pr] = M[pr], M[r]
        inv = pow(M[r][c], -1, q)
        M[r] = [v * inv % q for v in M[r]]
        for i in range(m):
            if i != r and M[i][c] % q:
                f = M[i][c]
                M[i] = [(v - f * w) % q for v, w in zip(M[i], M[r])]
        piv[c] = r
        r += 1
    x = [0] * n
    for c, rr in piv.items():
        x[c] = M[rr][n] % q
    for row, bi in zip(A, b):
        if sum(a * xi for a, xi in zip(row, x)) % q != bi % q:
            return None
    return x

def mat_inv_mod(A, q):
    """Inverse of a square matrix mod prime q, or None."""
    n = len(A)
    M = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(A)]
    for c in range(n):
        pr = next((i for i in range(c, n) if M[i][c] % q), None)
        if pr is None:
            return None
        M[c], M[pr] = M[pr], M[c]
        inv = pow(M[c][c], -1, q)
        M[c] = [v * inv % q for v in M[c]]
        for i in range(n):
            if i != c and M[i][c] % q:
                f = M[i][c]
                M[i] = [(v - f * w) % q for v, w in zip(M[i], M[c])]
    return [row[n:] for row in M]

def centre(v, q):
    return [(x + q // 2) % q - q // 2 for x in v]

# ---- LWE ----------------------------------------------------------------

def lwe_sample(n, m, q, err, rng, secret=None):
    s = secret or [rng.randrange(q) for _ in range(n)]
    A = [[rng.randrange(q) for _ in range(n)] for _ in range(m)]
    e = [rng.randrange(-err, err + 1) for _ in range(m)]
    b = [(dot(row, s) + ei) % q for row, ei in zip(A, e)]
    return A, b, s, e

def qary_basis(A, q):
    """Basis of {y : y = A x mod q}, assuming the top n x n block is invertible."""
    m, n = len(A), len(A[0])
    A1 = [row[:] for row in A[:n]]
    inv = mat_inv_mod(A1, q)
    if inv is None:
        return None
    # y2 = A2 * A1^{-1} * y1 (mod q); rows: (e_i | column i of that product)
    prod = [[sum(A[n + r][k] * inv[k][i] for k in range(n)) % q for i in range(n)]
            for r in range(m - n)]
    rows = []
    for i in range(n):
        rows.append([1 if j == i else 0 for j in range(n)] + [prod[r][i] for r in range(m - n)])
    for r in range(m - n):
        rows.append([0] * n + [q if j == r else 0 for j in range(m - n)])
    return rows

def break_lwe(A, b, q):
    """Primal/BDD attack: Babai on the q-ary lattice, then solve for s."""
    basis = qary_basis(A, q)
    if basis is None:
        return None
    v = babai(basis, b)
    e = centre([bi - vi for bi, vi in zip(b, v)], q)
    return solve_mod(A, [(bi - ei) % q for bi, ei in zip(b, e)], q), e

# ---- NTRU ---------------------------------------------------------------

def poly_mul(f, g, N, q):
    out = [0] * N
    for i, a in enumerate(f):
        if a:
            for j, bb in enumerate(g):
                out[(i + j) % N] = (out[(i + j) % N] + a * bb) % q
    return out

def circulant(h, N):
    """Matrix C with (f * h)_k = sum_i f_i * C[i][k]."""
    return [[h[(k - i) % N] for k in range(N)] for i in range(N)]

def ternary(N, ones, minus, rng):
    """A ternary polynomial with `ones` coefficients +1 and `minus` coefficients -1."""
    v = [0] * N
    idx = rng.sample(range(N), ones + minus)
    for i in idx[:ones]:
        v[i] = 1
    for i in idx[ones:]:
        v[i] = -1
    return v

def ntru_keygen(N, q, rng):
    d = N // 3
    while True:
        # f must be invertible: give it one more +1 than -1 so that f(1) != 0
        f = ternary(N, d + 1, d, rng)
        g = ternary(N, d, d, rng)
        Cf = circulant([x % q for x in f], N)
        inv = mat_inv_mod(Cf, q)
        if inv is None:
            continue
        # h = f^{-1} * g : solve (h * f) = g, i.e. h = g * Cf^{-1}
        h = [sum(g[i] * inv[i][k] for i in range(N)) % q for k in range(N)]
        if poly_mul(f, h, N, q) == [x % q for x in g]:
            return h, f, g

def break_ntru(h, N, q):
    """Coppersmith-Shamir lattice: rows (I | circ(h)) and (0 | qI)."""
    C = circulant(h, N)
    rows = []
    for i in range(N):
        rows.append([1 if j == i else 0 for j in range(N)] + C[i])
    for i in range(N):
        rows.append([0] * N + [q if j == i else 0 for j in range(N)])
    for row in lll(rows):
        for v in (row, [-x for x in row]):
            f = v[:N]
            g = centre(v[N:], q)
            if any(f) and all(abs(x) <= 1 for x in f) and all(abs(x) <= 1 for x in g):
                if centre(poly_mul(f, h, N, q), q) == g:
                    return f, g
    return None

if __name__ == "__main__":
    rng = random.Random(2024)

    # --- 1. LWE with NO error: it is just linear algebra ---
    q = 1021
    A, b, s, _ = lwe_sample(10, 14, q, 0, rng)
    assert solve_mod(A, b, q) == s
    print("[ok] noiseless LWE: Gaussian elimination mod q recovers the secret instantly")

    # --- 2. LWE with small error: primal/BDD attack ---
    n, m, q, err = 6, 18, 97, 1
    A, b, s, e = lwe_sample(n, m, q, err, rng)
    got, e_rec = break_lwe(A, b, q)
    assert got == s, (got, s)
    assert e_rec == e, (e_rec, e)
    print(f"[ok] LWE n={n}, m={m}, q={q}, |e|<={err}: secret and error both recovered")
    print(f"    q^((m-n)/m) = {q ** ((m - n) / m):.0f} vs ||e|| ~ {sum(x * x for x in e) ** 0.5:.1f}"
          " -- BDD distance far below the lattice scale")

    # --- 3. toy NTRU ---
    N, qn = 11, 127
    h, f, g = ntru_keygen(N, qn, rng)
    assert centre(poly_mul(f, h, N, qn), qn) == [x for x in g]
    rec = break_ntru(h, N, qn)
    assert rec is not None
    f2, g2 = rec
    assert centre(poly_mul(f2, h, N, qn), qn) == g2
    print(f"[ok] NTRU N={N}, q={qn}: recovered a valid short (f, g) from the public key alone")
    rot = any(f2 == [f[(i - k) % N] for i in range(N)] or
              f2 == [-f[(i - k) % N] for i in range(N)] for k in range(N))
    print(f"    it is the original key up to rotation/sign: {rot}; either way f2*h = g2 "
          "with both ternary, which is all decryption needs")
    print("all self-tests passed")
```

## Variants and pitfalls

- **`A_1` not invertible.** Permute the rows of `A` (and `b`) until the top `n x n` block is
  invertible mod `q`, or pick a different subset of samples.
- **Composite `q`.** `mat_inv_mod` needs a prime. For `q = 2^k` use Hensel lifting or work
  modulo each prime power and CRT.
- **Secret not in `[0, q)` but binary.** Then `s` is itself short: extend the lattice with one
  column per secret coordinate, scaled by `q/2` relative to the error columns. It roughly
  halves the required dimension.
- **RLWE / module-LWE.** Everything lives in `Z_q[x]/(x^n + 1)`. If `x^n + 1` factors mod `q`,
  CRT the problem into small pieces and attack each. If the challenge uses `x^n - 1` (as toy
  NTRU does) the factor `x - 1` always splits off.
- **NTRU rotations.** Any `(x^i f, x^i g)` decrypts just as well. Do not insist on matching the
  original `f`; check that decryption works.
- **`q` too small in NTRU.** Decryption failures appear; the challenge may quietly rely on
  them. Verify with a known plaintext.
- **Dimension.** `2N = 128` with a pure-Python LLL is hours. Use `fpylll` (`BKZ` block 20-40)
  or `flatter`; `2N` up to ~250 is still feasible on a laptop.
- **Do not attack real parameters.** Kyber-512 and NTRU-HPS-2048-509 are not falling to your
  laptop. If the parameters are real, the bug is elsewhere: reused randomness, a decryption
  oracle (chosen-ciphertext against a non-FO-transformed scheme), or a side channel.

## Tools

```python
# SageMath: q-ary lattices and BKZ
A = Matrix(GF(q), m, n, entries)
B = block_matrix(ZZ, [[identity_matrix(n), A2 * A1.inverse()], [0, q * identity_matrix(m - n)]])
R = B.BKZ(block_size=30)
# NTRU:
H = Matrix(ZZ, N, N, [[h[(k - i) % N] for k in range(N)] for i in range(N)])
M = block_matrix(ZZ, [[identity_matrix(N), H], [0, q * identity_matrix(N)]])
print(M.LLL()[0])
```

```python
# fpylll with a BKZ auto-tuner for larger instances
from fpylll import IntegerMatrix, BKZ
from fpylll.algorithms.bkz2 import BKZReduction
A = IntegerMatrix.from_matrix(rows)
BKZReduction(A)(BKZ.Param(block_size=40, max_loops=8))
```

## References

- Regev, "On lattices, learning with errors, random linear codes, and cryptography" (STOC 2005)
- Hoffstein, Pipher, Silverman, "NTRU: A ring-based public key cryptosystem" (ANTS 1998)
- Coppersmith, Shamir, "Lattice attacks on NTRU" (EUROCRYPT 1997)
- Albrecht, Player, Scott, "On the concrete hardness of Learning with Errors", J. Math. Cryptology 9 (2015)
- https://github.com/fplll/fpylll
