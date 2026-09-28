---
title: "Lattices - Truncated LCGs and Linear-Relation Recovery with LLL"
category: crypto
subcategory: lattice
type: technique
tags: [lattice, lll, lattice-reduction, cvp, babai, lcg, truncated-lcg, prng, state-recovery, linear-congruential-generator, integer-relation, gcd, modulus-recovery, frieze-hastad, hnp, sage, fpylll, python]
difficulty: medium
summary: "Truncated LCG outputs are a CVP: Babai recovers the state. Unknown a, c, m come out of gcds of determinants. Same lattice finds any small integer relation."
when_to_use:
  - "A PRNG publishes only the high bits of its internal state"
  - "random numbers come from a hand-rolled LCG and you have a few outputs"
  - "You need to recover the modulus/multiplier/increment from raw outputs"
  - "You suspect a small integer linear relation between published values"
tools: [sage, fpylll, python]
related: [lattice-hidden-number-problem, lattice-cvp-babai-scaling, lattice-lll-fundamentals, ecdsa-weak-k-derivation, lattice-toolkit]
---

## TL;DR

An LCG is `s_{i+1} = a s_i + c mod m`. If you see the whole state, three outputs recover
`a` and `c`, and six recover `m` too, all with gcds. If you only see the top bits, the hidden
low bits are a *closest vector* problem: build the `A_i = a^i` lattice, run Babai, done. The
same machinery finds any unknown small integer combination.

## Recognise it

- `class LCG:` / `seed = (a * seed + c) % m` in the source.
- Outputs are `state >> k` or `state // 2**k` or `state % 2**32` of a 64-bit state.
- `random.seed` replaced by a homemade generator "for speed".
- You are asked for the next output, or for the seed, and only a handful of outputs exist.
- Java `java.util.Random` (48-bit LCG returning the top 32 bits) -- the textbook case.

## Theory

**Full-output LCG, unknown parameters.** Let `s_0, s_1, ...` be consecutive states and
`t_i = s_{i+1} - s_i`. Then `t_{i+1} = a t_i mod m`, so

$$u_i = t_{i+2} t_i - t_{i+1}^2 \equiv 0 \pmod m$$

`m = gcd(u_0, u_1, ...)` up to a small factor (strip tiny cofactors and sanity-check).
Then `a = t_1 t_0^{-1} mod m` and `c = s_1 - a s_0 mod m`. Six outputs are usually enough.

**Truncated outputs.** Suppose `s_i = y_i 2^k + l_i` with `y_i` published and `0 <= l_i < 2^k`
unknown. Unroll the recurrence:

$$s_i \equiv A_i s_0 + B_i \pmod m, \quad A_i = a^i, \quad B_{i+1} = a B_i + c,\ B_0 = 0$$

Substituting `s_i = y_i 2^k + l_i` and writing everything in terms of `l_0`:

$$l_i \equiv A_i l_0 + \underbrace{\left(A_i y_0 2^k + B_i - y_i 2^k\right)}_{=: C_i} \pmod m$$

So we need `l_0` such that `A_i l_0 + C_i mod m` is small for every `i`. Consider the lattice

$$L = \text{rowspan} \begin{pmatrix}
1 & A_1 & A_2 & \cdots & A_{t-1} \\
0 & m & & & \\
0 & & m & & \\
& & & \ddots & \\
0 & & & & m
\end{pmatrix}$$

and the target `(0, -C_1, ..., -C_{t-1})`. The lattice vector closest to that target differs
from it by exactly `(l_0, l_1, ..., l_{t-1})`, which is tiny. Babai's nearest plane returns
it. `det(L) = m^{t-1}` in dimension `t`, so the heuristic shortest vector is about
`m^{(t-1)/t}`; the attack works when `2^k sqrt(t) << m^{(t-1)/t}`, i.e. when the *total*
number of published bits exceeds the state size with some margin.

**Why CVP and not HNP here.** The HNP basis inverts the bound modulo `n`. For an LCG with
`m = 2^64` (the usual choice) that inverse does not exist. The CVP formulation never inverts
anything, so it works for any modulus, prime or not.

**Integer relation finding.** Given reals/integers `v_1, ..., v_n` suspected to satisfy
`sum e_i v_i = 0` (or `= S`) with small `e_i`, reduce

$$\begin{pmatrix} I_n & K v \end{pmatrix}$$

and read `e` off a row whose last coordinate vanishes. With `K` large this is the same
trick as the knapsack lattice, and it is how you spot "the flag is a small combination of
these published numbers" challenges.

## Attack

1. Decide what you know: full outputs or truncated? parameters known or not?
2. Full outputs, unknown params: gcd of `t_{i+2} t_i - t_{i+1}^2`, then `a`, then `c`.
3. Truncated, known params: build `A_i`, `C_i`, do the CVP with Babai.
4. Truncated, unknown params: recover the parameters from any full outputs you can get, or
   brute-force `a` if the modulus is small; otherwise this is genuinely hard.
5. Verify by predicting the next output and comparing.

## Code

```python
#!/usr/bin/env python3
"""LCG attacks: parameter recovery by gcd, truncated-state recovery by Babai CVP."""
from fractions import Fraction
from math import gcd
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
    b = lll(basis)
    bs, _ = gram_schmidt(b)
    w = [Fraction(x) for x in target]
    for i in reversed(range(len(b))):
        d = dot(bs[i], bs[i])
        c = 0 if d == 0 else rnd(dot(w, bs[i]) / d)
        w = [x - c * y for x, y in zip(w, b[i])]
    return [int(t - x) for t, x in zip(target, w)]

# ---- the LCG itself -----------------------------------------------------

class LCG:
    def __init__(self, a, c, m, seed):
        self.a, self.c, self.m, self.s = a, c, m, seed

    def next(self):
        self.s = (self.a * self.s + self.c) % self.m
        return self.s

# ---- 1. full outputs, unknown a, c, m ----------------------------------

def recover_lcg_params(states):
    """From >= 6 consecutive full states, recover (m, a, c)."""
    t = [states[i + 1] - states[i] for i in range(len(states) - 1)]
    zeros = [t[i + 2] * t[i] - t[i + 1] * t[i + 1] for i in range(len(t) - 2)]
    m = 0
    for z in zeros:
        m = gcd(m, z)
    m = abs(m)
    # the gcd can be a small multiple of m; strip factors while the recurrence still holds
    def consistent(mod):
        if mod <= max(states):
            return False
        aa = t[1] % mod * pow(t[0] % mod, -1, mod) % mod
        cc = (states[1] - aa * states[0]) % mod
        return all((aa * states[i] + cc) % mod == states[i + 1] for i in range(len(states) - 1))
    for small in (2, 3, 5, 7, 11, 13):
        while m % small == 0 and consistent(m // small):
            m //= small
    a = t[1] % m * pow(t[0] % m, -1, m) % m
    c = (states[1] - a * states[0]) % m
    return m, a, c

# ---- 2. truncated outputs, known a, c, m -------------------------------

def recover_truncated_lcg(highs, a, c, m, hidden):
    """highs[i] = s_i >> hidden. Returns the full states."""
    t = len(highs)
    A, B = [1], [0]
    for i in range(1, t):
        A.append(A[-1] * a % m)
        B.append((B[-1] * a + c) % m)
    twok = 1 << hidden
    C = [(A[i] * highs[0] * twok + B[i] - highs[i] * twok) % m for i in range(t)]
    basis = [[0] * t for _ in range(t)]
    basis[0][0] = 1
    for i in range(1, t):
        basis[0][i] = A[i]
        basis[i][i] = m
    target = [0] + [-C[i] for i in range(1, t)]
    close = babai_nearest_plane(basis, target)
    l0 = (close[0] - target[0]) % m          # close - target == (l_0, l_1, ..., l_{t-1})
    s0 = highs[0] * twok + l0
    out, s = [s0], s0
    for _ in range(t - 1):
        s = (a * s + c) % m
        out.append(s)
    return out

# ---- 3. small integer relation ------------------------------------------

def small_relation(values, total, bound):
    """Find small e with sum e_i * values_i == total, |e_i| <= bound."""
    n = len(values)
    K = max(abs(v) for v in values) * (bound + 1) * (n + 1)
    rows = []
    for i in range(n):
        row = [0] * (n + 1) + [K * values[i]]
        row[i] = 1
        rows.append(row)
    rows.append([0] * n + [bound, K * total])
    for row in lll(rows):
        if row[-1] != 0 or abs(row[-2]) != bound:
            continue
        sign = 1 if row[-2] == -bound else -1
        e = [sign * row[i] for i in range(n)]
        if all(abs(x) <= bound for x in e) and sum(x * v for x, v in zip(e, values)) == total:
            return e
    return None

if __name__ == "__main__":
    rng = random.Random(6)

    # --- 1. recover a, c, m from full outputs ---
    m_true = (1 << 48) - 59
    a_true, c_true = rng.randrange(2, m_true), rng.randrange(1, m_true)
    g = LCG(a_true, c_true, m_true, rng.randrange(1, m_true))
    states = [g.next() for _ in range(8)]
    m_r, a_r, c_r = recover_lcg_params(states)
    assert (m_r, a_r, c_r) == (m_true, a_true, c_true), (m_r, a_r, c_r)
    print(f"[ok] recovered m, a, c from 8 full outputs (m = {m_r})")
    g2 = LCG(a_r, c_r, m_r, states[-1])
    assert g2.next() == (a_true * states[-1] + c_true) % m_true
    print("[ok] predicted the next output")

    # --- 2. truncated LCG: only the top bits are published ---
    m = (1 << 64) - 59
    a, c = rng.randrange(2, m), rng.randrange(1, m)
    seed = rng.randrange(1, m)
    hidden, t = 24, 8
    gen = LCG(a, c, m, seed)
    full = [gen.next() for _ in range(t)]
    highs = [s >> hidden for s in full]
    print(f"[ok] LCG state is 64 bits; only the top {64 - hidden} bits of each output "
          f"are published")
    rec = recover_truncated_lcg(highs, a, c, m, hidden)
    assert rec == full, (rec[:2], full[:2])
    print(f"[ok] recovered all {t} full states, including the {hidden} hidden low bits")
    nxt = (a * rec[-1] + c) % m
    assert nxt == LCG(a, c, m, full[-1]).next()
    print("[ok] next state predicted exactly")

    # --- 3. a small integer relation among published values ---
    vals = [rng.randrange(1 << 100, 1 << 101) for _ in range(6)]
    secret = [rng.randrange(-20, 21) for _ in range(6)]
    total = sum(e * v for e, v in zip(secret, vals))
    got = small_relation(vals, total, 32)
    assert got is not None and sum(x * v for x, v in zip(got, vals)) == total
    print(f"[ok] found a small integer relation {got} (true {secret})")
    print("all self-tests passed")
```

## Variants and pitfalls

- **`m` a power of two.** Very common (`2^32`, `2^48`, `2^64`). The CVP formulation above
  handles it; the HNP/inverse-based one does not.
- **Low bits of a power-of-two LCG are weak anyway.** Bit `j` of the state has period at most
  `2^{j+1}`, so if the *low* bits are published you can often solve bit by bit with no
  lattice at all.
- **`java.util.Random`.** `m = 2^48`, `a = 0x5DEECE66D`, `c = 0xB`, and `next(32)` returns the
  top 32 bits. Two consecutive outputs plus a `2^16` brute force recover the seed without any
  lattice; more outputs make it instant.
- **gcd gives a multiple of `m`.** Use more outputs, and strip small factors. Sanity-check by
  verifying the recurrence on all known states.
- **`t_0` not invertible mod `m`.** Pick another index, or divide out the common factor.
- **Not enough truncated outputs.** You need `t * (published bits) > log2(m)` with margin,
  same rule as HNP. With 8 bits published per output and a 64-bit state, use 12-16 outputs.
- **Babai returned garbage.** Check the basis orientation (row 0 must be the `A_i` row) and
  that `C_i` was reduced mod `m`. Then try Kannan embedding + LLL instead.
- **Non-linear generators.** A quadratic or truncated-MT generator does not reduce to this
  lattice. For Mersenne Twister use state recovery from 624 outputs (`randcrack`).

## Tools

```python
# SageMath: truncated LCG in a few lines
M = Matrix(ZZ, t, t)
M[0, 0] = 1
for i in range(1, t):
    M[0, i] = A[i]
    M[i, i] = m
from sage.modules.free_module_integer import IntegerLattice
L = IntegerLattice(M)
close = L.closest_vector(vector(ZZ, target))
print([tt - cc for tt, cc in zip(target, close)])
```

```sh
# Mersenne Twister, not an LCG: clone the generator from 624 outputs
pip install randcrack
```

## References

- Frieze, Hastad, Kannan, Lagarias, Shamir, "Reconstructing truncated integer variables satisfying linear congruences", SIAM J. Comput. 17 (1988)
- Boyar, "Inferring sequences produced by pseudo-random number generators", JACM 36 (1989)
- https://en.wikipedia.org/wiki/Linear_congruential_generator
- https://docs.oracle.com/javase/8/docs/api/java/util/Random.html (the 48-bit LCG spec)
