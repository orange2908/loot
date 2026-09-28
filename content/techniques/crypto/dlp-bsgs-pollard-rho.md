---
title: "DLP - Baby-Step Giant-Step, Pollard's Rho and Kangaroo"
category: crypto
subcategory: dlp
type: technique
tags: [dlp, discrete-log, discrete-logarithm, bsgs, baby-step-giant-step, pollard-rho, pollard-lambda, kangaroo, floyd-cycle, meet-in-the-middle, birthday, generic-algorithm, time-memory-tradeoff, sage, pari, python]
difficulty: medium
summary: "Generic square-root DLP algorithms: BSGS trades memory for time, rho needs none, kangaroo wins when the exponent is bounded."
when_to_use:
  - "You need a discrete log in a group of order up to roughly 2^60"
  - "Pohlig-Hellman left you with one prime-order subgroup to finish"
  - "The exponent is known to lie in a narrow interval (use kangaroo, not BSGS)"
  - "Memory is the constraint and you cannot store sqrt(n) elements"
tools: [sage, pari, python]
related: [dlp-pohlig-hellman, dlp-index-calculus, ecc-pohlig-hellman, dlp-diffie-hellman-attacks, ecc-toolkit]
---

## TL;DR

In a generic group of order `n` nothing beats `O(sqrt(n))`. Three ways to spend it:

| algorithm | time | memory | best for |
| --- | --- | --- | --- |
| baby-step giant-step | `sqrt(n)` | `sqrt(n)` | small `n`, you have RAM |
| Pollard's rho | `~1.25 sqrt(n)` | `O(1)` | large `n`, no RAM, parallelisable |
| Pollard's lambda (kangaroo) | `~2 sqrt(w)` | `O(1)` | exponent inside a width-`w` interval |

## Recognise it

- A prime-order subgroup of a few tens of bits survived Pohlig-Hellman.
- The challenge says "the secret is a 40-bit number" -- that is a kangaroo, not a `2^40` loop.
- `pow(g, x, p)` is given and `x` is described as "small" or "in this range".
- An elliptic curve subgroup with a 50-bit prime order.

## Theory

**Baby-step giant-step.** Write `x = i m + j` with `m = ceil(sqrt(n))`, `0 <= i, j < m`. Then
`h = g^x` gives `h g^{-i m} = g^j`. Store the `m` baby steps `g^j` in a hash table, then walk
the giant steps `h (g^{-m})^i` until one is in the table. Time and memory both `O(sqrt(n))`.
The memory is the problem: `2^40` group elements is not happening.

**Pollard's rho.** Define a pseudo-random walk on the group that also tracks the exponents:
partition the group into three parts `S_0, S_1, S_2` and set

$$x_{i+1} = \begin{cases} h x_i & x_i \in S_0 \\ x_i^2 & x_i \in S_1 \\ g x_i & x_i \in S_2 \end{cases}$$

carrying `a_i, b_i` with `x_i = g^{a_i} h^{b_i}`. The walk enters a cycle after about
`sqrt(pi n / 2)` steps (birthday bound); Floyd's tortoise-and-hare detects it with `O(1)`
memory. A collision `g^{a} h^{b} = g^{a'} h^{b'}` gives
`x = (a - a')(b' - b)^{-1} mod n`. If `b' - b` is not invertible, restart with a different
start point (or handle the small gcd by CRT).

The three-way partition is the textbook version; an *r-adding walk* with `r = 16..32`
precomputed multipliers mixes much better and is what real implementations use.

**Pollard's lambda / kangaroo.** When `x` is known to lie in `[a, b]` with width `w = b - a`,
you do not need `sqrt(n)`, only `sqrt(w)`. Run a "tame" kangaroo from `g^b` and a "wild" one
from `h`, both taking pseudo-random jumps of average size `sqrt(w)/2`, and store only
*distinguished points* (elements whose representation ends in `k` zero bits). When the wild
kangaroo lands on the tame trail, subtract the accumulated distances.

**Lower bound.** Shoup's theorem: any generic algorithm needs `Omega(sqrt(q))` group
operations for the largest prime factor `q` of `n`. If a challenge is solvable faster, the
group is not generic -- look for smooth order, index calculus, or a homomorphism.

## Attack

1. Determine the group order `n` and factor it. If smooth -> Pohlig-Hellman first.
2. For each prime-order piece, pick the algorithm from the table above.
3. BSGS if `sqrt(q)` elements fit in memory (rule of thumb: `q < 2^40`).
4. Rho if not, or if you can parallelise (`m` machines give a linear speedup with
   distinguished points).
5. Kangaroo if the exponent range is much smaller than the group.
6. CRT the residues.

## Code

```python
#!/usr/bin/env python3
"""BSGS, Pollard rho (Floyd and r-adding), and Pollard kangaroo for DLP in GF(p)^*."""
import hashlib
import random
from math import gcd, isqrt

def bsgs(g, h, n, p):
    """Solve g^x = h mod p for 0 <= x < n. O(sqrt(n)) time and memory."""
    m = isqrt(n - 1) + 1
    table, cur = {}, 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    factor = pow(g, -m, p)
    cur = h % p
    for i in range(m + 1):
        if cur in table:
            x = i * m + table[cur]
            if x < n and pow(g, x, p) == h % p:
                return x
        cur = cur * factor % p
    return None

def pollard_rho_floyd(g, h, n, p, tries=20):
    """Textbook three-partition rho with Floyd cycle finding. O(1) memory."""
    def step(x, a, b):
        if x % 3 == 0:
            return x * x % p, 2 * a % n, 2 * b % n
        if x % 3 == 1:
            return h * x % p, a, (b + 1) % n
        return g * x % p, (a + 1) % n, b

    for _ in range(tries):
        a0, b0 = random.randrange(n), random.randrange(n)
        x = pow(g, a0, p) * pow(h, b0, p) % p
        a, b = a0, b0
        X, A, B = x, a, b
        for _ in range(10 * isqrt(n) + 100):
            x, a, b = step(x, a, b)
            X, A, B = step(*step(X, A, B))
            if x == X:
                db = (b - B) % n
                if db == 0:
                    break
                d = gcd(db, n)
                if d == 1:
                    cand = (A - a) % n * pow(db, -1, n) % n
                    if pow(g, cand, p) == h % p:
                        return cand
                else:                       # partial information: lift the d solutions
                    base = (A - a) % n
                    if base % d:
                        break
                    m2 = n // d
                    c0 = (base // d) * pow(db // d, -1, m2) % m2
                    for t in range(d):
                        cand = (c0 + t * m2) % n
                        if pow(g, cand, p) == h % p:
                            return cand
                break
    return None

def pollard_rho_radding(g, h, n, p, r=20, tries=20):
    """r-adding walk: better mixing, the version real tools use."""
    exps = [(random.randrange(n), random.randrange(n)) for _ in range(r)]
    mult = [pow(g, ai, p) * pow(h, bi, p) % p for ai, bi in exps]
    idx = lambda x: int.from_bytes(hashlib.sha256(str(x).encode()).digest()[:4], "big") % r

    def step(x, a, b):
        i = idx(x)
        ai, bi = exps[i]
        return x * mult[i] % p, (a + ai) % n, (b + bi) % n

    for _ in range(tries):
        a0, b0 = random.randrange(n), random.randrange(n)
        x = pow(g, a0, p) * pow(h, b0, p) % p
        a, b = a0, b0
        X, A, B = x, a, b
        for _ in range(20 * isqrt(n) + 200):
            x, a, b = step(x, a, b)
            X, A, B = step(*step(X, A, B))
            if x == X:
                db = (b - B) % n
                if db and gcd(db, n) == 1:
                    cand = (A - a) % n * pow(db, -1, n) % n
                    if pow(g, cand, p) == h % p:
                        return cand
                break
    return None

def kangaroo(g, h, lo, hi, p, k=None, tries=8):
    """Pollard lambda: find x in [lo, hi] with g^x = h. O(sqrt(hi-lo))."""
    w = hi - lo
    if w <= 0:
        return None
    m = max(4, isqrt(w) // 2)
    jumps = [1 << i for i in range(m.bit_length())]
    mean = sum(jumps) // len(jumps)
    jump_of = lambda x: jumps[x % len(jumps)]
    steps = max(8, 4 * w // max(1, mean))
    for _ in range(tries):
        # tame kangaroo starts at the top of the interval
        tame_d = 0
        tame = pow(g, hi, p)
        trail = {}
        for _ in range(int(steps)):
            trail[tame] = tame_d
            j = jump_of(tame)
            tame = tame * pow(g, j, p) % p
            tame_d += j
        trail[tame] = tame_d
        # wild kangaroo starts at h
        wild_d = 0
        wild = h % p
        for _ in range(int(steps)):
            if wild in trail:
                x = hi + trail[wild] - wild_d
                if lo <= x <= hi and pow(g, x, p) == h % p:
                    return x
            j = jump_of(wild)
            wild = wild * pow(g, j, p) % p
            wild_d += j
        jumps = [j * 2 for j in jumps]      # retry with a coarser jump set
    return None

def is_prime(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for s in small:
        if n % s == 0:
            return n == s
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for a in small:
        y = pow(a, d, n)
        if y in (1, n - 1):
            continue
        for _ in range(r - 1):
            y = y * y % n
            if y == n - 1:
                break
        else:
            return False
    return True

if __name__ == "__main__":
    random.seed(17)

    # a prime p with a known 30-bit prime-order subgroup
    q = 1073741827                       # prime, ~2^30
    assert is_prime(q)
    k = 2
    while not is_prime(q * k + 1):
        k += 1
    p = q * k + 1
    g = pow(random.randrange(2, p - 1), (p - 1) // q, p)
    while g == 1:
        g = pow(random.randrange(2, p - 1), (p - 1) // q, p)
    assert pow(g, q, p) == 1
    print(f"[ok] p = {p} ({p.bit_length()} bits), subgroup order q = {q}")

    x = random.randrange(2, q)
    h = pow(g, x, p)

    got = bsgs(g, h, q, p)
    assert got == x
    print(f"[ok] BSGS solved a {q.bit_length()}-bit DLP: x = {x}")

    # rho on a smaller subgroup so the demo stays fast
    q2 = 1000003
    k2 = 2
    while not is_prime(q2 * k2 + 1):
        k2 += 1
    p2 = q2 * k2 + 1
    g2 = pow(5, (p2 - 1) // q2, p2)
    assert pow(g2, q2, p2) == 1 and g2 != 1
    x2 = random.randrange(2, q2)
    h2 = pow(g2, x2, p2)
    assert pollard_rho_floyd(g2, h2, q2, p2) == x2
    print(f"[ok] Pollard rho (Floyd) solved a {q2.bit_length()}-bit DLP with O(1) memory")
    assert pollard_rho_radding(g2, h2, q2, p2) == x2
    print("[ok] Pollard rho (r-adding walk) agreed")

    # kangaroo: 2^30 subgroup but the exponent is confined to a width-2^20 window
    lo = 700000000
    x3 = lo + random.randrange(1 << 20)
    h3 = pow(g, x3, p)
    got3 = kangaroo(g, h3, lo, lo + (1 << 20), p)
    assert got3 == x3, (got3, x3)
    print(f"[ok] kangaroo found x in a 2^20 window inside a 2^30 group: x = {x3}")
    print("all self-tests passed")
```

## Variants and pitfalls

- **BSGS memory.** `sqrt(2^50)` entries is 33 million dict entries: several GB in Python.
  Switch to rho well before that, or shard the baby-step table.
- **BSGS on a non-generator.** If `ord(g) < n` the table simply never matches. Compute the
  real order first.
- **Rho and non-invertible `b' - b`.** Happens when `n` is composite. The code above lifts
  the `d = gcd` candidates; the cleaner fix is to run Pohlig-Hellman first so every rho call
  sees a prime-order group.
- **Rho that never collides.** The three-way partition mixes badly for some groups; use the
  r-adding walk. Also re-randomise the start point between attempts.
- **Kangaroo jump sizes.** The mean jump must be about `sqrt(w)/2`. Too small and the tame
  trail is too short; too large and the wild kangaroo jumps over it. The code retries with
  doubled jumps.
- **Kangaroo interval must actually contain `x`.** If it does not, it silently fails; widen
  and retry rather than concluding the instance is hard.
- **Parallel rho.** With `m` cores, use distinguished points (e.g. elements whose low 20 bits
  are zero), report them to a central table, and you get a full `m`-fold speedup. That is how
  record DLP computations in small groups are done.
- **Elliptic curves.** All three algorithms are identical with `*` replaced by `+`; see
  `ecc-pohlig-hellman` and `ecc-toolkit`.

## Tools

```python
# SageMath: pick the algorithm explicitly
F = GF(p)
print(discrete_log(F(h), F(g), ord=q))                 # generic, uses Pohlig-Hellman + BSGS
print(bsgs(F(g), F(h), (0, q - 1))          # from sage.groups.generic import bsgs)                    # explicit BSGS
print(discrete_log_rho(F(h), F(g), ord=q)                      # ord must be PRIME)             # explicit rho
print(discrete_log_lambda(F(h), F(g), (lo, hi)))       # kangaroo over an interval
```

```sh
# PARI/GP: znlog is BSGS/Pohlig-Hellman under the hood
gp -q -c 'p=...; g=Mod(...,p); h=Mod(...,p); print(znlog(h,g))'
```

## References

- Shanks, "Class number, a theory of factorization, and genera" (1971) -- baby-step giant-step
- Pollard, "Monte Carlo methods for index computation (mod p)", Math. Comp. 32 (1978)
- van Oorschot, Wiener, "Parallel collision search with cryptanalytic applications" (1999)
- https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html
