---
title: "LCG - Recovering the Multiplier, Increment and Modulus from Outputs"
category: crypto
subcategory: prng
type: technique
tags: [lcg, linear-congruential-generator, prng, modulus-recovery, gcd, multiplier, increment, seed-recovery, java-random, glibc-rand, msvc-rand, mmix, numerical-recipes, truncated-lcg, lattice, sympy, prng-cracking]
difficulty: medium
summary: "Six consecutive outputs are enough: differences of differences are multiples of m, so gcd them to get m, then solve two linear equations for a and c."
when_to_use:
  - "Source shows `state = (a * state + c) % m` or a 48/64-bit multiply-add"
  - "Outputs are full-width integers from an unknown generator you can sample freely"
  - "A token stream where consecutive values are related by a fixed affine map"
  - "The generator is Java `Random`, MSVC `rand`, `drand48`, or a homemade 'crypto'"
tools: [python, sympy, sage, z3]
related: [prng-truncated-lcg-lattice, prng-java-random, prng-glibc-rand, prng-toolkit, prng-cheatsheet]
---

## TL;DR

An LCG is $s_{n+1} = a s_n + c \bmod m$. With consecutive **full-width** outputs:
- know $m$, $a$, $c$ -> you already have it;
- know $m$ only -> 3 outputs give $a$ and $c$ by solving a 2x2 linear system;
- know nothing -> ~6-8 outputs give $m$ as the gcd of $t_{i+2}t_i - t_{i+1}^2$ where
  $t_i = s_{i+1} - s_i$, then fall back to the previous case.

If the outputs are **truncated** (only the high bits are published, as in Java and
`rand()`), this arithmetic fails and you need lattice reduction - see
`prng-truncated-lcg-lattice`.

## Recognise it

- Source with `% 2**31`, `% 2**32`, `% 2**48`, `0x5DEECE66D`, `1103515245`,
  `6364136223846793005`, `214013`, `22695477`.
- A stream where `(s2 - s1) * inverse(s1 - s0)` is constant mod some number.
- Extremely short period or visible lattice structure when you plot pairs
  $(s_i, s_{i+1})$ - LCGs fall on a small number of hyperplanes ("Marsaglia's
  theorem"), which is a classic plot-based tell.
- The low bits cycle with a tiny period: for power-of-two $m$, bit $k$ of the state has
  period at most $2^{k+1}$. Bit 0 alternates.

## Theory

**The recurrence.** $s_{n+1} = a s_n + c \bmod m$ with $0 \le s_n < m$.

**Known $m$, unknown $a, c$.** From three outputs:
$$s_1 = a s_0 + c, \quad s_2 = a s_1 + c \pmod m$$
Subtract: $s_2 - s_1 = a (s_1 - s_0)$, so
$$a = (s_2 - s_1)(s_1 - s_0)^{-1} \bmod m$$
This needs $\gcd(s_1 - s_0, m) = 1$. If it is not, use another pair, or solve the
congruence with the gcd and test the (few) candidate lifts. Then $c = s_1 - a s_0
\bmod m$.

**Unknown $m$.** Let $t_n = s_{n+1} - s_n$. Then
$$t_{n+1} = a t_n \pmod m$$
so
$$u_n = t_{n+2} t_n - t_{n+1}^2 \equiv a^2 t_n^2 - (a t_n)^2 = 0 \pmod m$$
Every $u_n$ is an exact multiple of $m$. Take $\gcd(u_0, u_1, u_2, \ldots)$ - with
4-6 values the gcd is $m$ with overwhelming probability. It can come out as a small
multiple of $m$; sanity-check by verifying the recurrence reproduces all observed
outputs, and by discarding tiny factors.

**Recovering the seed / going backwards.** Once $a, c, m$ are known and
$\gcd(a, m) = 1$:
$$s_{n-1} = a^{-1}(s_n - c) \bmod m$$
so you can rewind arbitrarily far.

**Period facts.** The full period $m$ is reached iff (Hull-Dobell): $\gcd(c,m)=1$,
$a-1$ is divisible by every prime factor of $m$, and $a-1$ is divisible by 4 if 4
divides $m$. A "multiplicative" LCG has $c = 0$; then $s_n = a^n s_0$ and recovery of
$a$ needs a discrete log if you do not have consecutive outputs.

**Why LCGs are never secure.** Even without knowing the parameters, the map is affine,
so any leak of the state is total. Truncation is the only thing that makes it non-
trivial, and lattice reduction defeats that too.

## Attack

1. Collect at least 6-8 consecutive **full-width** outputs.
2. Compute $t_i$, then $u_i$, then $m = \gcd(u_i)$. Drop obviously spurious small
   factors (verify against the data).
3. Solve for $a$ with a modular inverse; if the inverse does not exist, try a
   different index pair.
4. Solve for $c$.
5. Verify by regenerating the whole observed sequence.
6. Predict forward, and rewind with $a^{-1}$ to recover earlier values.
7. If step 2 gives nonsense, the outputs are probably truncated or the generator is not
   a plain LCG (check for an XOR-shift on output, a Weyl sequence, or a combined LCG).

## Code

```python
#!/usr/bin/env python3
"""Recover a, c and m of a linear congruential generator from its outputs, with or
without a known modulus, then predict forward and backward. Pure stdlib, self-testing."""
from __future__ import annotations

import random
from functools import reduce
from math import gcd


class LCG:
    def __init__(self, seed: int, a: int, c: int, m: int):
        self.a, self.c, self.m = a, c, m
        self.state = seed % m

    def next(self) -> int:
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def take(self, n: int) -> list[int]:
        return [self.next() for _ in range(n)]

    def prev(self) -> int:
        """Rewind one step. Requires gcd(a, m) == 1."""
        a_inv = pow(self.a, -1, self.m)
        self.state = (a_inv * (self.state - self.c)) % self.m
        return self.state


def recover_modulus(outputs) -> int:
    """m = gcd over n of (t[n+2]*t[n] - t[n+1]**2), where t[i] = s[i+1] - s[i]."""
    if len(outputs) < 5:
        raise ValueError("need at least 5 outputs (6+ is comfortable)")
    t = [b - a for a, b in zip(outputs, outputs[1:])]
    u = [t[n + 2] * t[n] - t[n + 1] ** 2 for n in range(len(t) - 2)]
    m = abs(reduce(gcd, u))
    if m == 0:
        raise ValueError("degenerate sequence (constant differences?)")
    return m


def solve_linear_congruence(d: int, e: int, m: int, limit: int = 1 << 14):
    """All a with a*d == e (mod m). There are gcd(d, m) of them when solvable.

    Power-of-two moduli make gcd(d, m) > 1 the NORMAL case (differences of odd
    states are even), so a plain modular inverse is not enough.
    """
    g = gcd(d % m, m)
    if g == 0 or e % g:
        return []
    if g > limit:
        return []
    dg, eg, mg = (d % m) // g, (e % m) // g, m // g
    a0 = (eg * pow(dg, -1, mg)) % mg
    return [(a0 + k * mg) % m for k in range(g)]


def candidate_multipliers(outputs, m: int, limit: int = 1 << 14) -> list[int]:
    """Every a consistent with some consecutive triple, fewest candidates first."""
    best: list[int] = []
    for i in range(len(outputs) - 2):
        d = outputs[i + 1] - outputs[i]
        e = outputs[i + 2] - outputs[i + 1]
        cands = solve_linear_congruence(d, e, m, limit)
        if cands and (not best or len(cands) < len(best)):
            best = cands
            if len(best) == 1:
                break
    return best


def recover_increment(outputs, a: int, m: int) -> int:
    return (outputs[1] - a * outputs[0]) % m


def _fits(outputs, a: int, c: int, m: int) -> bool:
    return all((a * x + c) % m == y % m for x, y in zip(outputs, outputs[1:]))


def candidate_moduli(m: int, floor: int, depth: int = 64):
    """The gcd can be a small MULTIPLE of the true modulus - peel small factors off.

    Yields m first, then m//p, m//p**2, ... for each small prime p dividing m,
    never going at or below `floor` (every output must be < m).
    """
    seen = set()
    queue = [m]
    while queue:
        v = queue.pop(0)
        if v in seen or v <= floor or len(seen) > depth:
            continue
        seen.add(v)
        yield v
        for p in (2, 3, 5, 7, 11, 13):
            if v % p == 0:
                queue.append(v // p)


def _try_modulus(outputs, m: int):
    cands = candidate_multipliers(outputs, m)
    for a in cands:
        c = recover_increment(outputs, a, m)
        if _fits(outputs, a, c, m):
            return a, c, m
    return None


def recover_lcg(outputs, m: int | None = None):
    """Full pipeline -> (a, c, m). Verifies against the observed sequence."""
    if m is not None:
        got = _try_modulus(outputs, m)
        if got:
            return got
        raise ValueError(f"no (a, c) reproduces the sequence for m={m}")
    guess = recover_modulus(outputs)
    floor = max(outputs)
    for cand_m in candidate_moduli(guess, floor):
        got = _try_modulus(outputs, cand_m)
        if got:
            return got
    raise ValueError("no LCG parameters reproduce the sequence "
                     "(truncated outputs, or not a plain LCG)")


def predict_forward(last: int, a: int, c: int, m: int, count: int) -> list[int]:
    out, s = [], last
    for _ in range(count):
        s = (a * s + c) % m
        out.append(s)
    return out


def predict_backward(first: int, a: int, c: int, m: int, count: int) -> list[int]:
    """Values BEFORE `first`, returned oldest-first."""
    a_inv = pow(a, -1, m)
    out, s = [], first
    for _ in range(count):
        s = (a_inv * (s - c)) % m
        out.append(s)
    return list(reversed(out))


# A few real-world parameter sets worth trying before you solve anything.
KNOWN_LCGS = {
    "glibc TYPE_0 / ANSI C rand": (1103515245, 12345, 2 ** 31),
    "java.util.Random": (0x5DEECE66D, 0xB, 2 ** 48),
    "drand48 / erand48": (0x5DEECE66D, 0xB, 2 ** 48),
    "MSVC rand()": (214013, 2531011, 2 ** 31),
    "Borland C rand()": (22695477, 1, 2 ** 32),
    "MMIX (Knuth)": (6364136223846793005, 1442695040888963407, 2 ** 64),
    "Numerical Recipes ranqd1": (1664525, 1013904223, 2 ** 32),
    "RANDU (historically broken)": (65539, 0, 2 ** 31),
}


def identify_known(a: int, c: int, m: int) -> str | None:
    for name, params in KNOWN_LCGS.items():
        if params == (a, c, m):
            return name
    return None


if __name__ == "__main__":
    rng = random.Random(0xDECAF)

    # --- 1. everything unknown --------------------------------------------
    a, c, m = 1103515245, 12345, 2 ** 31
    g = LCG(seed=987654321, a=a, c=c, m=m)
    outs = g.take(10)
    ra, rc, rm = recover_lcg(outs)
    assert (ra, rc, rm) == (a, c, m), (ra, rc, rm)
    print(f"[ok] recovered a={ra} c={rc} m={rm} from {len(outs)} outputs "
          f"({identify_known(ra, rc, rm)})")

    # --- 2. prediction forward and backward -------------------------------
    future_real = g.take(5)
    future_pred = predict_forward(outs[-1], ra, rc, rm, 5)
    assert future_real == future_pred
    print(f"[ok] predicted the next 5 outputs: {future_pred[:2]}...")

    earlier = predict_backward(outs[0], ra, rc, rm, 3)
    g2 = LCG(seed=987654321, a=a, c=c, m=m)
    # the value before outs[0] is the seed itself
    assert earlier[-1] == 987654321
    print(f"[ok] rewound to the seed: {earlier[-1]}")

    # --- 3. 64-bit MMIX ----------------------------------------------------
    a2, c2, m2 = KNOWN_LCGS["MMIX (Knuth)"]
    g3 = LCG(seed=rng.getrandbits(64), a=a2, c=c2, m=m2)
    outs3 = g3.take(12)
    assert recover_lcg(outs3) == (a2, c2, m2)
    print("[ok] recovered 64-bit MMIX parameters from 12 outputs")

    # --- 4. random parameters, prime modulus ------------------------------
    for _ in range(20):
        m4 = 2 ** 61 - 1                      # a Mersenne prime
        a4 = rng.randrange(2, m4)
        c4 = rng.randrange(0, m4)
        g4 = LCG(seed=rng.randrange(m4), a=a4, c=c4, m=m4)
        o4 = g4.take(8)
        ra4, rc4, rm4 = recover_lcg(o4)
        # the gcd may land on a multiple/divisor of m; what matters is that the
        # recovered triple reproduces the sequence, which recover_lcg verifies.
        assert predict_forward(o4[-1], ra4, rc4, rm4, 3) == g4.take(3)
    print("[ok] 20 random 61-bit LCGs: parameters recovered and predictions correct")

    # --- 5. known modulus shortcut ----------------------------------------
    a5, c5, m5 = KNOWN_LCGS["java.util.Random"]
    g5 = LCG(seed=rng.getrandbits(48), a=a5, c=c5, m=m5)
    o5 = g5.take(3)
    assert recover_lcg(o5, m=m5) == (a5, c5, m5)
    print("[ok] with a KNOWN modulus, 3 outputs suffice (Java's 2**48 LCG)")

    # --- 6. multiplicative LCG (c = 0) -------------------------------------
    a6, m6 = 65539, 2 ** 31                   # RANDU
    g6 = LCG(seed=1, a=a6, c=0, m=m6)
    o6 = g6.take(10)
    ra6, rc6, rm6 = recover_lcg(o6)
    assert rc6 == 0 and ra6 == a6, (ra6, rc6, rm6)
    print(f"[ok] multiplicative LCG recovered: a={ra6} c={rc6} "
          f"({identify_known(ra6, rc6, rm6)})")

    # --- 7. failure mode: too few outputs ---------------------------------
    try:
        recover_modulus(outs[:4])
        raise AssertionError("should have refused")
    except ValueError:
        pass
    print("[ok] refuses to guess a modulus from fewer than 5 outputs")
    print("all self-tests passed")
```

## Variants & pitfalls

- **The gcd can be a multiple of $m$.** With few outputs, or with a multiplicative LCG
  whose states are all odd, you routinely get $2m$ or $4m$ (RANDU with $m = 2^{31}$
  reliably gcds to $2^{32}$). Peel small prime factors off the gcd and re-verify -
  `candidate_moduli` does exactly this.
- **The gcd can be a proper multiple that still works.** If the recovered $(a, c, m')$
  reproduces every observed value and predicts correctly, it is operationally the same
  generator - do not chase the "true" $m$.
- **Non-invertible differences are the norm, not the exception.** For power-of-two $m$
  and a multiplicative LCG (`c = 0`, `a` odd, odd seed) every state is odd, so every
  difference is even and no modular inverse exists. Solve
  $a d \equiv e \pmod m$ properly: with $g = \gcd(d, m)$ there are $g$ solutions
  $a = (e/g)(d/g)^{-1} \bmod (m/g) + k\,(m/g)$; test each against the sequence.
- **Truncated output.** Java's `nextInt()` returns the *top* 32 of 48 state bits;
  glibc's `rand()` returns the top 31 of a 32-bit word (and TYPE_3 is not an LCG at
  all). This arithmetic silently returns junk on truncated data - that is your signal
  to switch to `prng-truncated-lcg-lattice`.
- **Combined / shuffled LCGs.** `random()` in old BSD, `ranlux`, Wichmann-Hill, and
  L'Ecuyer combined generators sum two or three LCGs mod different primes. The gcd
  trick fails; model each component separately or use z3.
- **Non-consecutive outputs.** If you only see every $k$-th output, you are looking at
  the LCG $s_{n+k} = a^k s_n + c(a^{k-1}+\cdots+1)$ - still an LCG, so the same
  recovery works and gives you $a^k$; take a $k$-th root mod $m$ if you need $a$.
- **Additive-only ($a = 1$).** Then $t_n$ is constant and $u_n = 0$, so the gcd is 0.
  Handle that case separately: $c = s_1 - s_0$, $m$ unrecoverable from differences
  (look at where the sequence wraps).
- **Signed vs unsigned.** C implementations may produce negative values on overflow in
  a naive port. Normalise into $[0, m)$ before doing arithmetic.
- **Output transforms.** Many generators post-process: `>> 16`, `^ (s >> 33)`, `% 100`.
  Undo or account for the transform first.

## Tools

- **sympy** - `sympy.ntheory.residue_ntheory`, `Matrix.solve` over `GF(p)`, and
  `factorint` for splitting a suspicious modulus.
- **SageMath** - `crt`, `Zmod(m)`, and lattice tools if you need to move to the
  truncated case.
- **z3** - when there is an extra XOR/shift you cannot invert by hand.
- **`lcg_crack` / `prng-crack` snippets** - plenty exist, but the 40 lines above are
  the whole algorithm.

## References

- Wikipedia, "Linear congruential generator" (Hull-Dobell, parameter tables) - <https://en.wikipedia.org/wiki/Linear_congruential_generator>
- Marsaglia, "Random numbers fall mainly in the planes" - <https://www.pnas.org/doi/10.1073/pnas.61.1.25>
- SymPy documentation - <https://docs.sympy.org/latest/index.html>
