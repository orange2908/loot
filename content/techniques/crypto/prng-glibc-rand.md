---
title: "glibc rand() / random() - TYPE_3 Additive Feedback and srand(time(NULL))"
category: crypto
subcategory: prng
type: technique
tags: [glibc, rand, random, srand, srandom, initstate, type-3, additive-feedback, lagged-fibonacci, trinomial, r250, time-seed, prng, c-prng, untwister, msvc-rand, bsd-random, predictable-random]
difficulty: medium
summary: "glibc's random() is not an LCG: it is an additive feedback generator r[i]=r[i-3]+r[i-31] whose output drops the low bit, so 31 outputs predict the rest up to a 1-bit carry."
when_to_use:
  - "C/C++ target calls `srand(time(NULL))`, `srandom(...)`, `rand()` or `random()`"
  - "A binary generates tokens, canaries, salts or shuffles with libc randomness"
  - "You have 31+ consecutive `random()` outputs and want to predict the next ones"
  - "You need to reproduce a sequence offline to match a leaked value"
tools: [python, gdb, untwister, gcc]
related: [prng-lcg-recovery, prng-mt19937-seed-bruteforce, prng-toolkit, prng-cheatsheet]
---

## TL;DR

With the default 128-byte state ("TYPE_3"), glibc's `random()` keeps 34 words and
computes `r[i] = (r[i-3] + r[i-31]) mod 2**32`, returning `r[i] >> 1`. On glibc,
`rand()` is literally `random()`. Two attacks: **brute force `srand(time(NULL))`**
(a day is 86,400 candidates), or **use 31 consecutive outputs** to predict every
future output up to a single carry bit you can usually resolve immediately.

## Recognise it

- `srand(time(NULL))`, `srandom(getpid())`, `rand() % n` in decompiled C.
- Output values are always `< 2**31` (`RAND_MAX` = 2147483647) - never 32 bits.
- The sequence satisfies `o[i] == (o[i-3] + o[i-31]) % 2**31` for about three
  quarters of the indices and `+1` for the rest. **That mixed pattern is the
  fingerprint** - a pure LCG never behaves like that.
- `initstate(seed, buf, n)` in the binary tells you the state size and therefore the
  TYPE: n>=128 is TYPE_3 (default), 64 is TYPE_2, 32 is TYPE_1, 8 is TYPE_0 (a plain
  LCG `1103515245*s + 12345 mod 2**31`).

## Theory

**Seeding (`srandom`/`initstate`).**
```
r[0] = seed                     (seed 0 is treated as 1)
for i in 1..30:
    r[i] = (16807 * r[i-1]) mod 2147483647     # Park-Miller, via Schrage's trick
for i in 31..33:
    r[i] = r[i-31]
discard the first 310 outputs
```
Schrage's trick avoids 64-bit overflow: `hi, lo = divmod(prev, 127773)`,
`word = 16807*lo - 2836*hi`, `if word < 0: word += 2147483647`. Reimplement it
exactly or your stream diverges.

**Generation.**
```
r[i] = (r[i-3] + r[i-31]) mod 2**32
output = r[i] >> 1
```
This is a lagged-Fibonacci / additive-feedback generator over the trinomial
$x^{31} + x^3 + 1$. Period is about $2^{34}$.

**Why the output relation is only *almost* linear.** Write `r[i] = 2*o[i] + b[i]`
where `b[i]` is the discarded low bit. Then
$$2 o_i + b_i \equiv 2(o_{i-3} + o_{i-31}) + b_{i-3} + b_{i-31} \pmod{2^{32}}$$
The left side is even, so $b_i = b_{i-3} \oplus b_{i-31}$ (the low bits run their own
LFSR), and
$$o_i \equiv o_{i-3} + o_{i-31} + \left\lfloor \tfrac{b_{i-3}+b_{i-31}}{2} \right\rfloor \pmod{2^{31}}$$
i.e. the prediction is exact unless `b[i-3] == b[i-31] == 1`, which happens about a
quarter of the time and adds exactly 1. So from 31 outputs you predict every future
output as **one of two adjacent values**, and each observed value tells you whether
that carry fired - which in turn constrains the low-bit LFSR until you know it
completely.

**`rand()` vs `random()`.** On glibc they are the same function. On macOS/BSD,
`rand()` is a separate, different generator (`s = s*1103515245 + 12345`,
`return s & 0x7fffffff` historically; modern libc varies), while `random()` is this
same additive feedback design inherited from 4.3BSD. Check the platform before
assuming.

**Other TYPEs.** TYPE_0 (8-byte state) is the plain LCG `s = 1103515245*s + 12345 mod
2**31`, output `s`. TYPE_1 uses $x^7 + x^3 + 1$ with 7 words, TYPE_2 uses
$x^{15}+x+1$ with 15 words, TYPE_4 uses $x^{63}+x+1$ with 63 words. Same attack,
different lags.

## Attack

1. Decide the TYPE from `initstate` (default = TYPE_3).
2. If the seed is a timestamp/PID, **brute force it**: reimplement the generator,
   run it for each candidate, compare against a leaked output. One 31-bit output
   pins the seed.
3. Otherwise collect 31 consecutive outputs and roll the recurrence forward,
   carrying the 1-bit ambiguity.
4. Resolve the ambiguity: each observed output tells you whether the carry fired,
   giving AND-constraints on the low-bit LFSR; a handful of observations pins it.
5. Remember the 310 discarded outputs when reproducing a stream from a seed.
6. `rand() % n` introduces modulo bias for large `n`; it also destroys information,
   so collect more samples.

## Code

```python
#!/usr/bin/env python3
"""glibc / BSD random() (TYPE_3 additive feedback): exact reimplementation, seed
brute force, and prediction from 31 consecutive outputs. Pure stdlib, self-testing.

Verified against the C library: srandom(12345); random() -> 383100999, 858300821,
357768173, 455528251, ...
"""
from __future__ import annotations

MASK32 = 0xFFFFFFFF
MOD31 = 1 << 31

# (degree, lag) for each glibc TYPE; TYPE_3 is the default 128-byte state.
TYPES = {0: (0, 0), 1: (7, 3), 2: (15, 1), 3: (31, 3), 4: (63, 1)}


class GlibcRandom:
    """random() / srandom() with the default 128-byte state (TYPE_3)."""

    DEG = 31
    SEP = 3
    DISCARD = 310

    def __init__(self, seed: int):
        self.srandom(seed)

    def srandom(self, seed: int) -> None:
        seed &= MASK32
        if seed == 0:
            seed = 1
        r = [0] * (self.DEG + self.SEP)
        r[0] = seed
        for i in range(1, self.DEG):
            # r[i] = (16807 * r[i-1]) % 2147483647 without 64-bit overflow
            hi, lo = divmod(r[i - 1], 127773)
            word = 16807 * lo - 2836 * hi
            if word < 0:
                word += 2147483647
            r[i] = word
        for i in range(self.DEG, self.DEG + self.SEP):
            r[i] = r[i - self.DEG]
        self.r = r
        self.i = self.DEG + self.SEP
        for _ in range(self.DISCARD):
            self._step()

    def _step(self) -> int:
        v = (self.r[self.i - self.DEG] + self.r[self.i - self.SEP]) & MASK32
        self.r.append(v)
        self.i += 1
        return v

    def random(self) -> int:
        return self._step() >> 1

    def take(self, n: int) -> list[int]:
        return [self.random() for _ in range(n)]


def brute_force_seed(observed, candidates, skip: int = 0):
    """Find the seed whose stream reproduces `observed` (after `skip` draws)."""
    n = len(observed)
    for s in candidates:
        g = GlibcRandom(s)
        for _ in range(skip):
            g.random()
        if g.take(n) == list(observed):
            return s
    return None


def predict_next(outputs, count: int = 1):
    """From >=31 consecutive outputs, predict the next ones.

    Each prediction is a pair (low, high) = (S, S+1 mod 2**31): the true value is
    one of the two, and it is `low` about 75% of the time. Feeding back the WRONG
    value corrupts everything downstream, so resolve as you go when you can.
    """
    if len(outputs) < 31:
        raise ValueError("need at least 31 consecutive outputs")
    hist = list(outputs)
    preds = []
    for _ in range(count):
        s = (hist[-3] + hist[-31]) % MOD31
        preds.append((s, (s + 1) % MOD31))
        hist.append(s)                      # assume no carry and keep going
    return preds


def predict_with_feedback(outputs, truth_iter, count: int):
    """Predict step by step, using each real value to stay in sync.

    Returns (hits, total): how often the no-carry prediction was exactly right.
    """
    hist = list(outputs)
    hits = 0
    for _ in range(count):
        s = (hist[-3] + hist[-31]) % MOD31
        actual = next(truth_iter)
        if s == actual:
            hits += 1
        else:
            assert (s + 1) % MOD31 == actual, "not a TYPE_3 additive generator"
        hist.append(actual)
    return hits, count


def low_bit_lfsr(bits31):
    """The discarded low bits follow b[i] = b[i-3] XOR b[i-31] forever."""
    b = list(bits31)
    while True:
        b.append(b[-3] ^ b[-31])
        yield b[-1]


def looks_like_glibc_random(outputs) -> bool:
    """Structural test: o[i] - o[i-3] - o[i-31] mod 2**31 is always 0 or 1."""
    if len(outputs) < 40:
        return False
    diffs = {(outputs[i] - outputs[i - 3] - outputs[i - 31]) % MOD31
             for i in range(31, len(outputs))}
    return diffs <= {0, 1}


if __name__ == "__main__":
    # --- known-answer test against the real C library ---------------------
    g = GlibcRandom(12345)
    first = g.take(4)
    assert first == [383100999, 858300821, 357768173, 455528251], first
    print(f"[ok] srandom(12345) -> {first} (matches libc)")

    # seed 0 is coerced to 1
    assert GlibcRandom(0).take(3) == GlibcRandom(1).take(3)
    print("[ok] seed 0 is treated as seed 1")

    # --- structural fingerprint -------------------------------------------
    stream = GlibcRandom(0xC0FFEE).take(500)
    assert all(0 <= v < MOD31 for v in stream)
    assert looks_like_glibc_random(stream)
    print("[ok] structural test: o[i]-o[i-3]-o[i-31] mod 2**31 is always 0 or 1")

    # --- srand(time(NULL)) brute force ------------------------------------
    secret_ts = 1_735_689_600
    leaked = GlibcRandom(secret_ts).take(2)
    found = brute_force_seed(leaked, range(secret_ts - 4000, secret_ts + 4000))
    assert found == secret_ts, found
    print(f"[ok] recovered srandom(time(NULL)) seed {found} from 2 outputs")

    # one output is enough at 31 bits of entropy
    found1 = brute_force_seed(leaked[:1], range(secret_ts - 4000, secret_ts + 4000))
    assert found1 == secret_ts, found1
    print("[ok] a single 31-bit output already pins the timestamp seed")

    # --- prediction from 31 outputs, no seed knowledge --------------------
    victim = GlibcRandom(0xBADC0DE)
    window = victim.take(31)
    pairs = predict_next(window, 1)
    nxt = victim.random()
    assert nxt in pairs[0], (nxt, pairs[0])
    print(f"[ok] next output is one of {pairs[0]} - it was {nxt}")

    victim2 = GlibcRandom(0x1337BEEF)
    window2 = victim2.take(31)

    def truth():
        while True:
            yield victim2.random()

    hits, total = predict_with_feedback(window2, truth(), 2000)
    rate = hits / total
    assert 0.70 < rate < 0.80, rate
    print(f"[ok] no-carry prediction exact {rate*100:.1f}% of the time "
          f"(theory 75%); the other 25% are exactly +1")

    # --- the discarded low bits are their own LFSR ------------------------
    gen = low_bit_lfsr([1, 0, 1, 1] + [0] * 27)
    bits = [next(gen) for _ in range(100)]
    assert set(bits) <= {0, 1} and len(bits) == 100
    print("[ok] low-bit LFSR b[i] = b[i-3] ^ b[i-31] runs independently")

    # --- the 310-output warm-up is part of srandom(), not random() --------
    warm = GlibcRandom(777)
    cold = GlibcRandom.__new__(GlibcRandom)
    GlibcRandom.DISCARD, saved = 0, GlibcRandom.DISCARD
    cold.srandom(777)
    GlibcRandom.DISCARD = saved
    assert warm.random() != cold.random(), "skipping the warm-up must change the stream"
    print("[ok] the 310-output warm-up is baked into srandom() and cannot be skipped")
    print("all self-tests passed")
```

## Variants & pitfalls

- **`rand()` is not `random()` everywhere.** glibc aliases them; macOS/BSD do not.
  Verify with a two-line C program on the target platform before building an attack.
- **The 310 discarded outputs.** Forget them and every value is wrong. They are part
  of `srandom`, not of `random`.
- **Schrage's trick sign handling.** `16807*lo - 2836*hi` can be negative; you must add
  `2147483647`. Using plain `(16807 * prev) % 2147483647` gives the same answer in
  Python (arbitrary precision), but not in C - and some challenge binaries reimplement
  the C version with a 32-bit overflow bug you must replicate exactly.
- **`RAND_MAX` is 2147483647**, so `rand()` never returns a 32-bit value. If your
  samples exceed `2**31`, it is not glibc `rand()`.
- **`rand() % n` bias.** For `n` not dividing `2**31`, low residues are slightly more
  likely. For small `n` the bias is negligible; do not build an attack on it unless
  `n > 2**20` or so.
- **`initstate()` with a small buffer changes the TYPE** and therefore the lags. A
  32-byte state is TYPE_1 ($x^7+x^3+1$), 8 bytes is a plain LCG.
- **Thread safety.** `rand()` uses a global state; `rand_r(&seed)` uses a caller-owned
  32-bit seed and is a *different*, much weaker TYPE_0-style generator - if you see
  `rand_r`, attack it as an LCG.
- **Carry feedback.** `predict_next` assumes no carry when it rolls forward. If you
  feed a wrong value back, everything after it is wrong. Resolve the carry against the
  real stream whenever you can observe it.
- **`arc4random()` is not attackable** - it is a CSPRNG (ChaCha20 on modern systems).
  If the binary uses it, look elsewhere.
- **Windows.** MSVC `rand()` is `s = 214013*s + 2531011; return (s >> 16) & 0x7fff` -
  only 15 bits of output. Treat it as a truncated LCG.

## Tools

- **A 5-line C program** compiled on the target platform - the fastest way to get
  ground truth for any seed.
- **gdb** - break after `srand`, read the global state directly out of libc memory.
- **untwister** - <https://github.com/altf4/untwister> - includes a glibc mode with
  time-window seed search.
- **Ghidra/IDA** - to spot `initstate`, the state buffer size, and the TYPE.

## References

- glibc `stdlib/random_r.c` - <https://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/random_r.c>
- glibc `stdlib/random.c` - <https://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/random.c>
- `random(3)` man page - <https://man7.org/linux/man-pages/man3/random.3.html>
- untwister - <https://github.com/altf4/untwister>
