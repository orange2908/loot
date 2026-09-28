---
title: "MT19937 - State Recovery from 624 Outputs, Untempering, Forward and Backward Prediction"
category: crypto
subcategory: prng
type: technique
tags: [mt19937, mersenne-twister, untemper, untempering, state-recovery, prng, random, getrandbits, randcrack, mt19937predictor, clone-rng, backward-prediction, untwist, predictable-random, python-random, not-cryptographically-secure]
difficulty: medium
summary: "624 consecutive 32-bit outputs are the entire MT19937 state; untemper them, reload the state, and predict every future AND past output."
when_to_use:
  - "A service leaks 624 or more consecutive 32-bit values from `random.getrandbits(32)`"
  - "Tokens, nonces or shuffles come from Python `random`, PHP `mt_rand`, Ruby `rand` or C++ `mt19937`"
  - "You can request unlimited random values before the one that matters"
  - "You need a value generated BEFORE the ones you observed (a token issued earlier)"
tools: [python, randcrack, mt19937predictor, z3]
related: [prng-mt19937-seed-bruteforce, prng-python-random, prng-toolkit, prng-cheatsheet]
---

## TL;DR

MT19937's internal state is exactly 624 32-bit words. The output function
("tempering") is a bijection on 32 bits, so it is invertible with no search at all.
Collect 624 consecutive raw outputs, untemper each one, load them as the state, and
you have a perfect clone: every future output, and - by inverting the twist - every
past one too.

## Recognise it

- Python `import random` / `random.getrandbits` / `random.randint` / `random.shuffle`
  with no `secrets` or `os.urandom` anywhere.
- PHP `mt_rand()`, Ruby `Random#rand`, C++ `std::mt19937`, Java... no (Java is an LCG,
  see `prng-java-random`), JavaScript... no (V8 is xorshift128+, see
  `prng-xorshift-v8-math-random`).
- A service that will hand you as many tokens as you ask for.
- Token entropy is exactly 32 bits per value, or a multiple of it.
- A "session id" that is `hex(random.getrandbits(128))` - that is 4 outputs per token,
  so 156 tokens give you the full state.

## Theory

**State.** 624 words of 32 bits = 19937 bits (the top bit of word 0 is unused, hence
19937 not 19968). An index `i` says how many words of the current block have been
consumed.

**Tempering** turns state word `y` into an output:
```
y ^= y >> 11
y ^= (y << 7)  & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= y >> 18
```
Each step is an invertible linear map over GF(2). Inverting a right shift by `r`
takes $\lceil 32/r \rceil$ iterations of `x = y ^ (x >> r)`; the same for left shifts
with the mask reapplied. No brute force, no z3 needed (although z3 is the lazy way).

**The twist** refills all 624 words at once:
```
for i in range(624):
    y = (mt[i] & 0x80000000) | (mt[(i+1) % 624] & 0x7fffffff)
    mt[i] = mt[(i+397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
```
This is also invertible. Walking `i` from 623 down to 0 and recovering each word from
`mt[i]`, `mt[(i+397)%624]` and the *already-restored* neighbours gives the previous
block's state - which is what lets you predict **backwards**.

**Why 624 outputs exactly.** Fewer is not enough for a plain reconstruction, but if
the outputs are truncated (only the top bits leak, or only `getrandbits(1)`), you can
still solve for the state with a GF(2) linear system or z3 - it just needs ~19937 bits
of observed data in total.

## Attack

1. Get 624 consecutive full 32-bit outputs. If the service gives you
   `random.randint(0, 2**32-1)`, careful: `randint` does *rejection sampling*, so it
   may consume more than one output per value (see `prng-python-random`).
2. Untemper each output to recover a state word.
3. Load the 624 words as the state with `index = 624` (so the next call twists) and
   predict forward.
4. To go backward, untwist the recovered state and temper the result.
5. If you cannot get a clean 624, use z3 over the observed bits, or `randcrack` which
   handles the bookkeeping.

## Code

```python
#!/usr/bin/env python3
"""MT19937: untemper, full state recovery from 624 outputs, forward prediction and
BACKWARD prediction by inverting the twist. Verified against Python's own random."""
from __future__ import annotations

import random

N = 624
M = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF


def temper(y: int) -> int:
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y &= 0xFFFFFFFF
    y ^= y >> 18
    return y


def _unshift_right(y: int, shift: int) -> int:
    x = y
    for _ in range((32 + shift - 1) // shift):
        x = y ^ (x >> shift)
    return x & 0xFFFFFFFF


def _unshift_left_mask(y: int, shift: int, mask: int) -> int:
    x = y
    for _ in range((32 + shift - 1) // shift):
        x = y ^ ((x << shift) & mask)
    return x & 0xFFFFFFFF


def untemper(y: int) -> int:
    """Exact inverse of temper(). No search: tempering is a bijection on 32 bits."""
    y = _unshift_right(y, 18)
    y = _unshift_left_mask(y, 15, 0xEFC60000)
    y = _unshift_left_mask(y, 7, 0x9D2C5680)
    y = _unshift_right(y, 11)
    return y


class MT19937:
    """Reference implementation - use it when the target is not Python."""

    def __init__(self, seed: int | None = None):
        self.mt = [0] * N
        self.index = N
        if seed is not None:
            self.seed_int(seed)

    def seed_int(self, seed: int) -> None:
        """init_genrand: the standard 32-bit seeding routine."""
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, N):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30))
                          + i) & 0xFFFFFFFF
        self.index = N

    def set_state(self, words, index: int = N) -> None:
        assert len(words) == N
        self.mt = list(words)
        self.index = index

    def twist(self) -> None:
        for i in range(N):
            y = (self.mt[i] & UPPER_MASK) | (self.mt[(i + 1) % N] & LOWER_MASK)
            self.mt[i] = self.mt[(i + M) % N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= MATRIX_A
        self.index = 0

    def next_u32(self) -> int:
        if self.index >= N:
            self.twist()
        y = temper(self.mt[self.index])
        self.index += 1
        return y


def untwist(mt) -> list[int]:
    """Invert one twist: given the CURRENT block's state, return the PREVIOUS one."""
    mt = list(mt)
    for i in range(N - 1, -1, -1):
        # high bit of mt[i-1] comes from the pair (i-1, i+M-1)
        tmp = mt[i] ^ mt[(i + M) % N]
        if tmp & UPPER_MASK:
            tmp ^= MATRIX_A
        res = (tmp << 1) & UPPER_MASK
        tmp = mt[(i - 1) % N] ^ mt[(i + M - 1) % N]
        if tmp & UPPER_MASK:
            tmp ^= MATRIX_A
            res |= 1
        res |= (tmp << 1) & LOWER_MASK
        mt[i] = res
    return mt


def recover_state(outputs) -> list[int]:
    """624 consecutive raw 32-bit outputs -> the 624 state words behind them."""
    if len(outputs) < N:
        raise ValueError(f"need {N} consecutive outputs, got {len(outputs)}")
    return [untemper(o) for o in outputs[-N:]]


def clone_python_random(outputs) -> random.Random:
    """Return a random.Random positioned exactly where the victim's is."""
    state = recover_state(outputs)
    r = random.Random()
    r.setstate((3, tuple(state + [N]), None))
    return r


def predict_backwards(outputs, count: int) -> list[int]:
    """Outputs that were produced BEFORE the 624 you observed, oldest first."""
    state = recover_state(outputs)
    prev = untwist(state)
    past = [temper(w) for w in prev]
    if count > N:
        raise ValueError("untwist again to go back more than one block")
    return past[N - count:]


if __name__ == "__main__":
    # --- untemper is an exact inverse --------------------------------------
    rng = random.Random(0xC0FFEE)
    for _ in range(2000):
        v = rng.getrandbits(32)
        assert temper(untemper(v)) == v
    print("[ok] untemper(temper(x)) == x over 2000 samples")

    # --- clone Python's random from 624 outputs ---------------------------
    victim = random.Random(1337)
    observed = [victim.getrandbits(32) for _ in range(N)]
    clone = clone_python_random(observed)
    future_real = [victim.getrandbits(32) for _ in range(10)]
    future_pred = [clone.getrandbits(32) for _ in range(10)]
    assert future_real == future_pred, (future_real[:3], future_pred[:3])
    print(f"[ok] forward prediction: next 10 outputs match exactly")
    print(f"     e.g. {future_real[0]:#010x}")

    # --- higher-level APIs are now predictable too ------------------------
    victim2 = random.Random(2024)
    obs2 = [victim2.getrandbits(32) for _ in range(N)]
    clone2 = clone_python_random(obs2)
    assert victim2.randint(0, 10 ** 9) == clone2.randint(0, 10 ** 9)
    deck = list(range(20))
    a, b = deck[:], deck[:]
    victim2.shuffle(a)
    clone2.shuffle(b)
    assert a == b
    assert victim2.random() == clone2.random()
    print("[ok] randint / shuffle / random() all predicted")

    # --- backward prediction ----------------------------------------------
    victim3 = random.Random(999)
    all_outputs = [victim3.getrandbits(32) for _ in range(2 * N)]
    past = predict_backwards(all_outputs[N:], N)
    assert past == all_outputs[:N], (past[:3], all_outputs[:3])
    print(f"[ok] backward prediction: recovered all {N} earlier outputs")
    print(f"     oldest recovered = {past[0]:#010x}")

    # --- reference implementation matches CPython's Mersenne Twister ------
    ref = MT19937()
    ref.set_state(recover_state(observed), index=N)
    clone3 = clone_python_random(observed)
    assert [ref.next_u32() for _ in range(5)] == \
           [clone3.getrandbits(32) for _ in range(5)]
    print("[ok] standalone MT19937 class agrees with CPython")

    # --- init_genrand seeding matches a 32-bit seed -----------------------
    # CPython seeds differently for ints (init_by_array), so only compare the
    # reference implementation against itself here.
    m = MT19937(5489)                     # the canonical default seed
    first = [m.next_u32() for _ in range(3)]
    m2 = MT19937(5489)
    assert [m2.next_u32() for _ in range(3)] == first
    print(f"[ok] init_genrand(5489) -> {first}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **`random.randint` is not one output.** CPython's `randrange` uses `_randbelow`,
  which draws `getrandbits(k)` and *rejects* values >= n. So a stream of `randint`
  results does not map one-to-one to raw outputs. Collect `getrandbits(32)` if you can;
  otherwise model the rejection (see `prng-python-random`).
- **`random.random()` consumes TWO outputs.** It builds a 53-bit float from
  `a >> 5` (27 bits) and `b >> 6` (26 bits). You therefore lose the low 5 and 6 bits -
  reconstructing state from `random()` needs 2x624 draws *and* a solver for the
  missing bits, or simply more samples.
- **Python seeds with `init_by_array`, not `init_genrand`.** `random.seed(1234)`
  expands the int into a key array; do not expect the canonical `init_genrand`
  sequence. This matters when you are trying to *brute force the seed* - see
  `prng-mt19937-seed-bruteforce`.
- **PHP's `mt_rand` is a modified MT19937** (a different twist in older versions, and
  the output is `>> 1` into 31 bits). Use `php_mt_seed`, not this code.
- **Non-consecutive outputs.** If the service interleaves other `random` calls you did
  not see, your 624 are not consecutive and untempering yields garbage. Test by
  predicting one value and checking it.
- **Truncated outputs.** Only the top 8 bits leak? You need ~2500 samples and a GF(2)
  linear solve (or z3 with `Extract`). `randcrack` will not do this; write the solver.
- **MT19937-64** has 312 words of 64 bits, different tempering constants
  (`0x5555555555555555`, `0x71D67FFFEDA60000`, `0xFFF7EEE000000000`) and shifts
  (29, 17, 37, 43). Same attack, different numbers.
- **`random.SystemRandom`** is `os.urandom` - not attackable. If the code uses it,
  look elsewhere.
- **Going back more than one block** means calling `untwist` repeatedly; each call
  rewinds 624 outputs.
- **Index bookkeeping.** `setstate` with index 624 means "twist before the next
  output". If your predictions are off by exactly 624, that is the bug.

## Tools

- **randcrack** (`pip install randcrack`) - feed it 624 `getrandbits(32)` values with
  `submit()`, then `predict_getrandbits(32)`. Zero thinking required.
- **mt19937predictor** (`pip install mt19937predictor`) - `setrandbits(value, 32)` x624
  then `getrandbits(32)`; also handles partial-bit feeds.
- **z3** - for truncated or interleaved outputs, model the state as 624 `BitVec(32)`
  and assert the observed relations.
- **`untwister`** - <https://github.com/altf4/untwister> - brute forces seeds across
  several PRNG families (older, C-based).

## References

- Matsumoto & Nishimura, "Mersenne Twister" - <http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/emt.html>
- CPython `_randommodule.c` - <https://github.com/python/cpython/blob/main/Modules/_randommodule.c>
- randcrack - <https://github.com/tna0y/Python-random-module-cracker>
- mt19937predictor - <https://github.com/kmyk/mersenne-twister-predictor>
