---
title: "Python `random` Specifics - getrandbits, the 53-bit random(), shuffle, randrange bias, seeding"
category: crypto
subcategory: prng
type: technique
tags: [python-random, getrandbits, randbelow, randrange, randint, shuffle, fisher-yates, modulo-bias, rejection-sampling, mt19937, random-random, 53-bit, os-urandom, systemrandom, secrets, seed, sample, choices, prng]
difficulty: medium
summary: "How many MT19937 outputs each random API call actually consumes, and how shuffle/randrange leak state - the details that make or break a state-recovery attack."
when_to_use:
  - "You are recovering MT19937 state but predictions are off by a few draws"
  - "The only observable is a shuffled deck, a `random()` float, or a `randint` value"
  - "You need to know whether `randint` consumed one output or three"
  - "Deciding whether a target's `random` usage is exploitable at all"
tools: [python, randcrack, mt19937predictor, z3]
related: [prng-mt19937-state-recovery, prng-mt19937-seed-bruteforce, prng-toolkit, prng-cheatsheet]
---

## TL;DR

Every attack on Python's `random` depends on knowing **how many 32-bit MT19937 outputs
each call eats and which bits of them survive**. `getrandbits(k)` for `k<=32` is one
output right-shifted; `random()` is *two* outputs with 5 and 6 low bits thrown away;
`randrange`/`randint`/`choice`/`shuffle` all go through `_randbelow`, which does
**rejection sampling** and therefore consumes a variable number of outputs.

## Recognise it

- `import random` anywhere near token, key, nonce, password or shuffle generation.
- `random.SystemRandom()` or `secrets` - stop, that is `os.urandom`, not MT19937.
- `random.seed(...)` with an argument you can guess -> `prng-mt19937-seed-bruteforce`.
- A leak that is a shuffled list, a float, or a bounded integer rather than raw bits -
  you still have a path, you just need the right accounting.

## Theory

### `getrandbits(k)`

```
words = (k - 1) // 32 + 1
for i in range(words):
    r = genrand_uint32()
    if i == words - 1:
        r >>= (32 * words - k)       # only the LAST word is truncated
    word[i] = r
value = int.from_bytes(words, "little")     # word 0 is the LOW 32 bits
```
So:
- `getrandbits(32)` = one raw output, untouched. **This is the one you want.**
- `getrandbits(20)` = `out >> 12` - the top 20 bits of one output.
- `getrandbits(64)` = `w0 | (w1 << 32)` - two full outputs, **low word first**.
- `getrandbits(48)` = `w0 | ((w1 >> 16) << 32)` - one full output plus 16 top bits.

### `random()` - the 53-bit two-draw

```
a = genrand_uint32() >> 5     # 27 bits
b = genrand_uint32() >> 6     # 26 bits
return (a * 2**26 + b) / 2**53
```
Two outputs, and you lose the bottom 5 bits of the first and bottom 6 of the second.
That is why you cannot simply untemper a stream of `random()` values: each observed
float gives 53 of 64 state-derived bits. You can still solve for the state, but it
takes a GF(2) linear solve or z3 over ~19937 unknowns, with roughly 624 floats needed.

### `_randbelow(n)` - rejection sampling

```
k = n.bit_length()
r = getrandbits(k)
while r >= n:
    r = getrandbits(k)
return r
```
Note `k = n.bit_length()`, **not** `(n-1).bit_length()`. Consequences:
- `n = 2**m - 1` is the best case: `k = m`, and only the single value `2**m - 1` is
  rejected, so it is one output per call with probability `1 - 2**-m`.
- `n = 2**m` is the *worst* case: `k = m+1`, so exactly half of all draws are rejected
  and the call averages two outputs. A 64-card `_randbelow(64)` costs 2 outputs on
  average, not 1.
- In general the expected number of draws is `2**k / n`, between 1 and 2, and the
  *actual* number varies per call. A stream of `randint` results therefore does
  **not** line up one-to-one with raw outputs.
- `randrange(a, b)` = `a + _randbelow(b - a)`; `randint(a, b)` = `randrange(a, b+1)`.
- This is exactly why CPython's `randrange` has **no modulo bias**. A hand-rolled
  `getrandbits(32) % n` *does*.

### `shuffle(x)` - Fisher-Yates, backwards

```
for i in reversed(range(1, len(x))):
    j = _randbelow(i + 1)
    x[i], x[j] = x[j], x[i]
```
Because position `i` is never touched again after its step, a known shuffle of a known
deck is **fully invertible**: the final element at position `n-1` tells you
`j_{n-1}` outright, then replay and repeat. A shuffled 52-card deck pins down all 51
`_randbelow` outputs, i.e. $\log_2(52!) \approx 226$ bits of the stream - enough to
identify a brute-forceable seed on its own, and with a few shuffles, enough to
reconstruct state.

### `choice`, `choices`, `sample`

- `choice(seq)` = `seq[_randbelow(len(seq))]` - rejection sampling.
- `choices(...)` (with weights) uses `random()` - **two outputs per pick**.
- `sample(pop, k)` uses either `_randbelow` in a selection-set loop or a partial
  shuffle depending on the size ratio - the draw count depends on data, so avoid
  relying on it for exact accounting.

### Seeding

- `random.seed()` with no argument: `os.urandom(32)` (falls back to the clock only if
  urandom is unavailable). Not attackable.
- `random.seed(int)`: `init_by_array` over the absolute value's 32-bit limbs.
- `random.seed(str/bytes)`: `int.from_bytes(n + sha512(n).digest(), "big")`.
- `random.Random()` instances each have their own state; the module-level functions
  share one hidden global instance that *any* imported library can advance.
- `os.fork()` duplicates the state - parent and child then emit identical sequences.

## Attack

1. Read the target's code and write down the exact call sequence.
2. Convert every observable back into raw-output constraints using the rules above.
3. If you can get `getrandbits(32)` x624, do the straightforward state recovery.
4. If the leak is a shuffle, invert Fisher-Yates to recover the `_randbelow` outputs,
   then either brute force the seed or feed the bits to a solver.
5. If the leak is `random()` floats, extract the known 27+26 bits and hand them to z3 /
   a GF(2) solver, or pivot to seed brute force.
6. If the code uses a naive `% n`, exploit the modulo bias directly - it can leak the
   high bits of the underlying draw.

## Code

```python
#!/usr/bin/env python3
"""Exactly how Python's random API consumes MT19937 outputs, verified against CPython:
getrandbits decomposition, the 53-bit random(), _randbelow rejection sampling,
Fisher-Yates inversion from a known shuffle, and modulo bias. Self-testing."""
from __future__ import annotations

import random
from collections import Counter


def split_state(r: random.Random) -> random.Random:
    """A second Random positioned identically, so we can watch raw outputs."""
    twin = random.Random()
    twin.setstate(r.getstate())
    return twin


def getrandbits_from_words(words, k: int) -> int:
    """Reproduce CPython's getrandbits(k) from the raw 32-bit outputs it consumed."""
    nwords = (k - 1) // 32 + 1
    assert len(words) == nwords, f"getrandbits({k}) consumes {nwords} outputs"
    parts = list(words)
    parts[-1] >>= (32 * nwords - k)
    value = 0
    for i, w in enumerate(parts):
        value |= w << (32 * i)
    return value


def random_from_words(a: int, b: int) -> float:
    """Reproduce CPython's random() from its two raw outputs."""
    return ((a >> 5) * 2 ** 26 + (b >> 6)) * (1.0 / 2 ** 53)


def random_known_bits(f: float) -> tuple[int, int]:
    """Invert random(): the top 27 bits of output a and the top 26 bits of b."""
    q = int(f * 2 ** 53)
    return q >> 26, q & ((1 << 26) - 1)


def randbelow(r: random.Random, n: int) -> int:
    """CPython's _randbelow_with_getrandbits, reimplemented."""
    if n <= 0:
        return 0
    k = n.bit_length()
    v = r.getrandbits(k)
    while v >= n:
        v = r.getrandbits(k)
    return v


def randbelow_draw_count(r: random.Random, n: int) -> tuple[int, int]:
    """Return (value, how many getrandbits calls it took)."""
    k = n.bit_length()
    count = 1
    v = r.getrandbits(k)
    while v >= n:
        v = r.getrandbits(k)
        count += 1
    return v, count


def shuffle_manual(x: list, r: random.Random) -> None:
    """CPython's shuffle, reimplemented."""
    for i in reversed(range(1, len(x))):
        j = randbelow(r, i + 1)
        x[i], x[j] = x[j], x[i]


def recover_shuffle_indices(original: list, shuffled: list) -> list[int]:
    """Invert Fisher-Yates: recover every j = _randbelow(i+1), for i = n-1 down to 1.

    Position i is never touched after its own step, so the element sitting at i in the
    final list is whatever was at position j when step i ran. Replay forward.
    Requires distinct elements.
    """
    if sorted(map(str, original)) != sorted(map(str, shuffled)):
        raise ValueError("lists are not permutations of each other")
    work = list(original)
    js = []
    for i in reversed(range(1, len(work))):
        target = shuffled[i]
        j = work.index(target)
        js.append(j)
        work[i], work[j] = work[j], work[i]
    return js                      # js[0] is j for i = n-1


def modulo_bias_counts(seed: int, n: int, trials: int) -> Counter:
    """getrandbits(32) % n over-represents the first 2**32 % n residues."""
    r = random.Random(seed)
    return Counter(r.getrandbits(32) % n for _ in range(trials))


if __name__ == "__main__":
    # --- getrandbits decomposition ----------------------------------------
    for k in (8, 20, 31, 32, 48, 64, 96, 128):
        r = random.Random(k * 7919)
        twin = split_state(r)
        value = r.getrandbits(k)
        nwords = (k - 1) // 32 + 1
        words = [twin.getrandbits(32) for _ in range(nwords)]
        assert value == getrandbits_from_words(words, k), k
    print("[ok] getrandbits(k) decomposition verified for k in 8..128")

    # one full output, untouched - the ideal observable
    r = random.Random(1)
    twin = split_state(r)
    assert r.getrandbits(32) == twin.getrandbits(32)
    # low word first for k > 32
    r = random.Random(2)
    twin = split_state(r)
    v64 = r.getrandbits(64)
    w0, w1 = twin.getrandbits(32), twin.getrandbits(32)
    assert v64 == w0 | (w1 << 32)
    print("[ok] getrandbits(64) is w0 | (w1 << 32) - LOW word first")

    # --- random() is two draws -------------------------------------------
    r = random.Random(3)
    twin = split_state(r)
    f = r.random()
    a, b = twin.getrandbits(32), twin.getrandbits(32)
    assert f == random_from_words(a, b)
    hi_a, hi_b = random_known_bits(f)
    assert hi_a == a >> 5 and hi_b == b >> 6
    print(f"[ok] random() == ((a>>5)*2**26 + (b>>6))/2**53; "
          f"5+6 low bits are lost")

    # --- _randbelow rejection sampling ------------------------------------
    r = random.Random(4)
    twin = split_state(r)
    for _ in range(200):
        assert r.randrange(97) == randbelow(twin, 97)
    print("[ok] randrange(n) == _randbelow(n) reimplementation, 200 samples")

    r = random.Random(5)
    counts = Counter(randbelow_draw_count(r, 100)[1] for _ in range(20000))
    assert counts[1] > 0 and counts[2] > 0, counts
    expected = 128 / 100                       # 2**k / n
    observed = sum(k * v for k, v in counts.items()) / sum(counts.values())
    assert abs(observed - expected) < 0.05, (observed, expected)
    print(f"[ok] _randbelow(100) averages {observed:.3f} draws "
          f"(theory 2**7/100 = {expected:.3f}) - NOT one-to-one with outputs")

    # NOTE: k = n.bit_length(), NOT (n-1).bit_length(). So n = 2**m is the WORST
    # case: k = m+1 and exactly half of all draws are rejected.
    r = random.Random(6)
    counts64 = Counter(randbelow_draw_count(r, 64)[1] for _ in range(20000))
    avg64 = sum(k * v for k, v in counts64.items()) / sum(counts64.values())
    assert 1.9 < avg64 < 2.1, avg64
    # n = 2**m - 1 is the best case: k = m, so only the single value 2**m - 1 is
    # rejected - one output per call 63/64 of the time.
    r = random.Random(6)
    counts63 = Counter(randbelow_draw_count(r, 63)[1] for _ in range(20000))
    avg63 = sum(k * v for k, v in counts63.items()) / sum(counts63.values())
    assert 1.0 < avg63 < 1.05, avg63
    print(f"[ok] _randbelow(64) averages {avg64:.2f} draws (worst case), "
          f"_randbelow(63) averages {avg63:.3f} (best case)")

    # --- shuffle -----------------------------------------------------------
    deck = list(range(52))
    r = random.Random(7)
    twin = split_state(r)
    a_list, b_list = deck[:], deck[:]
    r.shuffle(a_list)
    shuffle_manual(b_list, twin)
    assert a_list == b_list
    print("[ok] shuffle == reversed Fisher-Yates with _randbelow")

    # --- invert a known shuffle -------------------------------------------
    r = random.Random(1234)
    twin = split_state(r)
    shuffled = deck[:]
    r.shuffle(shuffled)
    js = recover_shuffle_indices(deck, shuffled)
    truth = [randbelow(twin, i + 1) for i in reversed(range(1, len(deck)))]
    assert js == truth, (js[:5], truth[:5])
    leaked_bits = sum((i + 1).bit_length() for i in reversed(range(1, len(deck))))
    print(f"[ok] recovered all {len(js)} _randbelow outputs from one 52-card "
          f"shuffle (~{leaked_bits} bits of draws)")

    # and that is enough to brute force a small seed
    secret = 424242
    shuffled2 = deck[:]
    random.Random(secret).shuffle(shuffled2)
    found = None
    for cand in range(424000, 424500):
        trial = deck[:]
        random.Random(cand).shuffle(trial)
        if trial == shuffled2:
            found = cand
            break
    assert found == secret, found
    print(f"[ok] one shuffle identified the seed uniquely: {found}")

    # --- modulo bias -------------------------------------------------------
    n = 3_000_000_000                # 2**32 % n = 1294967296, a huge bias
    counts = modulo_bias_counts(8, n, 200_000)
    low = sum(v for k, v in counts.items() if k < 2 ** 32 % n)
    high = sum(v for k, v in counts.items() if k >= 2 ** 32 % n)
    ratio = low / max(high, 1)
    assert ratio > 1.5, ratio
    print(f"[ok] getrandbits(32) % n: residues below 2**32 % n are "
          f"{ratio:.2f}x more likely - CPython's randrange avoids this")
    print("all self-tests passed")
```

## Variants & pitfalls

- **`randint` is not one draw.** The single most common reason a state-recovery script
  produces garbage. Ask for `getrandbits(32)` if the service lets you.
- **Bit order for `k > 32`.** Low word first. Getting this backwards silently breaks
  everything.
- **`random()` loses 11 bits per pair.** Do not try to untemper reconstructed words
  from floats; use a solver.
- **The global instance is shared.** `random.random()` in your own helper code, an
  imported library's `random.shuffle`, a logging module - all advance the same stream.
  When replaying a victim, replay *everything*.
- **`random.seed(x)` mid-stream resets the state.** Look for reseeding per request; it
  turns a state-recovery problem into a seed-brute-force problem (usually easier).
- **`SystemRandom` overrides `random()` and `getrandbits`, but not `_randbelow`'s
  algorithm** - it still rejection-samples, just on urandom bits. Unattackable.
- **`secrets.token_hex` / `token_urlsafe`** are `os.urandom`. Stop.
- **NumPy has its own generator.** `numpy.random.seed`/`RandomState` is MT19937 too
  (same state layout, 624 words) but `default_rng()` is PCG64 - completely different,
  see `prng-xorshift-v8-math-random` for the PCG family.
- **`random.sample` draw counts are data-dependent.** For `k` small relative to the
  population it uses a selection set with retries; for large `k` it copies and partial-
  shuffles. Do not hard-code an accounting for it.
- **Modulo bias as an oracle.** If the target does `getrandbits(32) % 10`, the residue
  distribution is (almost) uniform because 2^32 % 10 is small relative to 2^32 - the
  bias only matters when `n` is a large fraction of 2^32. Check before claiming it.
- **`choices(k=...)` uses `random()`**, so each pick is 2 outputs, not 1.
- **Python 2.** `random.seed(str)` there uses `hash()`, which is 32/64-bit and
  collision-prone - a much smaller brute-force space.

## Tools

- **randcrack** - `submit()` 624 `getrandbits(32)` values, then predict.
- **mt19937predictor** - accepts partial-width feeds via `setrandbits(value, bits)`.
- **z3** - for `random()` floats, truncated outputs or interleaved unknown draws.
- **CPython source** - `Lib/random.py` and `Modules/_randommodule.c` are short; read
  them rather than guessing.

## References

- CPython `Lib/random.py` - <https://github.com/python/cpython/blob/main/Lib/random.py>
- CPython `Modules/_randommodule.c` - <https://github.com/python/cpython/blob/main/Modules/_randommodule.c>
- Python `random` documentation - <https://docs.python.org/3/library/random.html>
- randcrack - <https://github.com/tna0y/Python-random-module-cracker>
