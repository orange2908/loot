---
title: "java.util.Random Prediction and SecureRandom Misuse"
category: crypto
subcategory: prng
type: technique
tags: [java-random, java-util-random, nextint, nextlong, nextdouble, nextgaussian, lcg, 48-bit, seed-recovery, securerandom, sha1prng, seeduniquifier, nanotime, threadlocalrandom, splittablerandom, android-securerandom, prng]
difficulty: medium
summary: "java.util.Random is a 48-bit LCG whose nextInt() shows 32 of those bits - brute force the 16 missing bits and you own the stream forwards and backwards."
when_to_use:
  - "Java/Kotlin/Scala/Android target generates tokens, IDs, passwords or shuffles"
  - "You see `new Random()`, `new Random(System.currentTimeMillis())`, `Math.random()`"
  - "Two consecutive `nextInt()` values, or one `nextLong()`, are observable"
  - "`SecureRandom` is used with `setSeed` on a fixed value, or on old Android"
tools: [python, java, jd-gui, jadx]
related: [prng-lcg-recovery, prng-truncated-lcg-lattice, prng-mt19937-seed-bruteforce, prng-toolkit, prng-cheatsheet]
---

## TL;DR

`java.util.Random` is `seed = (seed * 0x5DEECE66D + 0xB) mod 2**48`, and `next(bits)`
returns the **top** `bits` of the new seed. `nextInt()` therefore shows you 32 of 48
bits: brute force the missing $2^{16}$ and check against a second output. One
`nextLong()` (two `next(32)` calls) is enough on its own. Once you have the 48-bit
seed you can step forwards *and* backwards, and recover the original `setSeed`
argument by XORing with `0x5DEECE66D`.

## Recognise it

- `new Random(...)`, `Math.random()` (a shared `Random`), `Collections.shuffle(list)`
  (uses a `Random`), `UUID.randomUUID()` (uses `SecureRandom` - different, see below).
- Decompiled constants `0x5DEECE66DL`, `0xBL`, `(1L << 48) - 1`, `>>> (48 - bits)`.
- Tokens that are 32 bits of entropy, or 8 hex chars, or an `int` cast to a string.
- `new Random(System.currentTimeMillis())` or `new Random(userId)` - seed brute force.
- `SecureRandom.getInstance("SHA1PRNG")` followed by `setSeed(constant)`.

## Theory

**Seeding.** `new Random(s)` and `setSeed(s)` store
`seed = (s ^ 0x5DEECE66D) & ((1<<48)-1)`. So the *scrambled* seed you recover is
`original ^ 0x5DEECE66D`; XOR it back to get the number the programmer wrote.

**Core step.**
```
next(bits):
    seed = (seed * 0x5DEECE66D + 0xB) & ((1<<48)-1)
    return (int)(seed >>> (48 - bits))
```

**The public API in terms of `next`.**

| call | consumption |
|---|---|
| `nextInt()` | `next(32)` - one step, top 32 of 48 bits |
| `nextInt(bound)` | `next(31)`; power-of-two bound uses one step, otherwise rejection-samples |
| `nextLong()` | `((long)next(32) << 32) + next(32)` - **two** steps, both halves signed |
| `nextBoolean()` | `next(1)` - one step, top bit |
| `nextFloat()` | `next(24) / 2**24` - one step |
| `nextDouble()` | `((long)next(26) << 27) + next(27)) / 2**53` - two steps |
| `nextGaussian()` | polar method: pairs of `nextDouble()` until `s < 1`, and it **caches** the second value |

**Attack 1 - one `nextInt()` plus a check.** `v = seed_new >> 16`, so
`seed_new = (v << 16) | x` for one of $2^{16}$ values of `x`. For each candidate, step
once and compare against the next observed `nextInt()`. Exactly one survives.

**Attack 2 - one `nextLong()`.** 64 observed bits over a 48-bit state: the high 32
bits fix `seed_1 >> 16`, so brute force $2^{16}$ and verify with the low 32 bits. Note
that both halves are *signed* ints and Java **adds** them, so a negative low half
borrows 1 from the high half - add it back before splitting.

**Attack 3 - going backwards.** `seed_prev = (seed - 0xB) * inv(0x5DEECE66D) mod
2**48`. So a token issued *before* the ones you saw is recoverable too.

**Attack 4 - weak seeds.** `new Random(System.currentTimeMillis())` is a millisecond
timestamp: a 10-second window is 10,000 candidates.

**Unseeded `new Random()`.** Java uses
`seedUniquifier() ^ System.nanoTime()` where `seedUniquifier` starts at
`8682522807148012L` and is multiplied by `1181783497276652981L` on each call
(atomically, per JVM). So the entropy is `nanoTime()` plus a count of how many
`Random`s were constructed - guessable if you can pin the process start and the
allocation order. Treat it as weak, not as unbreakable.

**`SecureRandom` misuse.**
- `SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); sr.setSeed(fixed);` -
  in the SUN provider, `setSeed` *before any output* **replaces** the seed rather than
  mixing, so the stream is fully deterministic from `fixed`.
- `new SecureRandom(byte[] seed)` - same problem when the byte array is a constant, a
  timestamp, or a user id.
- The 2013 **Android SecureRandom** bug: `SecureRandom` was not properly seeded on some
  devices, which broke Bitcoin wallet key generation.
- `SecureRandom.getInstance("SHA1PRNG")` is *not* a standardised algorithm; behaviour
  differs between providers. If a challenge asks you to reproduce it, replicate the
  exact provider (SUN's SHA1PRNG: state = SHA-1 of (seed || counter) with a carry).
- Correct usage is `new SecureRandom()` with no seed (or `SecureRandom.getInstanceStrong()`),
  which reads from the OS - not attackable.

**Other Java generators.** `ThreadLocalRandom` uses a mix of `SplittableRandom`'s
64-bit SplitMix-style step - much stronger than `Random` but still not a CSPRNG;
`SplittableRandom` is SplitMix64 with a gamma, invertible from one output (see
`prng-xorshift-v8-math-random`). `java.util.random.RandomGenerator` (JDK 17+) exposes
L64X128MixRandom and friends.

## Attack

1. Confirm the generator from decompiled code (`0x5DEECE66D` is unmistakable).
2. Work out exactly which `next(bits)` calls the observable corresponds to.
3. Recover the 48-bit scrambled seed: brute force $2^{16}$ against a second observation.
4. XOR with `0x5DEECE66D` to get the literal seed the code used - often the flag, a
   timestamp, or a user id.
5. Step forwards for future tokens, backwards for earlier ones.
6. If the observable is `nextInt(bound)` with a small bound, you get ~`log2(bound)`
   bits per call: collect enough calls that the total exceeds 48 bits, then brute force
   the top 16 unknown bits of the first state with the whole sequence as the check.

## Code

```python
#!/usr/bin/env python3
"""java.util.Random: exact reimplementation plus seed recovery forwards and backwards.

Verified against OpenJDK:
    new Random(42).nextInt() x3  -> -1170105035, 234785527, -1360544799
    new Random(42).nextLong()    -> -5025562857975149833
    new Random(42).nextDouble()  -> 0.7275636800328681
    new Random(12345).nextInt(100) x3 -> 51, 80, 41
"""
from __future__ import annotations

import math

MULT = 0x5DEECE66D
ADD = 0xB
MASK48 = (1 << 48) - 1
INV_MULT = pow(MULT, -1, 1 << 48)


def to_signed32(v: int) -> int:
    return v - (1 << 32) if v >= (1 << 31) else v


def to_signed64(v: int) -> int:
    return v - (1 << 64) if v >= (1 << 63) else v


class JavaRandom:
    def __init__(self, seed: int | None = None, *, raw_state: int | None = None):
        if raw_state is not None:
            self.seed = raw_state & MASK48
        else:
            self.set_seed(0 if seed is None else seed)
        self._next_gaussian: float | None = None

    def set_seed(self, seed: int) -> None:
        self.seed = (seed ^ MULT) & MASK48
        self._next_gaussian = None

    def next(self, bits: int) -> int:
        self.seed = (self.seed * MULT + ADD) & MASK48
        return self.seed >> (48 - bits)

    def next_int(self) -> int:
        return to_signed32(self.next(32))

    def next_int_bound(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        if bound & -bound == bound:                    # power of two
            return (bound * self.next(31)) >> 31
        while True:
            bits = self.next(31)
            val = bits % bound
            if to_signed32((bits - val + (bound - 1)) & 0xFFFFFFFF) >= 0:
                return val

    def next_long(self) -> int:
        hi = to_signed32(self.next(32))
        lo = to_signed32(self.next(32))
        return to_signed64(((hi << 32) + lo) & ((1 << 64) - 1))

    def next_boolean(self) -> bool:
        return self.next(1) != 0

    def next_float(self) -> float:
        return self.next(24) / float(1 << 24)

    def next_double(self) -> float:
        return ((self.next(26) << 27) + self.next(27)) / float(1 << 53)

    def next_gaussian(self) -> float:
        if self._next_gaussian is not None:
            v, self._next_gaussian = self._next_gaussian, None
            return v
        while True:
            v1 = 2 * self.next_double() - 1
            v2 = 2 * self.next_double() - 1
            s = v1 * v1 + v2 * v2
            if s < 1 and s != 0:
                break
        mul = math.sqrt(-2 * math.log(s) / s)
        self._next_gaussian = v2 * mul
        return v1 * mul


def prev_state(state: int) -> int:
    """Rewind the 48-bit LCG one step."""
    return ((state - ADD) * INV_MULT) & MASK48


def unscramble_seed(state: int) -> int:
    """The literal value the programmer passed to new Random(...) / setSeed(...)."""
    return state ^ MULT


def crack_from_two_nextints(v1: int, v2: int) -> int | None:
    """Return the 48-bit state AFTER the first nextInt(), or None."""
    target1 = v1 & 0xFFFFFFFF
    target2 = v2 & 0xFFFFFFFF
    for low in range(1 << 16):
        state = (target1 << 16) | low
        if ((state * MULT + ADD) & MASK48) >> 16 == target2:
            return state
    return None


def crack_from_nextlong(value: int) -> int | None:
    """One nextLong() is 64 observed bits over a 48-bit state - enough on its own.

    Careful: nextLong() is ((long)next(32) << 32) + next(32) with BOTH halves signed,
    so when the low half is negative the addition borrows from the high half. Undo
    that before splitting.
    """
    v = value & ((1 << 64) - 1)
    lo = v & 0xFFFFFFFF
    hi = ((v >> 32) + (1 if lo >= (1 << 31) else 0)) & 0xFFFFFFFF
    for low in range(1 << 16):
        state = (hi << 16) | low
        if ((state * MULT + ADD) & MASK48) >> 16 == lo:
            return state
    return None


def crack_from_bounded(values, bound: int, first_next31: int | None = None):
    """nextInt(bound) leaks only log2(bound) bits per call.

    Strategy: brute force the 48-bit state that reproduces the WHOLE sequence,
    anchored on a known next(31) if you have one, else over 2**48 (too slow) - so in
    practice you need another observable. Provided here for the anchored case.
    """
    if first_next31 is None:
        raise ValueError("need an anchor: a full next(31)/next(32) observation")
    for low in range(1 << 17):
        state = ((first_next31 << 17) | low) & MASK48
        r = JavaRandom(raw_state=state)
        if [r.next_int_bound(bound) for _ in values] == list(values):
            return state
    return None


def brute_force_time_seed(observed, candidates):
    """new Random(System.currentTimeMillis()) - milliseconds, so a small window."""
    n = len(observed)
    for s in candidates:
        r = JavaRandom(s)
        if [r.next_int() for _ in range(n)] == list(observed):
            return s
    return None


SEED_UNIQUIFIER_START = 8682522807148012
SEED_UNIQUIFIER_MULT = 1181783497276652981


def seed_uniquifier_chain(count: int):
    """The values `new Random()` (no args) XORs with System.nanoTime()."""
    out, u = [], SEED_UNIQUIFIER_START
    for _ in range(count):
        u = (u * SEED_UNIQUIFIER_MULT) & ((1 << 64) - 1)
        out.append(to_signed64(u))
    return out


if __name__ == "__main__":
    # --- known-answer tests against OpenJDK -------------------------------
    r = JavaRandom(42)
    got = [r.next_int() for _ in range(3)]
    assert got == [-1170105035, 234785527, -1360544799], got
    print(f"[ok] new Random(42).nextInt() x3 == {got}")

    assert JavaRandom(42).next_long() == -5025562857975149833
    assert JavaRandom(42).next_double() == 0.7275636800328681
    assert JavaRandom(42).next_boolean() is True
    assert abs(JavaRandom(42).next_float() - 0.7275637) < 1e-6
    assert abs(JavaRandom(42).next_gaussian() - 1.1419053154730547) < 1e-12
    z = JavaRandom(12345)
    assert [z.next_int_bound(100) for _ in range(3)] == [51, 80, 41]
    assert [JavaRandom(0).next_int() for _ in range(1)] == [-1155484576]
    print("[ok] nextLong / nextDouble / nextBoolean / nextFloat / nextGaussian / "
          "nextInt(bound) all match OpenJDK")

    # --- crack the state from two nextInt() values ------------------------
    victim = JavaRandom(0xC0FFEE)
    a, b = victim.next_int(), victim.next_int()
    state = crack_from_two_nextints(a, b)
    assert state is not None
    clone = JavaRandom(raw_state=state)
    assert clone.next_int() == b                       # resync past the second value
    assert [clone.next_int() for _ in range(5)] == [victim.next_int() for _ in range(5)]
    print("[ok] recovered the 48-bit state from two nextInt() values")

    # --- recover the literal seed -----------------------------------------
    # crack_from_two_nextints returns the state AFTER the first next(32), so one
    # rewind lands on the scrambled seed itself.
    s0 = prev_state(state)
    assert unscramble_seed(s0) == 0xC0FFEE, hex(unscramble_seed(s0))
    print(f"[ok] unscrambled the literal seed: {unscramble_seed(s0):#x}")

    # --- backwards prediction ---------------------------------------------
    v2 = JavaRandom(777)
    earlier = [v2.next_int() for _ in range(4)]
    later_state = crack_from_two_nextints(earlier[2], earlier[3])
    back = later_state
    rewound = [to_signed32(back >> 16)]                 # == earlier[2]
    for _ in range(2):
        back = prev_state(back)
        rewound.append(to_signed32(back >> 16))
    assert rewound == [earlier[2], earlier[1], earlier[0]], (rewound, earlier)
    print(f"[ok] rewound to earlier outputs: {list(reversed(rewound))}")

    # --- one nextLong() is enough -----------------------------------------
    v3 = JavaRandom(0xBAD5EED)
    lv = v3.next_long()
    st = crack_from_nextlong(lv)
    assert st is not None
    c3 = JavaRandom(raw_state=st)
    c3.next_int()                                      # consume the low half
    assert c3.next_long() == v3.next_long()
    print("[ok] recovered the state from a single nextLong()")

    # --- weak seed: new Random(System.currentTimeMillis()) ----------------
    secret_ms = 1_735_689_600_123
    obs = [JavaRandom(secret_ms).next_int()]
    found = brute_force_time_seed(obs, range(secret_ms - 3000, secret_ms + 3000))
    assert found == secret_ms, found
    print(f"[ok] brute forced a millisecond time seed: {found}")

    # --- nextInt(bound) with an anchor ------------------------------------
    v4 = JavaRandom(4242)
    anchor = v4.next(31)                               # one full 31-bit observation
    seq = [v4.next_int_bound(6) for _ in range(8)]     # dice rolls
    st4 = crack_from_bounded(seq, 6, first_next31=anchor)
    assert st4 is not None
    c4 = JavaRandom(raw_state=st4)
    assert [c4.next_int_bound(6) for _ in range(8)] == seq
    print(f"[ok] recovered the state behind 8 nextInt(6) dice rolls: {seq}")

    # --- the seedUniquifier chain -----------------------------------------
    chain = seed_uniquifier_chain(3)
    assert len(chain) == 3 and all(isinstance(x, int) for x in chain)
    print(f"[ok] new Random() seed = seedUniquifier ^ nanoTime; "
          f"first uniquifiers: {chain}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **`nextInt()` vs `nextInt(bound)`.** The first is `next(32)`, the second is
  `next(31)` with rejection. Mixing them up shifts everything by a bit.
- **`nextLong()` consumes two steps** and its result is a *signed* 64-bit value; in
  Python remember to sign-correct.
- **`nextGaussian()` caches.** It generates two values and returns them on alternate
  calls, and the rejection loop consumes a variable number of `nextDouble()`s (each
  itself two steps). Do not try to count steps through Gaussians - anchor elsewhere.
- **`Math.random()`** in Java lazily creates one shared `Random` seeded the unseeded
  way. Every thread in the JVM shares that stream.
- **`Collections.shuffle(list)`** without an explicit `Random` also uses that shared
  instance; with an explicit one it is Fisher-Yates using `nextInt(i+1)` - invertible
  exactly like Python's (see `prng-python-random`).
- **`ThreadLocalRandom.current()`** is not `java.util.Random` despite extending it.
  Its state is per-thread SplitMix-style; the 48-bit attack does not apply.
- **Kotlin `Random.Default`** is an xorshift-family generator, not the Java LCG.
  `kotlin.random.Random(seed)` is also its own implementation.
- **Android.** `java.util.Random` behaves identically. `SecureRandom` on API < 19 had
  the seeding bug; on modern Android it is fine.
- **`SecureRandom.setSeed` semantics differ by provider.** In SUN's SHA1PRNG a
  `setSeed` before the first `nextBytes` *sets* the state; afterwards it *mixes*. In
  the NativePRNG provider `setSeed` only mixes. Read the provider.
- **Seeds that are the flag.** `new Random(flagAsLong)` is a favourite CTF shape -
  recover the state, `unscramble_seed`, and convert the integer to bytes.
- **`nextInt(bound)` with a power-of-two bound** takes the *high* bits
  (`(bound * next(31)) >> 31`) and never rejects - a different code path entirely.

## Tools

- **A throwaway `.java` file** - the fastest ground truth. `javac T.java && java T`.
- **jadx / jd-gui / CFR** - to read the decompiled generator usage.
- **untwister** - <https://github.com/altf4/untwister> - has a Java `Random` mode.
- **z3** - overkill here; $2^{16}$ brute force is instant.

## References

- OpenJDK `java.util.Random` source - <https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/java/util/Random.java>
- `java.util.Random` API documentation - <https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Random.html>
- `SecureRandom` API documentation - <https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/SecureRandom.html>
- Android Developers Blog, "Some SecureRandom Thoughts" (2013) - <https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html>
