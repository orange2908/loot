---
title: "prng-toolkit.py - MT19937 State Recovery, LCG Parameter Recovery and a glibc rand() Clone"
category: crypto
subcategory: prng
type: script
tags: [prng, mt19937, mersenne-twister, untemper, untwist, state-recovery, backward-prediction, lcg, linear-congruential, parameter-recovery, glibc, rand, random, srandom, seed-bruteforce, randcrack, offline, python]
summary: "One dependency-free script: clone Python's MT19937 from 624 outputs (and rewind it), recover a, c, m for any LCG, and reproduce glibc random() exactly."
tools: [python]
related: [prng-mt19937-state-recovery, prng-mt19937-seed-bruteforce, prng-lcg-recovery, prng-glibc-rand, prng-cheatsheet]
---

## What it does

Three independent tools in one file, all pure stdlib:

1. **MT19937** - `untemper`, state recovery from 624 consecutive 32-bit outputs,
   a `random.Random` clone for forward prediction, and `untwist` for **backward**
   prediction (outputs produced *before* the ones you observed).
2. **LCG** - recover `m` (gcd of `t[i+2]*t[i] - t[i+1]**2`), then `a` and `c`,
   with or without a known modulus; predict forwards and backwards.
3. **glibc `random()`** - an exact TYPE_3 additive-feedback reimplementation
   (including the 310-output warm-up) plus a time-seed brute forcer.

```sh
python3 prng_toolkit.py --selftest
python3 prng_toolkit.py mt19937 outputs.txt      # >=624 decimal values, one per line
python3 prng_toolkit.py lcg outputs.txt          # >=6 decimal values
python3 prng_toolkit.py glibc 12345              # print the first outputs for a seed
python3 prng_toolkit.py glibc-seed outputs.txt   # brute force srandom(time()) +/- 1 day
```

## Script

```python
#!/usr/bin/env python3
"""prng_toolkit.py - MT19937, LCG and glibc random() offline attack toolkit.

Pure stdlib. Run with --selftest to verify every component against Python's own
random module and against the published glibc test vector.
"""
from __future__ import annotations

import random
import sys
import time
from functools import reduce
from math import gcd

# ===========================================================================
# MT19937
# ===========================================================================
N = 624
M = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
MASK32 = 0xFFFFFFFF


def temper(y: int) -> int:
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y &= MASK32
    y ^= y >> 18
    return y


def _unshift_right(y: int, shift: int) -> int:
    x = y
    for _ in range(-(-32 // shift)):
        x = y ^ (x >> shift)
    return x & MASK32


def _unshift_left(y: int, shift: int, mask: int) -> int:
    x = y
    for _ in range(-(-32 // shift)):
        x = y ^ ((x << shift) & mask)
    return x & MASK32


def untemper(y: int) -> int:
    """Exact inverse of temper(): tempering is a bijection on 32 bits."""
    y = _unshift_right(y, 18)
    y = _unshift_left(y, 15, 0xEFC60000)
    y = _unshift_left(y, 7, 0x9D2C5680)
    y = _unshift_right(y, 11)
    return y


def twist(mt) -> list[int]:
    """One forward twist over a 624-word state."""
    mt = list(mt)
    for i in range(N):
        y = (mt[i] & UPPER_MASK) | (mt[(i + 1) % N] & LOWER_MASK)
        mt[i] = mt[(i + M) % N] ^ (y >> 1)
        if y & 1:
            mt[i] ^= MATRIX_A
    return mt


def untwist(mt) -> list[int]:
    """Invert one twist: current block's state -> previous block's state."""
    mt = list(mt)
    for i in range(N - 1, -1, -1):
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


class MT19937:
    """Standalone generator - use it when the target is not Python."""

    def __init__(self, seed: int | None = None):
        self.mt = [0] * N
        self.index = N
        if seed is not None:
            self.seed_int(seed)

    def seed_int(self, seed: int) -> None:
        """init_genrand: the classic 32-bit seeding routine (C++, PHP, numpy)."""
        self.mt[0] = seed & MASK32
        for i in range(1, N):
            prev = self.mt[i - 1]
            self.mt[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & MASK32
        self.index = N

    def set_state(self, words, index: int = N) -> None:
        if len(words) != N:
            raise ValueError(f"state must be {N} words")
        self.mt = list(words)
        self.index = index

    def next_u32(self) -> int:
        if self.index >= N:
            self.mt = twist(self.mt)
            self.index = 0
        y = temper(self.mt[self.index])
        self.index += 1
        return y


def mt_recover_state(outputs) -> list[int]:
    """624 consecutive raw 32-bit outputs -> the state words behind them."""
    if len(outputs) < N:
        raise ValueError(f"need {N} consecutive outputs, got {len(outputs)}")
    return [untemper(o) for o in outputs[-N:]]


def mt_clone_python(outputs) -> random.Random:
    """A random.Random positioned exactly where the victim's generator is."""
    return _load(mt_recover_state(outputs))


def _load(state) -> random.Random:
    r = random.Random()
    r.setstate((3, tuple(list(state) + [N]), None))
    return r


def mt_predict_forward(outputs, count: int) -> list[int]:
    clone = mt_clone_python(outputs)
    return [clone.getrandbits(32) for _ in range(count)]


def mt_predict_backward(outputs, count: int) -> list[int]:
    """Outputs produced BEFORE the 624 you observed, oldest first."""
    if count > N:
        raise ValueError("call untwist repeatedly to rewind more than one block")
    prev = untwist(mt_recover_state(outputs))
    past = [temper(w) for w in prev]
    return past[N - count:]


def mt_brute_force_seed(observed, candidates, draw=None):
    """Find the Python seed reproducing `observed`. draw(rng) -> list."""
    if draw is None:
        def draw(rng, k=len(observed)):
            return [rng.getrandbits(32) for _ in range(k)]
    target = list(observed)
    for s in candidates:
        if draw(random.Random(s))[:len(target)] == target:
            return s
    return None


# ===========================================================================
# LCG:  s[n+1] = a*s[n] + c  (mod m)
# ===========================================================================
class LCG:
    def __init__(self, seed: int, a: int, c: int, m: int):
        self.a, self.c, self.m = a, c, m
        self.state = seed % m

    def next(self) -> int:
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def take(self, n: int) -> list[int]:
        return [self.next() for _ in range(n)]


KNOWN_LCGS = {
    "glibc TYPE_0 / ANSI C": (1103515245, 12345, 2 ** 31),
    "java.util.Random / drand48": (0x5DEECE66D, 0xB, 2 ** 48),
    "MSVC rand()": (214013, 2531011, 2 ** 31),
    "Borland rand()": (22695477, 1, 2 ** 32),
    "MMIX (Knuth)": (6364136223846793005, 1442695040888963407, 2 ** 64),
    "Numerical Recipes": (1664525, 1013904223, 2 ** 32),
    "RANDU": (65539, 0, 2 ** 31),
}


def lcg_recover_modulus(outputs) -> int:
    """m divides every t[i+2]*t[i] - t[i+1]**2 where t[i] = s[i+1] - s[i]."""
    if len(outputs) < 5:
        raise ValueError("need at least 5 outputs (6+ is comfortable)")
    t = [b - a for a, b in zip(outputs, outputs[1:])]
    u = [t[i + 2] * t[i] - t[i + 1] ** 2 for i in range(len(t) - 2)]
    m = abs(reduce(gcd, u))
    if m == 0:
        raise ValueError("degenerate sequence (constant differences?)")
    return m


def _solve_congruence(d: int, e: int, m: int, limit: int = 1 << 14):
    """All a with a*d == e (mod m); there are gcd(d, m) of them when solvable."""
    g = gcd(d % m, m)
    if g == 0 or e % g or g > limit:
        return []
    dg, eg, mg = (d % m) // g, (e % m) // g, m // g
    a0 = (eg * pow(dg, -1, mg)) % mg
    return [(a0 + k * mg) % m for k in range(g)]


def _candidate_multipliers(outputs, m: int) -> list[int]:
    best: list[int] = []
    for i in range(len(outputs) - 2):
        cands = _solve_congruence(outputs[i + 1] - outputs[i],
                                  outputs[i + 2] - outputs[i + 1], m)
        if cands and (not best or len(cands) < len(best)):
            best = cands
            if len(best) == 1:
                break
    return best


def _fits(outputs, a: int, c: int, m: int) -> bool:
    return all((a * x + c) % m == y % m for x, y in zip(outputs, outputs[1:]))


def _candidate_moduli(m: int, floor: int, depth: int = 64):
    """The gcd can be a small multiple of the true modulus - peel small factors."""
    seen, queue = set(), [m]
    while queue:
        v = queue.pop(0)
        if v in seen or v <= floor or len(seen) > depth:
            continue
        seen.add(v)
        yield v
        for p in (2, 3, 5, 7, 11, 13):
            if v % p == 0:
                queue.append(v // p)


def lcg_recover(outputs, m: int | None = None):
    """Return (a, c, m), verified against the observed sequence."""
    def attempt(mod):
        for a in _candidate_multipliers(outputs, mod):
            c = (outputs[1] - a * outputs[0]) % mod
            if _fits(outputs, a, c, mod):
                return a, c, mod
        return None

    if m is not None:
        got = attempt(m)
        if got:
            return got
        raise ValueError(f"no (a, c) reproduces the sequence for m={m}")
    for cand in _candidate_moduli(lcg_recover_modulus(outputs), max(outputs)):
        got = attempt(cand)
        if got:
            return got
    raise ValueError("no LCG parameters fit (truncated outputs, or not an LCG)")


def lcg_forward(last: int, a: int, c: int, m: int, count: int) -> list[int]:
    out, s = [], last
    for _ in range(count):
        s = (a * s + c) % m
        out.append(s)
    return out


def lcg_backward(first: int, a: int, c: int, m: int, count: int) -> list[int]:
    """Values BEFORE `first`, oldest first. Needs gcd(a, m) == 1."""
    ai = pow(a, -1, m)
    out, s = [], first
    for _ in range(count):
        s = (ai * (s - c)) % m
        out.append(s)
    return list(reversed(out))


def lcg_identify(a: int, c: int, m: int):
    for name, params in KNOWN_LCGS.items():
        if params == (a, c, m):
            return name
    return None


# ===========================================================================
# glibc / BSD random()  (TYPE_3 additive feedback)
# ===========================================================================
MOD31 = 1 << 31


class GlibcRandom:
    """srandom()/random() with the default 128-byte state.

    Verified: srandom(12345) -> 383100999, 858300821, 357768173, 455528251, ...
    """

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
            hi, lo = divmod(r[i - 1], 127773)          # Schrage's trick
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


def glibc_brute_force_seed(observed, candidates):
    n = len(observed)
    for s in candidates:
        if GlibcRandom(s).take(n) == list(observed):
            return s
    return None


def glibc_predict(outputs, count: int):
    """From >=31 outputs, each prediction is (S, S+1): a one-bit carry ambiguity."""
    if len(outputs) < 31:
        raise ValueError("need at least 31 consecutive outputs")
    hist, preds = list(outputs), []
    for _ in range(count):
        s = (hist[-3] + hist[-31]) % MOD31
        preds.append((s, (s + 1) % MOD31))
        hist.append(s)
    return preds


def looks_like_glibc(outputs) -> bool:
    if len(outputs) < 40:
        return False
    diffs = {(outputs[i] - outputs[i - 3] - outputs[i - 31]) % MOD31
             for i in range(31, len(outputs))}
    return diffs <= {0, 1}


# ===========================================================================
# CLI
# ===========================================================================
def _read_ints(path: str) -> list[int]:
    data = sys.stdin.read() if path == "-" else open(path).read()
    return [int(tok, 0) for tok in data.split()]


def cmd_mt19937(path: str) -> int:
    outs = _read_ints(path)
    print(f"read {len(outs)} outputs")
    clone = mt_clone_python(outs)
    print("next 10 getrandbits(32):",
          [clone.getrandbits(32) for _ in range(10)])
    print("previous 10 (backwards):", mt_predict_backward(outs, 10))
    return 0


def cmd_lcg(path: str) -> int:
    outs = _read_ints(path)
    a, c, m = lcg_recover(outs)
    name = lcg_identify(a, c, m)
    print(f"a={a} c={c} m={m}" + (f"   ({name})" if name else ""))
    print("next 10:", lcg_forward(outs[-1], a, c, m, 10))
    print("previous 5:", lcg_backward(outs[0], a, c, m, 5))
    return 0


def cmd_glibc(seed: str) -> int:
    print(GlibcRandom(int(seed, 0)).take(10))
    return 0


def cmd_glibc_seed(path: str) -> int:
    outs = _read_ints(path)
    now = int(time.time())
    found = glibc_brute_force_seed(outs[:2], range(now - 86400, now + 1))
    print(f"seed = {found}" if found else "not found in the last 24 hours")
    return 0 if found else 1


USAGE = ("commands: --selftest | mt19937 FILE | lcg FILE | glibc SEED | "
         "glibc-seed FILE   (FILE may be '-' for stdin)")


def main(argv) -> int:
    if len(argv) > 1 and argv[1] in ("-h", "--help"):
        print(__doc__)
        print(USAGE)
        return 0
    if len(argv) < 2:
        # Run bare: self-test, so the file is always verifiable on its own.
        print(USAGE, file=sys.stderr)
        return selftest()
    cmd = argv[1]
    if cmd == "--selftest":
        return selftest()
    if len(argv) < 3:
        print("missing argument", file=sys.stderr)
        return 1
    return {
        "mt19937": cmd_mt19937,
        "lcg": cmd_lcg,
        "glibc": cmd_glibc,
        "glibc-seed": cmd_glibc_seed,
    }[cmd](argv[2])


# ===========================================================================
# Self-test
# ===========================================================================
def selftest() -> int:
    ok = 0

    # --- MT19937: untemper is exact ---------------------------------------
    rng = random.Random(0xC0FFEE)
    for _ in range(2000):
        v = rng.getrandbits(32)
        assert temper(untemper(v)) == v
    print("[ok] untemper(temper(x)) == x over 2000 samples")
    ok += 1

    # --- MT19937: clone Python's random -----------------------------------
    victim = random.Random(1337)
    observed = [victim.getrandbits(32) for _ in range(N)]
    assert mt_predict_forward(observed, 10) == \
        [victim.getrandbits(32) for _ in range(10)]
    print("[ok] MT19937 forward prediction matches Python exactly")
    ok += 1

    # --- MT19937: higher-level APIs ---------------------------------------
    v2 = random.Random(2024)
    obs2 = [v2.getrandbits(32) for _ in range(N)]
    c2 = mt_clone_python(obs2)
    assert v2.randint(0, 10 ** 9) == c2.randint(0, 10 ** 9)
    deck_a, deck_b = list(range(20)), list(range(20))
    v2.shuffle(deck_a)
    c2.shuffle(deck_b)
    assert deck_a == deck_b
    assert v2.random() == c2.random()
    print("[ok] randint / shuffle / random() predicted through the clone")
    ok += 1

    # --- MT19937: backward prediction -------------------------------------
    v3 = random.Random(999)
    all_out = [v3.getrandbits(32) for _ in range(2 * N)]
    assert mt_predict_backward(all_out[N:], N) == all_out[:N]
    print(f"[ok] MT19937 backward prediction recovered all {N} earlier outputs")
    ok += 1

    # --- MT19937: twist/untwist are inverses ------------------------------
    st = mt_recover_state(observed)
    assert untwist(twist(st)) == st
    print("[ok] untwist(twist(state)) == state")
    ok += 1

    # --- MT19937: standalone class agrees with the clone ------------------
    ref = MT19937()
    ref.set_state(mt_recover_state(observed), index=N)
    clone = mt_clone_python(observed)
    assert [ref.next_u32() for _ in range(5)] == \
        [clone.getrandbits(32) for _ in range(5)]
    assert MT19937(5489).next_u32() == 3499211612      # canonical init_genrand
    print("[ok] standalone MT19937 matches CPython and the init_genrand vector")
    ok += 1

    # --- MT19937: seed brute force ----------------------------------------
    secret = 1_735_689_600
    token = random.Random(secret).getrandbits(32)
    assert mt_brute_force_seed([token], range(secret - 5000, secret + 5000)) == secret
    print("[ok] MT19937 timestamp seed recovered from one 32-bit output")
    ok += 1

    # --- LCG: full recovery -----------------------------------------------
    a, c, m = KNOWN_LCGS["glibc TYPE_0 / ANSI C"]
    g = LCG(987654321, a, c, m)
    outs = g.take(10)
    assert lcg_recover(outs) == (a, c, m)
    assert lcg_forward(outs[-1], a, c, m, 5) == g.take(5)
    assert lcg_backward(outs[0], a, c, m, 1)[0] == 987654321
    assert lcg_identify(a, c, m) == "glibc TYPE_0 / ANSI C"
    print("[ok] LCG a, c, m recovered from 10 outputs; forward and backward verified")
    ok += 1

    # --- LCG: 64-bit and multiplicative cases -----------------------------
    a2, c2_, m2 = KNOWN_LCGS["MMIX (Knuth)"]
    assert lcg_recover(LCG(0xDEADBEEF, a2, c2_, m2).take(12)) == (a2, c2_, m2)
    a3, c3, m3 = KNOWN_LCGS["RANDU"]
    ra, rc, rm = lcg_recover(LCG(1, a3, c3, m3).take(10))
    assert (ra, rc) == (a3, c3), (ra, rc, rm)
    assert lcg_recover(LCG(12345, *KNOWN_LCGS["java.util.Random / drand48"]).take(3),
                       m=2 ** 48) == KNOWN_LCGS["java.util.Random / drand48"]
    print("[ok] LCG: 64-bit MMIX, multiplicative RANDU, and known-modulus Java")
    ok += 1

    # --- glibc random(): known-answer test --------------------------------
    first = GlibcRandom(12345).take(4)
    assert first == [383100999, 858300821, 357768173, 455528251], first
    assert GlibcRandom(0).take(3) == GlibcRandom(1).take(3)
    print(f"[ok] glibc srandom(12345) -> {first} (matches libc)")
    ok += 1

    # --- glibc: structure and prediction ----------------------------------
    stream = GlibcRandom(0xC0FFEE).take(400)
    assert all(0 <= v < MOD31 for v in stream)
    assert looks_like_glibc(stream)
    window, rest = stream[:31], stream[31:41]
    preds = glibc_predict(window, 10)
    assert preds[0][0] == rest[0] or preds[0][1] == rest[0]
    print("[ok] glibc structural test passes and the next output is one of two values")
    ok += 1

    # --- glibc: time-seed brute force -------------------------------------
    gsecret = 1_735_689_600
    leaked = GlibcRandom(gsecret).take(2)
    assert glibc_brute_force_seed(leaked, range(gsecret - 3000,
                                                gsecret + 3000)) == gsecret
    print("[ok] glibc srandom(time(NULL)) seed recovered from 2 outputs")
    ok += 1

    print(f"all {ok} self-tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

## Notes

- **Feed it raw outputs.** `getrandbits(32)` is one MT19937 output; `randint`,
  `random()` and `shuffle` are not. See `prng-python-random` for the exact
  accounting before you collect data.
- **`mt_predict_backward` rewinds one block (624 outputs).** Call `untwist` again on
  the returned state to go further back.
- **The LCG recovery verifies itself.** If it raises, either the outputs are
  truncated (go to `prng-truncated-lcg-lattice`) or the generator is not a plain LCG
  (glibc `random()` is not).
- **`lcg_recover` may return a multiple/divisor of the "true" modulus.** If it
  reproduces and predicts the sequence, it is operationally the same generator.
- **glibc prediction has a one-bit carry ambiguity** because `random()` drops the low
  bit of each state word. The true value is `S` about 75% of the time and `S+1`
  otherwise; feed the real value back when you can observe it.
- **`glibc-seed` searches the last 24 hours by default.** Widen the range in
  `cmd_glibc_seed` for older captures, or parallelise with `multiprocessing`.
- For PHP `mt_rand`, Java `Random`, V8 `Math.random` and xoshiro/PCG, see the
  dedicated `prng-*` techniques - those need different state models.
