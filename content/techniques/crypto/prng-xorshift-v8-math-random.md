---
title: "xorshift / xoshiro / PCG State Recovery and V8 Math.random Prediction"
category: crypto
subcategory: prng
type: technique
tags: [xorshift, xorshift128plus, xoshiro, xoshiro256, xoroshiro, pcg, pcg32, splitmix64, math-random, v8, javascript-prng, gf2, linear-algebra, z3, state-recovery, todouble, nodejs, chrome, prng]
difficulty: hard
summary: "xorshift-family generators are GF(2)-linear, so a handful of outputs gives a solvable linear system - and V8's Math.random is xorshift128+ served from a reversed 64-value cache."
when_to_use:
  - "JavaScript `Math.random()` drives a token, shuffle, lottery or captcha"
  - "Source uses xorshift128+, xoshiro256**, xoroshiro128+, splitmix64 or PCG"
  - "You can observe 4+ consecutive raw outputs (or doubles in [0,1))"
  - "A Go/Rust/C++ program uses a non-cryptographic 'fast' RNG for secrets"
tools: [python, z3, nodejs]
related: [prng-lcg-recovery, prng-truncated-lcg-lattice, prng-java-random, prng-toolkit, prng-cheatsheet]
---

## TL;DR

xorshift and xoshiro update their state with XORs and shifts only, which is a
**linear map over GF(2)**. Each observed output bit is therefore a linear equation in
the state bits: gather enough of them and solve by Gaussian elimination - no z3
required, though z3 is the convenient route when a non-linear output function (PCG's
rotate, xoshiro's `*`) gets in the way.

For **V8 `Math.random()`** specifically: the generator is xorshift128+, the double is
built from the top 52 bits of `state0`, and V8 fills a **64-entry cache which JS then
consumes in reverse order**. Four consecutive values give you the state; getting the
*direction* right is what most exploits get wrong.

## Recognise it

- Browser/Node challenge where `Math.random()` picks something valuable.
- Source constants: `<< 23`, `>> 17`, `>> 26` (xorshift128+); `0x2545F4914F6CDD1D`
  (xorshift64*); `0x9E3779B97F4A7C15` (splitmix64); `0xBF58476D1CE4E5B9`,
  `0x94D049BB133111EB` (splitmix64 finaliser); `6364136223846793005` with a rotate
  (PCG32); `rotl(s[1] * 5, 7) * 9` (xoshiro256**).
- Go's `math/rand` (not `crypto/rand`), Rust's `rand::thread_rng` with
  `SmallRng`/`Xoshiro`, `numpy.random.default_rng` (PCG64).
- 64 identical-looking values then a "jump" in behaviour - that is V8's cache refill.

## Theory

### V8 xorshift128+

```
XorShift128(state0, state1):
    s1 = state0
    s0 = state1
    state0 = s0
    s1 ^= s1 << 23
    s1 ^= s1 >> 17
    s1 ^= s0
    s1 ^= s0 >> 26
    state1 = s1

ToDouble(state0):
    return bitcast_double((state0 >> 12) | 0x3FF0000000000000) - 1.0
```

Three things matter:

1. The double keeps the **top 52 bits** of the *new* `state0`; the bottom 12 are lost.
2. `MathRandom::RefillCache` generates **64** values into a cache; JavaScript then
   reads them **from the end backwards**. So the first `Math.random()` you observe is
   the *last* one generated. To predict the *next* value returned to JS you must step
   the generator **backwards**, not forwards.
3. Each isolate/context has its own cache and seed.

**Inverting the update** (needed for the cache direction):
```
old_state1 = new_state0
t = new_state1 ^ old_state1 ^ (old_state1 >> 26)
u = invert_xor_rshift(t, 17)          # x ^ (x>>17) -> x
old_state0 = invert_xor_lshift(u, 23) # x ^ (x<<23) -> x
```
Both inversions are the usual fixed-point iterations: `x = t ^ (x >> n)` repeated
`ceil(64/n)` times (and the left-shift analogue).

### Why a linear solve works

Every state bit after $n$ steps is a fixed XOR of initial state bits. Simulate the
update *symbolically*: represent each of the 128 state bits as a 128-bit mask of which
initial bits it depends on. After $n$ steps, each observed output bit gives one linear
equation `mask . unknowns = observed_bit`. With 52 bits per output:

| outputs | equations | rank of the system |
|---|---|---|
| 2 | 104 | 104 |
| 3 | 156 | 116 |
| 4 | 208 | **128 (full)** |

So **four** consecutive `Math.random()` values are enough. (Three are not, despite
having 156 equations - the system is rank-deficient.)

### xoshiro / xoroshiro / splitmix

- `xoshiro256+` and `xoroshiro128+` have a *linear* output (a sum), so the same
  GF(2) attack applies to the high bits.
- `xoshiro256**` and `xoshiro256++` scramble with multiplication/rotation. The state
  update is still linear, but the output is not - invert the scrambler first
  (multiplication by an odd constant mod $2^{64}$ is invertible; rotation is trivially
  invertible), then you are back to the linear case.
- `splitmix64` is a counter plus a bijective finaliser - **fully invertible from a
  single output**, since every step is an invertible map:
  `z ^= z>>30; z *= 0xBF58476D1CE4E5B9; z ^= z>>27; z *= 0x94D049BB133111EB; z ^= z>>31`.

### PCG

`PCG32` is `state = state*6364136223846793005 + inc` (an LCG) with an output function
`rotr32(((state ^ (state >> 18)) >> 27), state >> 59)`. 64 bits of state, 32 bits out,
and the rotation amount itself leaks 3 bits of state. Recovery: guess the 5-bit rotate
+ enumerate the missing low bits, or hand the whole thing to z3 with 3-4 outputs.
PCG64 (numpy's default) has a 128-bit state; z3 handles it with ~5 outputs but is slow.

## Attack

1. Identify the generator from its constants.
2. Collect outputs - **consecutive**, and note whether they are raw integers or doubles.
3. For doubles, recover the known bits: `int((x) * 2**52)` gives the top 52 bits of
   `state0` for V8.
4. Build the symbolic GF(2) system, solve, verify by regenerating your observations.
5. For V8, remember the cache reversal: reverse your observed list before solving, and
   step **backwards** to produce the next values JS will return.
6. For non-linear scramblers, invert the scrambler or use z3.

## Code

```python
#!/usr/bin/env python3
"""V8 Math.random (xorshift128+): implementation, ToDouble, exact GF(2) state recovery
from 4 outputs, backwards stepping for the cache order. Plus xoshiro256**, splitmix64
and PCG32 reference implementations. Pure stdlib, self-testing."""
from __future__ import annotations

import random
import struct

M64 = (1 << 64) - 1


# ------------------------------ V8 xorshift128+ ----------------------------
def xs128p(state0: int, state1: int) -> tuple[int, int]:
    """One V8 XorShift128 step. Returns the NEW (state0, state1)."""
    s1 = state0
    s0 = state1
    new0 = s0
    s1 ^= (s1 << 23) & M64
    s1 ^= s1 >> 17
    s1 ^= s0
    s1 ^= s0 >> 26
    return new0, s1 & M64


def _inv_xor_rshift(t: int, n: int) -> int:
    x = t
    for _ in range((64 + n - 1) // n):
        x = t ^ (x >> n)
    return x & M64


def _inv_xor_lshift(t: int, n: int) -> int:
    x = t
    for _ in range((64 + n - 1) // n):
        x = t ^ ((x << n) & M64)
    return x & M64


def xs128p_prev(state0: int, state1: int) -> tuple[int, int]:
    """Invert one step: given (state0, state1) return the PREVIOUS pair."""
    old1 = state0
    t = state1 ^ old1 ^ (old1 >> 26)
    u = _inv_xor_rshift(t, 17)
    old0 = _inv_xor_lshift(u, 23)
    return old0, old1


def to_double(state0: int) -> float:
    """V8's ToDouble: keep the top 52 bits of state0."""
    bits = (state0 >> 12) | 0x3FF0000000000000
    return struct.unpack("<d", struct.pack("<Q", bits))[0] - 1.0


def from_double(x: float) -> int:
    """Recover the 52 known high bits of state0 from a Math.random() value."""
    bits = struct.unpack("<Q", struct.pack("<d", x + 1.0))[0]
    return bits & ((1 << 52) - 1)


# ---------------------- symbolic GF(2) state recovery ----------------------
def _sym_step(s0, s1):
    """Same update, but each 'bit' is a 128-bit dependency mask (index 0 = LSB)."""
    def shl(v, n):
        return [0] * n + v[:64 - n]

    def shr(v, n):
        return v[n:] + [0] * n

    def xor(a, b):
        return [p ^ q for p, q in zip(a, b)]

    x, y = s0[:], s1[:]
    new0 = y[:]
    x = xor(x, shl(x, 23))
    x = xor(x, shr(x, 17))
    x = xor(x, y)
    x = xor(x, shr(y, 26))
    return new0, x


def build_output_masks(nsteps: int):
    """masks[i][b] = which initial state bits XOR into bit b of the i-th output."""
    s0 = [1 << i for i in range(64)]
    s1 = [1 << (64 + i) for i in range(64)]
    masks = []
    for _ in range(nsteps):
        s0, s1 = _sym_step(s0, s1)
        masks.append(s0[:])
    return masks


def solve_gf2(equations, nvars: int = 128):
    """equations: [(mask, rhs_bit)]. Returns the solution as an int, or None."""
    pivots: dict[int, tuple[int, int]] = {}
    for mask, rhs in equations:
        m, r = mask, rhs
        while m:
            b = m.bit_length() - 1
            if b in pivots:
                pm, pr = pivots[b]
                m ^= pm
                r ^= pr
            else:
                pivots[b] = (m, r)
                break
        else:
            if r:
                raise ValueError("inconsistent system - wrong model or bad data")
    if len(pivots) < nvars:
        return None                      # underdetermined: collect more outputs
    sol = 0
    for b in sorted(pivots):             # ascending: lower bits already solved
        m, r = pivots[b]
        val = r
        rest = m & ~(1 << b)
        while rest:
            i = rest.bit_length() - 1
            val ^= (sol >> i) & 1
            rest &= ~(1 << i)
        if val:
            sol |= 1 << b
    return sol


def recover_state_from_outputs(state0_values, known_bits: int = 52):
    """state0_values: consecutive NEW state0 values (or their top `known_bits`).

    If you pass full 64-bit values, all 64 bits are used. If you pass values already
    shifted down (as from_double gives), set known_bits=52 and pass them as-is.
    Returns (state0, state1) BEFORE the first observed step.
    """
    n = len(state0_values)
    masks = build_output_masks(n)
    eqs = []
    lowest = 64 - known_bits
    for step, val in enumerate(state0_values):
        for bit in range(lowest, 64):
            rhs = (val >> (bit - lowest)) & 1
            eqs.append((masks[step][bit], rhs))
    sol = solve_gf2(eqs)
    if sol is None:
        return None
    return sol & M64, (sol >> 64) & M64


def v8_predict_next(observed_doubles, count: int = 5):
    """Predict the next values Math.random() will return, respecting the cache order.

    V8 generates cache[0..63] forwards but JavaScript pops them from the END, so the
    values you observe run BACKWARDS through the generator. Reverse them to get a
    forward-consecutive window, recover the state S that precedes that window, and
    then walk backwards: S.state0 is already the next double JS will hand out.
    """
    vals = [from_double(x) for x in reversed(observed_doubles)]
    st = recover_state_from_outputs(vals, known_bits=52)
    if st is None:
        raise ValueError("need at least 4 consecutive Math.random() values")
    a, b = st
    out = [to_double(a)]
    for _ in range(count - 1):
        a, b = xs128p_prev(a, b)
        out.append(to_double(a))
    return out[:count]


# ------------------------------- xoshiro256** ------------------------------
def _rotl(x: int, k: int) -> int:
    return ((x << k) | (x >> (64 - k))) & M64


class Xoshiro256SS:
    def __init__(self, s):
        self.s = list(s)

    def next(self) -> int:
        result = (_rotl((self.s[1] * 5) & M64, 7) * 9) & M64
        t = (self.s[1] << 17) & M64
        self.s[2] ^= self.s[0]
        self.s[3] ^= self.s[1]
        self.s[1] ^= self.s[2]
        self.s[0] ^= self.s[3]
        self.s[2] ^= t
        self.s[3] = _rotl(self.s[3], 45)
        return result


def unscramble_xoshiro_ss(result: int) -> int:
    """Invert rotl(s1*5, 7)*9 to get s[1]. Both multipliers are odd, so invertible."""
    inv9 = pow(9, -1, 1 << 64)
    inv5 = pow(5, -1, 1 << 64)
    t = (result * inv9) & M64
    t = _rotl(t, 64 - 7)
    return (t * inv5) & M64


# -------------------------------- splitmix64 -------------------------------
def splitmix64(state: int) -> tuple[int, int]:
    state = (state + 0x9E3779B97F4A7C15) & M64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return state, z ^ (z >> 31)


def splitmix64_invert_output(out: int) -> int:
    """Every step is a bijection, so one output reveals the counter exactly."""
    z = _inv_xor_rshift(out, 31)
    z = (z * pow(0x94D049BB133111EB, -1, 1 << 64)) & M64
    z = _inv_xor_rshift(z, 27)
    z = (z * pow(0xBF58476D1CE4E5B9, -1, 1 << 64)) & M64
    return _inv_xor_rshift(z, 30)


# ----------------------------------- PCG32 ---------------------------------
class PCG32:
    MULT = 6364136223846793005

    def __init__(self, seed: int, inc: int = 1442695040888963407):
        self.inc = (inc << 1 | 1) & M64
        self.state = 0
        self.next()
        self.state = (self.state + seed) & M64
        self.next()

    def next(self) -> int:
        old = self.state
        self.state = (old * self.MULT + self.inc) & M64
        xorshifted = ((old >> 18) ^ old) >> 27 & 0xFFFFFFFF
        rot = old >> 59
        return ((xorshifted >> rot) | (xorshifted << ((-rot) & 31))) & 0xFFFFFFFF


if __name__ == "__main__":
    rng = random.Random(0x5EED)

    # --- V8 round trip -----------------------------------------------------
    s0, s1 = rng.getrandbits(64), rng.getrandbits(64)
    a, b = xs128p(s0, s1)
    assert xs128p_prev(a, b) == (s0, s1)
    print("[ok] xorshift128+ step is invertible")

    d = to_double(0x123456789ABCDEF0)
    assert from_double(d) == 0x123456789ABCDEF0 >> 12
    assert 0.0 <= d < 1.0
    print(f"[ok] ToDouble/from_double round trip ({d:.17f})")

    # --- rank: 3 outputs are NOT enough, 4 are -----------------------------
    for n, expect_full in ((2, False), (3, False), (4, True)):
        masks = build_output_masks(n)
        eqs = [(masks[i][bit], 0) for i in range(n) for bit in range(12, 64)]
        got = solve_gf2(eqs) is not None
        assert got == expect_full, (n, got)
    print("[ok] rank check: 2 and 3 outputs underdetermined, 4 outputs full rank")

    # --- recover the state from 4 doubles ---------------------------------
    s0, s1 = rng.getrandbits(64), rng.getrandbits(64)
    a, b = s0, s1
    doubles, state0s = [], []
    for _ in range(6):
        a, b = xs128p(a, b)
        state0s.append(a)
        doubles.append(to_double(a))
    rec = recover_state_from_outputs([from_double(x) for x in doubles[:4]], 52)
    assert rec == (s0, s1), (rec, (s0, s1))
    print(f"[ok] recovered the full 128-bit V8 state from 4 Math.random() doubles")

    # and it predicts the rest of the generated sequence
    a, b = rec
    regen = []
    for _ in range(6):
        a, b = xs128p(a, b)
        regen.append(to_double(a))
    assert regen == doubles
    print("[ok] regenerated all 6 doubles from the recovered state")

    # --- the cache is served backwards -------------------------------------
    # Simulate V8: generate 64 values into a cache, JS pops from the end.
    a, b = rng.getrandbits(64), rng.getrandbits(64)
    cache = []
    for _ in range(64):
        a, b = xs128p(a, b)
        cache.append(to_double(a))
    js_order = list(reversed(cache))
    observed, future = js_order[:4], js_order[4:9]
    predicted = v8_predict_next(observed, count=5)
    assert predicted == future, (predicted[:2], future[:2])
    print(f"[ok] predicted the next 5 Math.random() values through the cache "
          f"reversal: {predicted[0]:.6f}")

    # --- xoshiro256** scrambler inversion ---------------------------------
    st = [rng.getrandbits(64) for _ in range(4)]
    x = Xoshiro256SS(st)
    s1_before = st[1]
    out = x.next()
    assert unscramble_xoshiro_ss(out) == s1_before
    print("[ok] xoshiro256** output scrambler inverted -> s[1] recovered directly")

    # --- splitmix64 is fully invertible ------------------------------------
    counter = rng.getrandbits(64)
    new_counter, out = splitmix64(counter)
    assert splitmix64_invert_output(out) == new_counter
    print("[ok] splitmix64: one output reveals the counter exactly")

    # --- PCG32 sanity -------------------------------------------------------
    p = PCG32(42, 54)
    vals = [p.next() for _ in range(6)]
    assert all(0 <= v < 2 ** 32 for v in vals) and len(set(vals)) == 6
    p2 = PCG32(42, 54)
    assert [p2.next() for _ in range(6)] == vals
    print(f"[ok] PCG32 deterministic: {vals[:3]}")
    print("all self-tests passed")
```

### The same attack in z3 (when the output function is not linear)

```python
#!/usr/bin/env python3
"""z3 formulation of V8 Math.random state recovery. Runs only if z3 is installed;
prints a skip message otherwise so the file is still executable."""
from __future__ import annotations

import struct

M64 = (1 << 64) - 1


def to_double(state0: int) -> float:
    bits = (state0 >> 12) | 0x3FF0000000000000
    return struct.unpack("<d", struct.pack("<Q", bits))[0] - 1.0


def xs128p(state0: int, state1: int):
    s1, s0 = state0, state1
    new0 = s0
    s1 ^= (s1 << 23) & M64
    s1 ^= s1 >> 17
    s1 ^= s0
    s1 ^= s0 >> 26
    return new0, s1 & M64


def solve_with_z3(doubles):
    from z3 import BitVec, BitVecVal, LShR, Solver, sat

    s0 = BitVec("s0", 64)
    s1 = BitVec("s1", 64)
    solver = Solver()
    a, b = s0, s1
    for d in doubles:
        # symbolic step
        t1, t0 = a, b
        new0 = t0
        t1 = t1 ^ (t1 << 23)
        t1 = t1 ^ LShR(t1, 17)
        t1 = t1 ^ t0
        t1 = t1 ^ LShR(t0, 26)
        a, b = new0, t1
        observed = struct.unpack("<Q", struct.pack("<d", d + 1.0))[0] & ((1 << 52) - 1)
        solver.add(LShR(a, 12) == BitVecVal(observed, 64))
    if solver.check() != sat:
        return None
    model = solver.model()
    return model[s0].as_long(), model[s1].as_long()


if __name__ == "__main__":
    state = (0x0123456789ABCDEF, 0xFEDCBA9876543210)
    a, b = state
    doubles = []
    for _ in range(5):
        a, b = xs128p(a, b)
        doubles.append(to_double(a))
    try:
        import z3  # noqa: F401
    except ImportError:
        print("[skip] z3 is not installed: pip install z3-solver")
    else:
        got = solve_with_z3(doubles)
        assert got == state, (got, state)
        print(f"[ok] z3 recovered the V8 state: {got[0]:#018x} {got[1]:#018x}")
```

## Variants & pitfalls

- **The cache direction is the classic mistake.** V8 fills 64 values then hands them
  out in reverse. If your prediction is right but "shifted" or only works for the
  values you already saw, this is why. Also: after 64 values the cache refills, and
  your backwards walk runs out.
- **`Math.random()` in Node vs Chrome vs Firefox.** Node and Chrome are both V8
  (xorshift128+). SpiderMonkey also uses xorshift128+ but with a different double
  conversion. JavaScriptCore differs again. Check the engine.
- **Per-context seeding.** Each realm/iframe/worker has its own state. Values from
  different contexts do not interleave into one stream.
- **`Math.random()` is not the only consumer.** Other engine internals may pull from
  the cache; if a prediction desynchronises, allow for skipped values.
- **Truncation.** You lose the bottom 12 bits of each `state0`. That is why 3 outputs
  (156 equations) are still rank-deficient - do not assume "more equations than
  unknowns" means solvable.
- **Go `math/rand`**: pre-1.20 it is a lagged-Fibonacci ALFG with a 607-element table
  (seeded from a 64-bit seed - brute-forceable if seeded from time); Go 1.20+ seeds it
  randomly, and `math/rand/v2` uses ChaCha8 or PCG. Check the version.
- **Rust**: `thread_rng` is ChaCha12 (secure). `SmallRng` is xoshiro - attackable.
- **numpy**: `default_rng()` is PCG64 (not attackable by the simple GF(2) trick);
  `numpy.random.seed()`/`RandomState` is MT19937 - attack that instead.
- **xoshiro jump functions.** If the target calls `jump()`/`long_jump()`, the state
  moves by a huge stride; the linear structure survives, but your step count does not.
- **z3 scales badly.** Past ~5 outputs of 64-bit state with non-linear scramblers it
  can hang. Prefer inverting the scrambler and using linear algebra.

## Tools

- **z3** (`pip install z3-solver`) - for PCG, xoshiro\*\*, and anything with a
  multiply in the output path.
- **`v8-randomness-predictor`-style scripts** - several public implementations exist;
  they all do exactly the above.
- **Node REPL** - the fastest ground truth: `node -e 'for(let i=0;i<8;i++)
  console.log(Math.random())'`.
- **SageMath / galois (PyPI)** - if you prefer a library for the GF(2) solve.

## References

- V8 `src/base/utils/random-number-generator.h` (XorShift128, ToDouble) - <https://github.com/v8/v8/blob/main/src/base/utils/random-number-generator.h>
- V8 `src/numbers/math-random.cc` (the 64-entry cache) - <https://github.com/v8/v8/blob/main/src/numbers/math-random.cc>
- Vigna, "xoshiro/xoroshiro generators" - <https://prng.di.unimi.it/>
- O'Neill, "PCG: A Family of Simple Fast Space-Efficient Statistically Good Algorithms for Random Number Generation" - <https://www.pcg-random.org/paper.html>
