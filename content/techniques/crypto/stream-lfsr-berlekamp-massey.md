---
title: "LFSR - Berlekamp-Massey Recovery and Correlation Attacks on Geffe/Filter Generators"
category: crypto
subcategory: stream-cipher
type: technique
tags: [lfsr, berlekamp-massey, linear-complexity, connection-polynomial, feedback-polynomial, gf2, galois-field, linear-algebra, geffe-generator, correlation-attack, siegenthaler, divide-and-conquer, filter-generator, combiner, stream-cipher, keystream, sagemath, primitive-polynomial, xor]
difficulty: hard
summary: "Any LFSR of length L is fully determined by 2L output bits via Berlekamp-Massey; nonlinear combiners like Geffe leak each register separately through correlations."
when_to_use:
  - "A keystream comes from an LFSR, a combination of LFSRs, or a `shift`/`taps` loop"
  - "You have at least 2L bits of keystream (or plaintext to xor against ciphertext)"
  - "The challenge mentions Geffe, a combining function, or a filter/nonlinear generator"
  - "The full keyspace is 2^(L1+L2+L3) but each register is small on its own"
  - "You must predict future keystream, not just decrypt what you have"
tools: [sagemath, python]
related: [stream-rc4-attacks, xor-repeating-key, block-differential-linear, block-meet-in-the-middle]
---

## TL;DR

A length-`L` LFSR satisfies a linear recurrence over `GF(2)`, so `2L` consecutive
output bits pin down its feedback polynomial *and* its state: Berlekamp-Massey does it
in `O(L^2)`. Designers therefore combine several LFSRs through a nonlinear function.
If that function correlates with any single input - and the Geffe function correlates
with two of its three inputs at probability `3/4` - you attack each register on its
own, turning `2^(L1+L2+L3)` into `2^L1 + 2^L2 + 2^L3`.

## Recognise it

- Source with `state = ((state << 1) | feedback) & mask` or `state >>= 1` plus a
  `taps` constant.
- A "random" generator seeded once, producing one bit per call.
- Three registers and a combining expression like `(a & b) ^ ((1 ^ b) & c)`.
- The keystream is much longer than any key, and xoring known plaintext gives you a
  long bit sequence.
- The challenge asks you to predict the *next* output, not to decrypt.

## Theory

**LFSR.** State `(s_{n-1}, ..., s_{n-L})`, connection polynomial

$$C(x) = 1 + c_1 x + c_2 x^2 + \dots + c_L x^L$$

and recurrence

$$s_n = c_1 s_{n-1} \oplus c_2 s_{n-2} \oplus \dots \oplus c_L s_{n-L}$$

If `C` is primitive the period is `2^L - 1` (maximal). `c_L = 1` is required for the
state update to be a bijection.

**Berlekamp-Massey.** Finds the shortest LFSR generating a given bit sequence. It
processes the sequence one bit at a time, keeping a current polynomial `C` and the
last one that failed, `B`, and patching `C` whenever the predicted bit is wrong. The
output is the *linear complexity* `L` and the polynomial. Feeding it `2L` bits is
enough; feeding it more is free verification. Complexity `O(n^2)` bit operations.

Equivalent formulation: write the recurrence as a linear system. `L` unknowns
`c_1..c_L`, and each of `s_L, s_{L+1}, ...` gives one equation. Solve over `GF(2)`
with Gaussian elimination. Berlekamp-Massey is just the fast incremental version, and
it also tells you `L` when you do not know it.

**Why this kills a bare LFSR.** Linear complexity is the whole security. Even a
128-bit LFSR falls to 256 known keystream bits.

**Nonlinear combiners.** Combine `k` LFSR outputs with a Boolean function `F`. The
Geffe generator uses

$$z = (x_1 \wedge x_2) \oplus (\neg x_2 \wedge x_3)$$

which is a multiplexer: `x_2` selects between `x_1` and `x_3`. Its truth table gives

$$P(z = x_1) = 3/4,\qquad P(z = x_3) = 3/4,\qquad P(z = x_2) = 1/2$$

Those `3/4` correlations are the bug (Siegenthaler's correlation attack). Guess the
initial state of LFSR 1 alone, generate `N` bits, and count agreement with the
keystream: the correct state agrees ~75% of the time, every wrong state ~50%. With
`N = 200-300` bits the gap is many standard deviations, so the correct state is
unambiguous. Do the same for LFSR 3. Then brute-force LFSR 2 (or solve it directly)
with an exact match against the keystream.

Total work `2^{L_1} + 2^{L_3} + 2^{L_2}` instead of `2^{L_1+L_2+L_3}`.

**Correlation immunity.** A function is `m`-th order correlation immune if its output
is statistically independent of every subset of `m` inputs. Siegenthaler's trade-off:
for an `n`-variable function of algebraic degree `d` with correlation immunity `m`,
`m + d <= n`. You cannot have both high nonlinearity and high correlation immunity -
which is why combiners eventually gave way to designs like Trivium and Grain, and to
*fast correlation attacks* using LDPC-style decoding when the correlation is weak.

**Filter generators** apply `F` to several taps of *one* LFSR. Attacks: algebraic
attacks (write the keystream as equations in the initial state and solve with a
Groebner basis or a SAT solver), or the inversion attack.

## Attack

1. Xor the known plaintext against the ciphertext to obtain keystream bits.
2. Run Berlekamp-Massey. If the linear complexity is small and stable as you add more
   bits, it is a single LFSR: you now have the polynomial and can run the register
   backwards or forwards at will.
3. If the linear complexity is large (roughly `L1*L2 + ...`, the product terms of the
   combining function), it is a nonlinear combiner. Find the combining function from
   the source or the challenge description.
4. Compute the correlation of the function with each input by enumerating its truth
   table. Any probability other than `1/2` is an attack.
5. For each correlated input register, brute-force its initial state and keep the
   candidate with the best agreement.
6. Fill in the remaining registers by exhaustive search with an exact match.
7. Verify by regenerating the whole keystream.

## Code

```python
#!/usr/bin/env python3
"""LFSR cryptanalysis: Berlekamp-Massey, and a Siegenthaler correlation attack on a
Geffe generator built from three LFSRs.

Self-contained; both attacks are asserted against locally generated keystream.
Runs in a few seconds.
"""

import random
from itertools import product

# Primitive connection polynomials 1 + sum(x^i for i in taps), verified below.
POLY11 = (11, [2, 11])
POLY13 = (13, [1, 3, 4, 13])
POLY15 = (15, [1, 15])


class LFSR:
    """Fibonacci LFSR over GF(2). taps = exponents of C(x) = 1 + sum x^i."""

    def __init__(self, length: int, taps: list[int], state: int) -> None:
        self.length = length
        self.mask = sum(1 << (i - 1) for i in taps)
        self.mod = (1 << length) - 1
        self.state = state & self.mod

    def step(self) -> int:
        out = (self.state >> (self.length - 1)) & 1
        fb = bin(self.state & self.mask).count("1") & 1
        self.state = ((self.state << 1) | fb) & self.mod
        return out

    def bits(self, n: int) -> list[int]:
        return [self.step() for _ in range(n)]


def period(length: int, taps: list[int]) -> int:
    """Cycle length from state 1. Equals 2^L - 1 iff the polynomial is primitive."""
    reg = LFSR(length, taps, 1)
    start, count = reg.state, 0
    while True:
        reg.step()
        count += 1
        if reg.state == start or count > (1 << length):
            return count


# ------------------------------------------------------- Berlekamp-Massey
def berlekamp_massey(bits: list[int]) -> tuple[int, list[int]]:
    """Shortest LFSR for `bits`. Returns (L, C) with C[0] == 1 and len(C) == L+1.

    The recurrence is s[n] = xor(C[i] & s[n-i] for i in 1..L).
    """
    n = len(bits)
    c = [0] * n
    b = [0] * n
    c[0] = b[0] = 1
    ell, m = 0, -1
    for i in range(n):
        d = bits[i]
        for j in range(1, ell + 1):
            d ^= c[j] & bits[i - j]
        if d:
            prev = c[:]
            shift = i - m
            for j in range(shift, n):
                c[j] ^= b[j - shift]
            if ell <= i // 2:
                ell, m, b = i + 1 - ell, i, prev
    return ell, c[:ell + 1]


def predict(bits: list[int], c: list[int], ell: int, count: int) -> list[int]:
    """Continue a sequence using a recovered connection polynomial."""
    seq = list(bits)
    for _ in range(count):
        nxt = 0
        for i in range(1, ell + 1):
            nxt ^= c[i] & seq[-i]
        seq.append(nxt)
    return seq[len(bits):]


def taps_from_poly(c: list[int]) -> list[int]:
    return [i for i in range(1, len(c)) if c[i]]


# ------------------------------------------------------ the Geffe generator
def geffe(x1: int, x2: int, x3: int) -> int:
    """Multiplexer: x2 chooses between x1 and x3. Correlates 3/4 with x1 and x3."""
    return (x1 & x2) ^ ((1 ^ x2) & x3)


def correlation(func, n_inputs: int = 3) -> list[float]:
    """P(output == input_i) for every input, straight off the truth table."""
    out = []
    for i in range(n_inputs):
        agree = sum(1 for v in product((0, 1), repeat=n_inputs) if func(*v) == v[i])
        out.append(agree / (2 ** n_inputs))
    return out


class GeffeGenerator:
    def __init__(self, polys, states) -> None:
        self.regs = [LFSR(length, taps, st)
                     for (length, taps), st in zip(polys, states)]

    def bits(self, n: int) -> list[int]:
        return [geffe(*(r.step() for r in self.regs)) for _ in range(n)]


# ---------------------------------------------------- the correlation attack
def recover_correlated_register(keystream: list[int], length: int, taps: list[int],
                                threshold: float = 0.62) -> list[tuple[float, int]]:
    """Every initial state whose own output agrees with the keystream too often."""
    n = len(keystream)
    hits = []
    for state in range(1, 1 << length):
        reg = LFSR(length, taps, state)
        agree = 0
        for k in range(n):
            agree += reg.step() == keystream[k]
        rate = agree / n
        if rate > threshold:
            hits.append((rate, state))
    hits.sort(reverse=True)
    return hits


def recover_middle_register(keystream: list[int], polys, s1: int, s3: int,
                            check: int = 48) -> int | None:
    """Brute-force the uncorrelated register with an exact keystream match."""
    (l1, t1), (l2, t2), (l3, t3) = polys
    for state in range(1, 1 << l2):
        r1, r2, r3 = LFSR(l1, t1, s1), LFSR(l2, t2, state), LFSR(l3, t3, s3)
        if all(geffe(r1.step(), r2.step(), r3.step()) == keystream[k]
               for k in range(check)):
            return state
    return None


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    # --- the polynomials really are primitive ------------------------------
    for length, taps in (POLY11, POLY13, POLY15):
        assert period(length, taps) == (1 << length) - 1, (length, taps)
    print("[+] PASS all three connection polynomials are primitive")

    # --- 1. Berlekamp-Massey on a bare LFSR --------------------------------
    seed = random.randrange(1, 1 << 11)
    reg = LFSR(*POLY11, seed)
    stream = reg.bits(2 * 11)                 # exactly 2L bits, the theoretical bound
    ell, c = berlekamp_massey(stream)
    print(f"[+] linear complexity {ell}, taps {taps_from_poly(c)}")
    assert ell == 11
    assert taps_from_poly(c) == POLY11[1], taps_from_poly(c)

    # and it predicts the future correctly
    more = LFSR(*POLY11, seed).bits(2 * 11 + 200)[2 * 11:]
    assert predict(stream, c, ell, 200) == more
    print("[+] PASS berlekamp-massey: polynomial recovered from 2L bits, 200 predicted")

    # a random sequence has linear complexity ~n/2, which is how you tell them apart
    noise = [random.randrange(2) for _ in range(200)]
    ell_noise, _ = berlekamp_massey(noise)
    print(f"[+] random 200-bit sequence has linear complexity {ell_noise} (~n/2)")
    assert ell_noise > 80

    # --- 2. the Geffe correlations -----------------------------------------
    corr = correlation(geffe)
    print("[+] P(z == x_i) =", corr)
    assert corr == [0.75, 0.5, 0.75]
    print("[+] PASS geffe correlates 3/4 with inputs 1 and 3")

    # --- 3. build the generator and attack it ------------------------------
    POLYS = (POLY11, POLY13, POLY15)
    true_states = [random.randrange(1, 1 << p[0]) for p in POLYS]
    keystream = GeffeGenerator(POLYS, true_states).bits(400)
    print("[+] keyspace if brute-forced whole: 2^%d" % sum(p[0] for p in POLYS))

    cand1 = recover_correlated_register(keystream, *POLY11)
    cand3 = recover_correlated_register(keystream, *POLY15)
    print(f"[+] lfsr1: {len(cand1)} candidate(s), best {cand1[0]}")
    print(f"[+] lfsr3: {len(cand3)} candidate(s), best {cand3[0]}")
    assert cand1[0][1] == true_states[0], (cand1[:3], true_states[0])
    assert cand3[0][1] == true_states[2], (cand3[:3], true_states[2])
    print("[+] PASS correlation attack isolated registers 1 and 3")

    s2 = recover_middle_register(keystream, POLYS, cand1[0][1], cand3[0][1])
    assert s2 == true_states[1], (s2, true_states[1])
    print("[+] PASS middle register brute-forced:", s2)

    # --- 4. full verification: regenerate and predict -----------------------
    found = [cand1[0][1], s2, cand3[0][1]]
    assert GeffeGenerator(POLYS, found).bits(400) == keystream
    future_true = GeffeGenerator(POLYS, true_states).bits(1000)[400:]
    future_ours = GeffeGenerator(POLYS, found).bits(1000)[400:]
    assert future_ours == future_true
    print("[+] PASS regenerated the keystream and predicted 600 future bits")

    # --- 5. the combiner's linear complexity is why BM alone fails ---------
    ell_geffe, _ = berlekamp_massey(keystream)
    print(f"[+] geffe keystream linear complexity {ell_geffe} "
          f"(too high for 400 bits to pin down)")
    assert ell_geffe > 100

    print("\nall checks passed")
```

## Variants & pitfalls

- **You need `2L` bits, and `L` may be unknown.** Run Berlekamp-Massey on everything
  you have: if the reported `L` stops growing as you add bits, that `L` is real. If it
  keeps tracking `n/2`, your data is not from a short LFSR.
- **Galois vs Fibonacci LFSRs** produce the same set of sequences with a reversed tap
  order. If your recovered polynomial does not reproduce the sequence, try the
  reciprocal `x^L * C(1/x)`.
- **Bit order.** Whether the output is the bit shifted out or the new feedback bit
  changes the sequence by one position. If prediction is off by one, that is why.
- **The combining function may be secret.** Recover it by correlating the keystream
  against candidate registers, or by algebraic attack: the keystream bits are
  polynomial equations in the initial states; hand them to a SAT solver or
  `sage`'s Groebner machinery.
- **Weak correlation.** If `P(z = x_i)` is only `0.52`, plain brute force needs far
  more keystream (`N ~ 1/(p-0.5)^2`). That is where *fast correlation attacks*
  (Meier-Staffelbach, LDPC decoding) come in.
- **Threshold tuning.** With `N` bits and a `3/4` correlation, the correct state sits
  at `0.75 +- 0.5/sqrt(N)` and wrong ones at `0.5 +- 0.5/sqrt(N)`. Put the threshold
  at `0.62` for `N >= 200`; lower it and you drown in false positives, raise it and
  you may miss the true state on short keystreams.
- **Shrinking / self-shrinking / alternating-step generators** are irregularly clocked,
  so a direct correlation attack does not apply - look up the specific attack.
- **Sage** has `berlekamp_massey` for `GF(2)` sequences and full `GF(2^n)` polynomial
  machinery, which is much faster than a Python loop for large `L`.

## Tools

- SageMath - `berlekamp_massey(list_of_GF2_elements)`, `GF(2)['x']`, Groebner bases.
- A SAT solver (`python-sat`, `z3`) for filter generators and algebraic attacks; see
  `block-toy-spn-z3`.

## References

- Massey, "Shift-Register Synthesis and BCH Decoding" (1969) - the algorithm.
- Siegenthaler, "Decrypting a Class of Stream Ciphers Using Ciphertext Only" (1985) -
  the correlation attack used above.
- Meier and Staffelbach, "Fast Correlation Attacks on Certain Stream Ciphers" (1989).
