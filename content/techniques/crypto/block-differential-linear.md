---
title: "Differential, Linear and Slide Attacks on Toy / Reduced-Round Block Ciphers"
category: crypto
subcategory: cryptanalysis
type: technique
tags: [differential-cryptanalysis, linear-cryptanalysis, ddt, lat, difference-distribution-table, linear-approximation-table, piling-up-lemma, matsui, biham-shamir, slide-attack, related-key, reduced-round, spn, sbox, heys, key-recovery, chosen-plaintext, known-plaintext, block-cipher, toy-cipher]
difficulty: insane
summary: "Build the S-box DDT/LAT, chain high-probability characteristics through r-1 rounds, then filter last-round key guesses by counting; slide attacks ignore round count entirely."
when_to_use:
  - "A custom or reduced-round SPN/Feistel cipher with a small block and small S-box"
  - "You have an encryption oracle and can request thousands of chosen plaintext pairs"
  - "The key schedule is trivial, self-similar, or the round keys are independent"
  - "Every round is identical with no round constants (slide attack)"
  - "Round keys are rotations of a master key (related-key attack)"
tools: [python, sagemath, z3]
related: [block-toy-spn-z3, block-meet-in-the-middle, stream-lfsr-berlekamp-massey]
---

## TL;DR

Three structural attacks on ciphers with weak or few rounds:

- **Differential** (Biham-Shamir): pick an input difference; the S-box DDT says which
  output differences are likelier than `1/2^n`. Chain them through `r-1` rounds, guess
  the last-round subkey nibbles, partially decrypt each pair, and count how often the
  expected difference appears. The right guess spikes.
- **Linear** (Matsui): the LAT gives bit masks whose input/output parities agree more
  than half the time. Chain with the piling-up lemma, then score last-round key
  guesses by how far the parity count deviates from `N/2`.
- **Slide**: if every round is the same keyed `F_k` with no round constants, a *slid
  pair* `(P, F_k(P))` satisfies `E(F_k(P)) = F_k(E(P))` - two equations in `k`, at a
  cost independent of the round count.

## Recognise it

- A hand-rolled cipher with a 4-bit S-box, a bit permutation and 3-6 rounds, with
  round keys sliced from the master key or every round using the same key.
- No round constants and an identical round function in a loop (slide attack).
- An encryption oracle with unlimited queries, or a known cipher with the round count
  cut down ("AES, 4 rounds").

## Theory

The demo cipher is a 4-round SPN on 16-bit blocks (Heys' teaching cipher shape):

```
for r in 0,1,2:   x = PERM(SBOX(x xor K[r]))
                  x = SBOX(x xor K[3])
                  C = x xor K[4]
```

**DDT.** `DDT[a][b] = #{x : S(x) xor S(x xor a) == b}`; uniform would be 1 per entry
for a 4-bit S-box, real ones reach 6 or 8. `DDT[a][b]/16` is the differential
probability of one S-box.

**Chaining.** Differences pass through the key xor untouched (`(x^k) xor (x'^k) =
x xor x'`) and through the bit permutation deterministically, so a characteristic's
probability is the product of the DDT probabilities of all active S-boxes. A beam
search over "which output difference per active nibble" finds the best one; here the
optimum 3-round characteristic is `0x0B00 -> 0x0606` at `27/1024 ~ 2^-5.2`, which the
code rediscovers.

**Last-round key recovery.** The characteristic ends at the input of round 4's key
xor, and only the *active* nibbles of the output difference matter, so you guess just
those nibbles of `K[4]` (8 bits here, not 16): undo `xor K[4]` and the final S-box on
them for both ciphertexts of a pair and check the recovered difference against the
prediction. Right guess `~p*N` hits, wrong guess `~N/2^{4*active}`; budget a few times
`1/p` pairs.

**LAT.** `LAT[a][b] = #{x : parity(a & x) == parity(b & S(x))} - 8`, bias
`LAT[a][b]/16`. Masks propagate *forwards* through a bit permutation exactly like
data; the key xor only flips the sign of the whole approximation.

**Piling-up lemma.** Independent approximations with biases `e_1..e_m` combine to
$\varepsilon = 2^{m-1}\prod \varepsilon_i$.

**Matsui Algorithm 1** recovers one key-bit parity from the sign of the bias.
**Algorithm 2** guesses the last-round subkey nibbles, partially decrypts, and keeps
the guess maximising `|count - N/2|`; it needs `N ~ c/\varepsilon^2` known plaintexts
with `c` between 8 and 64 (the demo uses 64 for a comfortable margin).

**Slide attack.** `E = F_k^r` with identical rounds. If `P' = F_k(P)` then
`C' = E(P') = F_k^{r+1}(P) = F_k(C)`, so a slid pair gives two equations. With an
`n`-bit block collect `~2^{n/2}` known pairs; by the birthday bound one slid pair
exists. For each candidate pair solve `k` from the plaintext equation and test it
against the ciphertext equation. Cost is independent of `r`; round constants fix it.

**Related-key.** If `K_r = rotl(K, r)`, encrypting under `K` and under `rotl(K,1)`
produces slid-like relations across the whole cipher - same attack shape, with the
key relation supplied by the attacker.

## Attack

1. Extract the S-box and permutation from the source, then build the DDT and LAT. A
   4-bit S-box with a DDT entry of 8 or a LAT entry of +-6 is badly broken.
2. Beam-search `r-1`-round characteristics / approximations.
3. Collect data: chosen pairs for differential, known plaintexts for linear.
4. Score all guesses for the active last-round key nibbles and take the argmax; then
   peel the round off and repeat, or brute-force the rest.
5. If all rounds are identical, try the slide attack first - it is far cheaper.

## Code

```python
#!/usr/bin/env python3
"""Differential and linear cryptanalysis of a 4-round toy SPN, plus a slide attack
on a self-similar cipher. Every characteristic is SEARCHED FOR, not hardcoded.

Self-contained; all three key recoveries are asserted. Runs in ~20 seconds.
"""

import random
import secrets

# ----------------------------------------------------------- the toy SPN
SBOX = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
        0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]
INV_SBOX = [0] * 16
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

# Bit permutation, 1-indexed: input bit i moves to output position PERM[i-1].
PERM = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]


def permute(x: int) -> int:
    y = 0
    for i in range(16):
        if (x >> (15 - i)) & 1:
            y |= 1 << (15 - (PERM[i] - 1))
    return y


def sub(x: int) -> int:
    return sum(SBOX[(x >> s) & 0xF] << s for s in (12, 8, 4, 0))


def nib(x: int, i: int) -> int:
    return (x >> (4 * (3 - i))) & 0xF


def mknib(ns) -> int:
    return sum(n << (4 * (3 - i)) for i, n in enumerate(ns))


def encrypt(keys, p: int) -> int:
    x = p
    for r in range(3):
        x = permute(sub(x ^ keys[r]))
    return sub(x ^ keys[3]) ^ keys[4]


def parity(x: int) -> int:
    return bin(x).count("1") & 1


# ------------------------------------------------------------- DDT / LAT
DDT = [[0] * 16 for _ in range(16)]
for _a in range(16):
    for _x in range(16):
        DDT[_a][SBOX[_x] ^ SBOX[_x ^ _a]] += 1

LAT = [[0] * 16 for _ in range(16)]
for _a in range(16):
    for _b in range(16):
        LAT[_a][_b] = sum(1 for _x in range(16)
                          if parity(_a & _x) == parity(_b & SBOX[_x])) - 8


def _beam_search(step, rounds: int, beam: int, max_active: int, key):
    """Generic characteristic search over single-active-nibble starting differences.

    `step` is one round in the difference or mask domain; `key` turns a carried value
    into the quantity to maximise (identity for probabilities, abs for biases).
    """
    best = []
    for i in range(4):
        for v in range(1, 16):
            start = mknib([v if j == i else 0 for j in range(4)])
            cur = [(start, 1.0)]
            for _ in range(rounds):
                nxt: dict[int, float] = {}
                for d, p in cur:
                    for d2, q in step(d):
                        if key(p * q) > key(nxt.get(d2, 0.0)):
                            nxt[d2] = p * q
                cur = sorted(nxt.items(), key=lambda t: -key(t[1]))[:beam]
            for d, p in cur:
                if sum(1 for j in range(4) if nib(d, j)) <= max_active:
                    best.append((key(p), start, d))
    best.sort(key=lambda t: -t[0])
    return best


def diff_round(diff: int, beam: int = 6):
    """One SPN round: nibble-wise DDT transitions, then the permutation."""
    outs = [(0, 1.0)]
    for i in range(4):
        a = nib(diff, i)
        cur = []
        if a == 0:
            cur = outs
        else:
            for b in range(1, 16):
                if DDT[a][b]:
                    pr = DDT[a][b] / 16
                    cur += [(d | (b << (4 * (3 - i))), p * pr) for d, p in outs]
        cur.sort(key=lambda t: -t[1])
        outs = cur[:beam]
    return [(permute(d), p) for d, p in outs]


def best_differential(rounds: int = 3, beam: int = 60, max_active: int = 2):
    """(probability, input difference, output difference), best first."""
    return _beam_search(diff_round, rounds, beam, max_active, lambda x: x)


# ------------------------------------------------- linear approximation
def lin_round(mask: int, beam: int = 8):
    """One SPN round in the mask domain; value carried is prod(2*bias)."""
    outs = [(0, 1.0)]
    for i in range(4):
        a = nib(mask, i)
        cur = []
        if a == 0:
            cur = outs
        else:
            for b in range(1, 16):
                if LAT[a][b]:
                    q = 2 * LAT[a][b] / 16
                    cur += [(d | (b << (4 * (3 - i))), p * q) for d, p in outs]
        cur.sort(key=lambda t: -abs(t[1]))
        outs = cur[:beam]
    return [(permute(d), p) for d, p in outs]


def best_linear(rounds: int = 3, beam: int = 80, max_active: int = 2):
    """(bias, input mask, output mask), best first. Bias = |prod(2*eps)| / 2."""
    return [(v / 2, s, d) for v, s, d in
            _beam_search(lin_round, rounds, beam, max_active, abs)]


# ------------------------------------------------------- key recovery
def partial_decrypt(ct: int, active, guess) -> int:
    """Undo `xor K[4]` and the last S-box on the active nibbles only."""
    u = 0
    for t, i in enumerate(active):
        u |= INV_SBOX[nib(ct, i) ^ guess[t]] << (4 * (3 - i))
    return u


def differential_attack(oracle, in_diff: int, out_diff: int, n_pairs: int):
    active = [i for i in range(4) if nib(out_diff, i)]
    pairs = []
    for _ in range(n_pairs):
        p = secrets.randbelow(1 << 16)
        pairs.append((oracle(p), oracle(p ^ in_diff)))
    scores = {}
    for g in range(1 << (4 * len(active))):
        guess = [(g >> (4 * (len(active) - 1 - t))) & 0xF for t in range(len(active))]
        hits = 0
        for c1, c2 in pairs:
            if partial_decrypt(c1, active, guess) ^ \
               partial_decrypt(c2, active, guess) == out_diff:
                hits += 1
        scores[tuple(guess)] = hits
    return active, sorted(scores.items(), key=lambda t: -t[1])


def linear_attack(oracle, in_mask: int, out_mask: int, n_texts: int):
    active = [i for i in range(4) if nib(out_mask, i)]
    data = []
    for _ in range(n_texts):
        p = secrets.randbelow(1 << 16)
        data.append((p, oracle(p)))
    scores = {}
    for g in range(1 << (4 * len(active))):
        guess = [(g >> (4 * (len(active) - 1 - t))) & 0xF for t in range(len(active))]
        agree = 0
        for p, ct in data:
            u = partial_decrypt(ct, active, guess)
            agree += parity(in_mask & p) ^ parity(out_mask & u) == 0
        scores[tuple(guess)] = abs(agree - n_texts / 2)
    return active, sorted(scores.items(), key=lambda t: -t[1])


# ------------------------------------------- a self-similar cipher + slide
_rng = random.Random(0x51DE)
SBOX16 = list(range(1 << 16))
_rng.shuffle(SBOX16)
INV_SBOX16 = [0] * (1 << 16)
for _i, _v in enumerate(SBOX16):
    INV_SBOX16[_v] = _i

ROUNDS = 1000


def slide_round(k: int, x: int) -> int:
    return SBOX16[x ^ k]


def slide_encrypt(k: int, p: int, rounds: int = ROUNDS) -> int:
    x = p
    for _ in range(rounds):
        x = slide_round(k, x)
    return x


def slide_attack(pairs):
    """P' = F_k(P) implies C' = F_k(C). Each candidate pair pins one key."""
    cands: dict[int, int] = {}
    for pi, ci in pairs:
        for pj, cj in pairs:
            if pi == pj:
                continue
            k = INV_SBOX16[pj] ^ pi            # from pj == SBOX16[pi ^ k]
            if SBOX16[ci ^ k] == cj:
                cands[k] = cands.get(k, 0) + 1
    return sorted(cands.items(), key=lambda t: -t[1])


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    ddt_max = max(DDT[a][b] for a in range(1, 16) for b in range(16))
    lat_max = max(abs(LAT[a][b]) for a in range(1, 16) for b in range(1, 16))
    print(f"[+] DDT max {ddt_max}/16, LAT max {lat_max}/16 (uniform would be 1 and 0)")
    assert DDT[0][0] == 16 and all(sum(row) == 16 for row in DDT)
    keys = [secrets.randbelow(1 << 16) for _ in range(5)]
    oracle = lambda p: encrypt(keys, p)

    # --- 1. differential ---------------------------------------------------
    p_best, in_diff, out_diff = best_differential()[0]
    print(f"[+] best 3-round characteristic 0x{in_diff:04x} -> 0x{out_diff:04x}, "
          f"p = {p_best:.5f} (~2^{-__import__('math').log2(1 / p_best):.1f})")
    assert p_best > 0.02

    active, ranked = differential_attack(oracle, in_diff, out_diff, 8000)
    truth = tuple(nib(keys[4], i) for i in active)
    print(f"[+] active nibbles {active}, true K4 {truth}, top: {ranked[:3]}")
    assert ranked[0][0] == truth, (ranked[:5], truth)
    print("[+] PASS differential last-round key recovery")

    # --- 2. linear ---------------------------------------------------------
    bias, in_mask, out_mask = best_linear()[0]
    print(f"[+] best 3-round approximation 0x{in_mask:04x} -> 0x{out_mask:04x}, "
          f"bias = {bias:.5f}")
    assert bias > 0.02

    n_texts = int(64 / bias ** 2)
    active_l, ranked_l = linear_attack(oracle, in_mask, out_mask, n_texts)
    truth_l = tuple(nib(keys[4], i) for i in active_l)
    print(f"[+] {n_texts} known plaintexts, active {active_l}, true {truth_l}, "
          f"top: {[(k, round(v, 1)) for k, v in ranked_l[:3]]}")
    assert truth_l in [k for k, _ in ranked_l[:2]], (ranked_l[:5], truth_l)
    print("[+] PASS linear (Matsui algorithm 2) last-round key recovery")

    # --- 3. slide attack ---------------------------------------------------
    slide_key = secrets.randbelow(1 << 16)
    n_queries = 800
    ps = [secrets.randbelow(1 << 16) for _ in range(n_queries)]
    pairs = [(p, slide_encrypt(slide_key, p)) for p in ps]
    print(f"[+] {ROUNDS}-round self-similar cipher, {n_queries} known plaintexts")

    cands = slide_attack(pairs)
    survivors = [k for k, _ in cands
                 if slide_encrypt(k, pairs[0][0]) == pairs[0][1]]
    print(f"[+] {len(cands)} raw candidates, {len(survivors)} survive verification")
    assert survivors and survivors[0] == slide_key, (survivors[:4], slide_key)
    print(f"[+] PASS slide attack recovered key 0x{slide_key:04x} "
          f"with {n_queries} queries, independent of the {ROUNDS} rounds")

    print("\nall checks passed")
```

## Variants & pitfalls

- **Independence is an assumption.** Measure the real probability before spending
  thousands of queries on a computed one.
- **Impossible differentials.** With no high-probability characteristic, look for
  differences *impossible* after `r` rounds: a sieve rather than a counter.
- **Beam width.** Widen it until the best characteristic stops improving. If several
  key guesses tie, break the tie with a second characteristic.
- **Active nibbles.** Guess only the key nibbles the characteristic touches.
- **Slide attacks need identical rounds.** One round constant kills them; if the cipher
  is 2-round self-similar, slide by two rounds instead.
- **Key schedule.** Independent round keys must be peeled one at a time; `K_r = K`
  gives the whole key from one round.
- **Scaling.** DES falls to `2^47` chosen plaintexts (differential) and `2^43` known
  plaintexts (linear). Full AES falls to neither; reduced-round AES does, and that is
  what CTFs use. When the search itself is the hard part, model the cipher in z3
  instead - see `block-toy-spn-z3`.

## Tools

- SageMath - `SBox` objects expose `difference_distribution_table()` and
  `linear_approximation_table()` directly. `z3` / `python-sat` for algebraic modelling.

## References

- Biham and Shamir, "Differential Cryptanalysis of DES-like Cryptosystems" (1990).
- Matsui, "Linear Cryptanalysis Method for DES Cipher" (EUROCRYPT 1993).
- Howard Heys, "A Tutorial on Linear and Differential Cryptanalysis" - the 16-bit
  4-round SPN used above follows that tutorial's structure.
- Biryukov and Wagner, "Slide Attacks" (FSE 1999).
