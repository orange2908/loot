---
title: "Repeating-Key XOR and the Many-Time Pad"
category: crypto
subcategory: xor
type: technique
tags: [xor, repeating-key-xor, vigenere, many-time-pad, two-time-pad, keystream-reuse, hamming-distance, index-of-coincidence, chi-squared, frequency-analysis, crib-dragging, transposition, keylength, xortool, cryptopals, cyberchef, known-plaintext]
difficulty: easy
summary: "Repeating-key XOR splits into independent single-byte XOR problems once you know the key length; Hamming distance or the index of coincidence finds that length."
when_to_use:
  - "A ciphertext is the same length as the plaintext and xored with a short repeating key"
  - "Ciphertext has visible periodicity, or repeated byte patterns at a fixed stride"
  - "Several messages were encrypted with the SAME keystream (many-time pad)"
  - "A stream cipher, CTR mode or OTP reused its nonce and you have C1 xor C2"
  - "The challenge says `Vigenere`, `xor`, `otp`, or hands you a hex/base64 blob"
tools: [xortool, cyberchef, python, featherduster]
source:
  name: "Cryptopals Set 1"
  url: "https://cryptopals.com/sets/1"
related: [xor-known-plaintext, aes-ctr-nonce-reuse, stream-rc4-attacks, hash-collisions-magic]
---

## TL;DR

`C[i] = P[i] xor K[i mod n]`. Every `n`-th byte is encrypted with the same key byte, so
once you know `n` the problem is `n` independent single-byte XOR problems, each solved
by frequency analysis. Find `n` with the normalised Hamming distance between adjacent
blocks or with the index of coincidence, then transpose, then solve each column.

The many-time pad is the same problem with `n = len(message)`: instead of many bytes
per column you have one byte per message, so you need several ciphertexts.

## Recognise it

- `len(ct) == len(pt)`, no block structure, no IV.
- `bytes(a ^ b for a, b in zip(data, cycle(key)))` in the source.
- A hex or base64 blob that decodes to high-entropy bytes with a suspicious period:
  `ct[i] == ct[i+n]` happens far more often than chance for the true `n`.
- Several ciphertexts from the same service whose pairwise xor is mostly printable.
- `xortool -c 20 file` immediately reports a likely key length.

## Theory

**Key length by Hamming distance.** For the correct key length `n`, two adjacent
`n`-byte blocks are `P1 xor K` and `P2 xor K`; their xor is `P1 xor P2`, which is
English-ish and therefore has *few* set bits (English ASCII is concentrated in a
narrow byte range). For a wrong `n` the xor looks random, with ~4 set bits per byte.
So compute

$$d(n) = \frac{1}{m}\sum_{i} \frac{\mathrm{hamming}(B_i, B_{i+1})}{n}$$

over several block pairs and take the smallest. Random data gives `~4.0` bits per
byte; correct English-vs-English gives `~2.5-3.0`.

**Key length by index of coincidence.** For a candidate `n`, take every `n`-th byte
and compute $IC = \sum_c f_c (f_c - 1) / (N(N-1))$. English text has
`IC ~ 0.065-0.070`; uniform random bytes give `IC ~ 0.0039`. The true `n` (and its
multiples) stand out sharply, and IC beats Hamming distance on short ciphertexts.

**Solving a column.** A column is single-byte XOR. Try all 256 keys and score with
chi-squared against English letter frequencies,
$\chi^2 = \sum_c (O_c - E_c)^2 / E_c$, keeping the lowest. Penalise non-printable
bytes heavily - that alone usually picks the right key.

**Many-time pad.** `N` messages under one keystream. Column `j` gives `N` samples of
`P_i[j] xor KS[j]`. Either use the *space statistic* (`letter xor 0x20` is a letter
with the case flipped, so the message whose column byte xors to a letter against most
others holds a space, pinning `KS[j]`), or *column scoring*: treat the column as a
single-byte-XOR problem across messages and score all 256 candidates with an English
log-likelihood model. Column scoring wins once `N >= 8`.

**Crib dragging.** Given `X = C1 xor C2 = P1 xor P2`, slide a guessed word `w` along
`X`: at the offset where `P2` contains `w`, `X xor w` reveals the corresponding
stretch of `P1`. Then extend the crib in both directions and bounce between the two.

## Attack

1. Decode the blob (hex, base64, raw).
2. Score key lengths 2..40 with Hamming distance and IC. Watch for multiples: if 6
   scores well so will 12 and 18, so prefer the smallest.
3. Transpose into `n` columns and solve each with single-byte XOR + chi-squared.
4. Join the key bytes, decrypt, read. If the text is 90% right, fix the bad columns by
   hand - you can usually read the intended word and back out the key byte.
5. If it is a many-time pad instead, run the column scorer across messages and finish
   by crib dragging.

## Code

```python
#!/usr/bin/env python3
"""Repeating-key XOR and many-time-pad solvers.

Key-length detection by normalised Hamming distance and index of coincidence,
column-wise chi-squared solving, crib dragging, and a many-time-pad recovery.
Self-test encrypts a known plaintext with a random key and asserts exact recovery.
"""

import math
import os
import secrets
from itertools import cycle

# Relative frequency of each character in English prose, including the space.
ENGLISH_FREQ = {
    " ": 18.00, "e": 10.23, "t": 7.51, "a": 6.54, "o": 6.31, "n": 5.71, "i": 5.67,
    "s": 5.32, "r": 5.06, "h": 4.90, "l": 3.38, "d": 3.29, "u": 2.30, "c": 2.25,
    "m": 2.06, "f": 1.83, "w": 1.72, "y": 1.66, "g": 1.63, "p": 1.57, "b": 1.25,
    "v": 0.80, "k": 0.59, "x": 0.14, "q": 0.09, "j": 0.09, "z": 0.05,
}


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, cycle(key)))


# ------------------------------------------------------------- scoring
def score_english(data: bytes) -> float:
    """Chi-squared distance to English. Lower is better; inf for junk."""
    if not data:
        return float("inf")
    bad = sum(1 for b in data if b < 9 or (13 < b < 32) or b > 126)
    if bad:
        return float("inf")
    counts: dict[str, int] = {}
    letters = 0
    for b in data:
        c = chr(b).lower()
        if c in ENGLISH_FREQ:
            counts[c] = counts.get(c, 0) + 1
            letters += 1
    if letters < len(data) * 0.6:
        return float("inf")
    chi = 0.0
    for c, pct in ENGLISH_FREQ.items():
        expected = letters * pct / 100.0
        observed = counts.get(c, 0)
        chi += (observed - expected) ** 2 / expected
    return chi


def single_byte_xor(data: bytes) -> tuple[float, int, bytes]:
    """Best (score, key byte, plaintext) over all 256 single-byte keys."""
    best = (float("inf"), 0, b"")
    for k in range(256):
        pt = bytes(b ^ k for b in data)
        s = score_english(pt)
        if s < best[0]:
            best = (s, k, pt)
    return best


# --------------------------------------------------- key-length detection
def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keysizes_hamming(data: bytes, lo: int = 2, hi: int = 40,
                           top: int = 5) -> list[tuple[float, int]]:
    scores = []
    for n in range(lo, min(hi, len(data) // 4) + 1):
        chunks = [data[i * n:(i + 1) * n] for i in range(len(data) // n)]
        pairs = [(chunks[i], chunks[i + 1]) for i in range(min(len(chunks) - 1, 20))]
        if not pairs:
            continue
        avg = sum(hamming_distance(x, y) for x, y in pairs) / (len(pairs) * n)
        scores.append((avg, n))
    return sorted(scores)[:top]


def index_of_coincidence(data: bytes) -> float:
    n = len(data)
    if n < 2:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def guess_keysizes_ioc(data: bytes, lo: int = 2, hi: int = 40,
                       top: int = 5) -> list[tuple[float, int]]:
    """Average IC of the n columns. English columns score ~0.065, random ~0.004."""
    scores = []
    for n in range(lo, min(hi, len(data) // 4) + 1):
        ics = [index_of_coincidence(data[j::n]) for j in range(n)]
        scores.append((sum(ics) / n, n))
    return sorted(scores, reverse=True)[:top]


# ----------------------------------------------------------- the solvers
def guess_keysize(data: bytes, lo: int = 2, hi: int = 40,
                  ioc_threshold: float = 0.055) -> int | None:
    """Smallest key length whose columns have an English-like index of coincidence.

    Multiples of the true length also pass the threshold, so scanning upwards and
    returning the FIRST hit gives the true length rather than a multiple.
    """
    hi = min(hi, max(lo, len(data) // 4))
    for n in range(lo, hi + 1):
        ics = [index_of_coincidence(data[j::n]) for j in range(n)]
        if sum(ics) / n >= ioc_threshold:
            return n
    return None


def reduce_period(key: bytes) -> bytes:
    """Collapse `abcabcabc` to `abc`. Multiples of the key length always score well."""
    n = len(key)
    for d in range(1, n):
        if n % d == 0 and key == key[:d] * (n // d):
            return key[:d]
    return key


def break_repeating_key_xor(data: bytes, keysizes: list[int] | None = None,
                            tolerance: float = 1.3) -> tuple[bytes, bytes]:
    """Return (key, plaintext).

    Multiples of the true key length fit at least as well as the true length, so
    among all candidates within `tolerance` of the best chi-squared score we keep
    the SHORTEST key. That is what stops a 9-byte key coming back as 36 bytes.
    """
    if keysizes is None:
        n = guess_keysize(data)
        if n is not None:
            keysizes = [n]
        else:                                   # short or non-English ciphertext
            cand = {m for _, m in guess_keysizes_hamming(data, top=6)}
            cand |= {m for _, m in guess_keysizes_ioc(data, top=6)}
            keysizes = sorted(cand)
    results = []
    for n in sorted(keysizes):
        key = reduce_period(bytes(single_byte_xor(data[j::n])[1] for j in range(n)))
        pt = repeating_key_xor(data, key)
        results.append((score_english(pt), len(key), key, pt))
    finite = [r for r in results if r[0] != float("inf")] or results
    best = min(r[0] for r in finite)
    for score, _n, key, pt in sorted(finite, key=lambda r: r[1]):
        if score <= best * tolerance:
            return key, pt
    return finite[0][2], finite[0][3]


def crib_drag(xored: bytes, crib: bytes):
    """Slide `crib` over C1 xor C2; yields (offset, candidate other plaintext)."""
    for off in range(len(xored) - len(crib) + 1):
        yield off, xor_bytes(xored[off:off + len(crib)], crib)


# Log-likelihood per character. Chi-squared is useless on a 10-byte sample; a plain
# sum of log-probabilities is not, which is what makes the many-time-pad solve work.
_LOGP = {}
for _c, _f in ENGLISH_FREQ.items():
    _LOGP[ord(_c)] = math.log(_f / 100.0)
    if _c != " ":
        _LOGP[ord(_c.upper())] = math.log(_f / 100.0 * 0.06)
for _c in ".,'\"!?;:-()_{}/0123456789":
    _LOGP[ord(_c)] = math.log(0.002)
_MISS = math.log(1e-7)


def score_column(data: bytes) -> float:
    """Log-likelihood that `data` is a column of English text. Higher is better."""
    return sum(_LOGP.get(b, _MISS) for b in data)


def solve_many_time_pad(cts: list[bytes]) -> bytes:
    """Recover the shared keystream: each column is a single-byte-XOR problem."""
    longest = max(len(c) for c in cts)
    ks = bytearray(longest)
    for pos in range(longest):
        column = bytes(c[pos] for c in cts if len(c) > pos)
        best_k, best_s = 0, float("-inf")
        for k in range(256):
            s = score_column(bytes(b ^ k for b in column))
            if s > best_s:
                best_k, best_s = k, s
        ks[pos] = best_k
    return bytes(ks)


# --------------------------------------------------------------------- demo
PLAIN = (
    b"It was the best of times, it was the worst of times, it was the age of "
    b"wisdom, it was the age of foolishness, it was the epoch of belief, it "
    b"was the epoch of incredulity, it was the season of Light, it was the "
    b"season of Darkness, it was the spring of hope, it was the winter of "
    b"despair, we had everything before us, we had nothing before us, we were "
    b"all going direct to Heaven, we were all going direct the other way. "
    b"In short, the period was so far like the present period that some of its "
    b"noisiest authorities insisted on its being received, for good or for "
    b"evil, in the superlative degree of comparison only. The flag is "
    b"flag{repeating_key_xor_is_just_many_single_byte_xors}. "
)

MANY = [
    b"the quick brown fox jumps over the lazy dog again and again today",
    b"cryptography is the practice of secure communication in the open",
    b"never use the same keystream twice or you will regret it quickly",
    b"a stream cipher must have a unique nonce for every single message",
    b"the index of coincidence measures how far from random a text is",
    b"frequency analysis breaks every simple substitution ever invented",
    b"english prose has far more spaces than any other single character",
    b"this sentence exists only to give the solver another data point",
    b"and this one as well because statistics love a larger sample set",
    b"the flag is flag{many_time_pad_is_no_pad_at_all} and nothing else",
    b"repeating key xor is a vigenere cipher over the whole byte range",
    b"transposing the ciphertext turns one hard problem into easy ones",
    b"one time pads are only unbreakable when used exactly one time each",
    b"the space character is the single strongest statistical signal here",
    b"column scoring beats chi squared badly on very short byte samples",
    b"do not roll your own crypto unless you are doing it for a puzzle",
    b"every additional ciphertext makes the statistics noticeably better",
    b"an attacker with ten messages recovers nearly the whole keystream",
]

if __name__ == "__main__":
    # --- repeating-key XOR -------------------------------------------------
    key = bytes(secrets.choice(b"abcdefghijklmnopqrstuvwxyz_") for _ in range(9))
    ct = repeating_key_xor(PLAIN, key)
    print("[+] real key:", key)

    ham = guess_keysizes_hamming(ct)
    ioc = guess_keysizes_ioc(ct)
    print("[+] hamming top-5 :", [(round(s, 3), n) for s, n in ham])
    print("[+] ioc     top-5 :", [(round(s, 4), n) for s, n in ioc])
    assert len(key) in [n for _, n in ham] or len(key) in [n for _, n in ioc]
    assert guess_keysize(ct) == len(key), guess_keysize(ct)
    print("[+] ioc threshold picks key length", guess_keysize(ct))

    found_key, found_pt = break_repeating_key_xor(ct)
    print("[+] found key:", found_key)
    assert found_key == key, (found_key, key)
    assert found_pt == PLAIN
    print("[+] PASS repeating-key xor recovered exactly")
    print("[+]", found_pt[-60:].decode())

    # --- known key length shortcut -----------------------------------------
    k2, p2 = break_repeating_key_xor(ct, keysizes=[len(key)])
    assert k2 == key and p2 == PLAIN
    print("[+] PASS solve with a known key length")

    # --- many-time pad -----------------------------------------------------
    ks = os.urandom(max(len(m) for m in MANY))
    cts = [xor_bytes(m, ks[:len(m)]) for m in MANY]

    guess = solve_many_time_pad(cts)
    common = min(len(m) for m in MANY)       # columns with every message present
    hits = sum(1 for i in range(common) if guess[i] == ks[i])
    acc = hits / common
    print(f"[+] keystream accuracy over {common} well-covered columns: {acc:.0%}")
    assert acc >= 0.90, acc

    flag_line = xor_bytes(cts[9], guess[:len(cts[9])])
    print("[+] recovered:", flag_line)
    assert b"flag{many_time_pad_is_no_pad_at_all}" in flag_line
    print("[+] PASS many-time pad")

    # --- crib dragging -----------------------------------------------------
    x = xor_bytes(cts[0], cts[1])
    hits = [(o, c) for o, c in crib_drag(x, b"cryptography")
            if score_english(c) != float("inf")]
    assert any(b"the quick br" == c for _, c in hits), hits[:5]
    print("[+] PASS crib dragging:", hits[0])

    print("\nall checks passed")
```

## Variants & pitfalls

- **Multiples of the key length also score well.** If `4`, `8` and `12` all look good,
  the answer is `4`. Below ~10x the key length Hamming distance is noise; use IC, or
  brute-force lengths 2..16 and pick the most readable output.
- **Non-English plaintext.** Swap the frequency table: for base64 score by "is it in
  the base64 alphabet", for JSON weight `"`, `:`, `,`, `{`.
- **A column can go wrong** when it holds few bytes or an unusual letter mix. Decrypt
  anyway: one wrong key byte is one wrong character every `n` positions, easy to fix
  by eye. And do not restrict key bytes to printable ASCII unless the challenge says
  so - though if it is text, restricting is a huge speedup.
- **`xortool` is fast but not magic.** `xortool -c 20 -l 9 file` assumes the most
  frequent plaintext byte is `0x20`, which fails on binary payloads.
- **Too few messages.** With `N < 5` the column statistic is unreliable; switch to crib
  dragging with format-specific guesses (`flag{`, `the `, `HTTP/1.1`, `{"`).
- **Xor with a file header.** Magic bytes are free known plaintext for the first
  `len(magic)` key bytes - see `xor-known-plaintext`.

## Tools

- `xortool -c 20 <file>` - key-length guess; `xortool -l <n> -c 20` to decrypt.
- CyberChef "XOR Brute Force" / "XOR"; `featherduster` for interactive analysis.

## References

- Cryptopals Set 1, challenges 3-6 (single-byte XOR, detection, repeating-key XOR):
  <https://cryptopals.com/sets/1>
- Cryptopals Set 3, challenges 19-20 (fixed-nonce CTR = many-time pad):
  <https://cryptopals.com/sets/3>
