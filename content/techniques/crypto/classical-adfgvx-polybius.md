---
title: "ADFGVX / ADFGX, Nihilist and the Polybius Square Family"
category: crypto
subcategory: classical
type: technique
tags: [adfgvx, adfgx, polybius, polybius-square, nihilist-cipher, checkerboard, straddling-checkerboard, vic-cipher, fractionation, fractionated, columnar-transposition, digraph, coordinate-cipher, bifid, dcode, cyberchef, cryptool]
difficulty: medium
summary: "Polybius turns letters into coordinate pairs; ADFGVX transposes those pairs, Nihilist adds a repeating key to them - attack the transposition first, the square second."
when_to_use:
  - "Ciphertext uses only the six letters A D F G V X (or the five A D F G X)"
  - "Ciphertext is digit pairs in the range 11-55 (or 11-66)"
  - "Ciphertext is a list of 2-3 digit numbers larger than 66 - Nihilist additive"
  - "Ciphertext length is even and factors nicely - a transposition sits on top"
tools: [python, cyberchef, dcode, cryptool]
related: [classical-transposition, classical-playfair-bifid, classical-symbol-ciphers, cipher-identification]
---

## TL;DR

Every cipher here starts by replacing each letter with its `(row, col)` coordinates in
a keyed Polybius square. **Plain Polybius** stops there (trivial). **ADFGX/ADFGVX**
then applies a columnar transposition to the coordinate stream, which is what makes it
strong - break the transposition and what remains is a simple digraph substitution.
**Nihilist** adds a repeating numeric key to the coordinate pairs, which makes it a
Vigenere over two-digit numbers.

## Recognise it

- **ADFGVX**: alphabet is exactly `{A, D, F, G, V, X}` (those six letters were chosen
  because their Morse codes are maximally distinct). Length is even.
  **ADFGX** uses five letters and a 5x5 square (no digits, I/J merged).
- **Plain Polybius**: pairs of digits `1-5` (or `1-6`), so ciphertext length is even,
  and every character is `1..5`. Often written as `11 24 33 ...`.
- **Nihilist**: space-separated numbers roughly in `22..110`. Each is
  `(plain coordinate pair as a 2-digit number) + (key coordinate pair)`. Values above
  `55` and below `111` are the giveaway.
- **Straddling checkerboard / VIC**: a mixed-length code where common letters get one
  digit and the rest get two; output is a digit string with no obvious pairing.
- If a Polybius-looking ciphertext has coordinates but does *not* decode to English
  with any square, a transposition is layered on top.

## Theory

**Polybius square.** A 5x5 (25 letters, `I=J`) or 6x6 (36 = 26 letters + 10 digits)
grid, usually seeded with a keyword. Letter -> `(row, col)`. The 6x6 version is what
ADFGVX uses so it can carry digits.

**ADFGVX** (Fritz Nebel, 1918):
1. Substitute each plaintext character with its two row/column labels drawn from
   `ADFGVX`. A message of $n$ characters becomes $2n$ symbols.
2. Write those $2n$ symbols row-wise under a transposition keyword of length $k$ and
   read the columns off in the keyword's alphabetical order.

The transposition is what separates the two halves of each letter, so unigram
statistics on the ciphertext are flat - it is a genuine fractionating cipher.

**Why it breaks.** The intermediate string has *even* length $2n$, and the two halves
of every plaintext character sit at positions $2i$ and $2i+1$. Under a columnar
transposition with an even key length $k$, each column therefore holds symbols of a
single parity - all "row" halves or all "column" halves - which constrains the
solution space sharply. Historically Painvin exploited pairs of messages with
identical beginnings; in practice today you:
- brute force the transposition key order for $k \le 8$ (or hill-climb it),
- undo the transposition, re-pair the symbols,
- solve the resulting **digraph -> letter** map as a monoalphabetic substitution over
  36 symbols (frequency analysis, or a keyword guess for the square).

**Nihilist.** Plaintext letter -> Polybius pair -> 2-digit number $P$. Key letter ->
2-digit number $K$. Ciphertext number $C = P + K$ (no carry reduction). Because
$P, K \in [11, 55]$, $C \in [22, 110]$. This is a Vigenere over base-10 pairs: find
the key length by the usual periodic statistics, then each residue class is a single
additive constant that you solve by frequency. Known plaintext recovers the key
instantly: $K = C - P$.

**Straddling checkerboard.** Row 0 holds 8 high-frequency letters at single digits;
two "escape" digits lead to rows 1 and 2 for the remaining letters and digits. It
compresses and makes the digit stream self-delimiting. In the VIC cipher it is then
combined with a chain addition and a double transposition.

## Attack

1. Count the distinct symbols. 6 -> ADFGVX. 5 -> ADFGX. Digits 1-5 -> Polybius.
   Numbers 22-110 -> Nihilist.
2. For ADFGVX: factor the ciphertext length. The transposition key length $k$ divides
   it (for a complete grid) or nearly does. Try $k = 2..10$.
3. Brute force (or Held-Karp / hill-climb) the column order. For each candidate,
   re-pair the symbols and check that every pair is a valid coordinate - and that the
   resulting 36-symbol frequency profile looks like a language (a few very frequent
   digraphs = E, T, A).
4. Guess the square's keyword, or solve the digraph substitution by hill climbing
   exactly as in `classical-substitution-hillclimb` but over 36 symbols.
5. For Nihilist: find the period (Kasiski on the number stream, or per-period IoC on
   the implied letters), then solve each residue class as a shift.

## Code

```python
#!/usr/bin/env python3
"""Polybius, ADFGX, ADFGVX and Nihilist: encode, decode, and attacks.

Includes a transposition brute force against ADFGVX given a known/guessed square,
and known-plaintext key recovery for Nihilist. Self-testing."""
from __future__ import annotations

import math
import string
from collections import Counter
from itertools import permutations

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"            # I = J
ALPHA36 = string.ascii_uppercase + "0123456789"
ADFGX_LABELS = "ADFGX"
ADFGVX_LABELS = "ADFGVX"

_CORPUS = (
    "the history of the world is in many ways the history of the ordinary people "
    "who lived through it and not only of the kings and generals whose names are "
    "written in the books that children read at school in every village there were "
    "farmers who watched the weather and the price of grain and children who "
    "learned to count the days until the harvest they did not think of themselves "
    "as living in a period that would one day be given a name by scholars they "
    "thought about the rain and the road to the market and whether there would be "
    "enough bread in the house for the long winter that was coming very soon"
)


def clean(t: str, alphabet: str = ALPHA25) -> str:
    u = t.upper()
    if "J" not in alphabet:
        u = u.replace("J", "I")
    return "".join(c for c in u if c in alphabet)


def _model(n: int):
    s = clean(_CORPUS, ALPHA36)
    c = Counter(s[i:i + n] for i in range(len(s) - n + 1))
    tot, vocab = sum(c.values()), 36 ** n
    return ({g: math.log10((v + 1) / (tot + vocab)) for g, v in c.items()},
            math.log10(1 / (tot + vocab)))


_TRI, _TRIF = _model(3)


def eng_score(s: str) -> float:
    s = clean(s, ALPHA36)
    if len(s) < 3:
        return -1e9
    return sum(_TRI.get(s[i:i + 3], _TRIF) for i in range(len(s) - 2))


def make_square(key: str, alphabet: str = ALPHA25) -> str:
    """Keyword square, row-major."""
    out, seen = [], set()
    for ch in clean(key, alphabet) + alphabet:
        if ch in alphabet and ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


# ----------------------------- plain Polybius ------------------------------
def polybius_encode(pt: str, square: str = ALPHA25, one_indexed: bool = True) -> str:
    side = int(len(square) ** 0.5)
    base = 1 if one_indexed else 0
    out = []
    for ch in clean(pt, square):
        r, c = divmod(square.index(ch), side)
        out.append(f"{r + base}{c + base}")
    return "".join(out)


def polybius_decode(ct: str, square: str = ALPHA25, one_indexed: bool = True) -> str:
    side = int(len(square) ** 0.5)
    base = 1 if one_indexed else 0
    digits = [c for c in ct if c.isdigit()]
    out = []
    for i in range(0, len(digits) - 1, 2):
        r = int(digits[i]) - base
        c = int(digits[i + 1]) - base
        out.append(square[r * side + c])
    return "".join(out)


# -------------------------------- ADFG(V)X ---------------------------------
def key_order(keyword: str) -> list[int]:
    """Read-out order: column indices sorted by key letter, ties left-to-right."""
    k = "".join(c for c in keyword.upper() if c.isalnum())
    return [i for i, _ in sorted(enumerate(k), key=lambda t: (t[1], t[0]))]


def _fractionate(pt: str, square: str, labels: str) -> str:
    side = len(labels)
    out = []
    for ch in clean(pt, square):
        r, c = divmod(square.index(ch), side)
        out.append(labels[r] + labels[c])
    return "".join(out)


def _defractionate(frac: str, square: str, labels: str) -> str:
    side = len(labels)
    out = []
    for i in range(0, len(frac) - 1, 2):
        r, c = labels.index(frac[i]), labels.index(frac[i + 1])
        out.append(square[r * side + c])
    return "".join(out)


def columnar_encrypt(s: str, order, pad: str = "A") -> str:
    k = len(order)
    if len(s) % k:
        s += pad * (k - len(s) % k)
    cols = ["".join(s[i::k]) for i in range(k)]
    return "".join(cols[c] for c in order)


def columnar_decrypt(s: str, order) -> str:
    k = len(order)
    n = len(s)
    full, extra = divmod(n, k)
    lengths = [full + (1 if i < extra else 0) for i in range(k)]
    cols, pos = {}, 0
    for c in order:
        cols[c] = s[pos:pos + lengths[c]]
        pos += lengths[c]
    out = []
    for r in range(max(lengths)):
        for c in range(k):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)


def adfgvx_encrypt(pt: str, square_key: str, trans_key: str,
                   labels: str = ADFGVX_LABELS) -> str:
    alphabet = ALPHA36 if len(labels) == 6 else ALPHA25
    square = make_square(square_key, alphabet)
    frac = _fractionate(pt, square, labels)
    return columnar_encrypt(frac, key_order(trans_key), pad=labels[0])


def adfgvx_decrypt(ct: str, square_key: str, trans_key: str,
                   labels: str = ADFGVX_LABELS) -> str:
    alphabet = ALPHA36 if len(labels) == 6 else ALPHA25
    square = make_square(square_key, alphabet)
    frac = columnar_decrypt("".join(c for c in ct.upper() if c in labels),
                            key_order(trans_key))
    return _defractionate(frac, square, labels)


def crack_adfgvx_transposition(ct: str, square_key: str, min_k: int = 2,
                               max_k: int = 7, labels: str = ADFGVX_LABELS,
                               top: int = 3):
    """Known/guessed square, unknown transposition key: brute force the order."""
    alphabet = ALPHA36 if len(labels) == 6 else ALPHA25
    square = make_square(square_key, alphabet)
    body = "".join(c for c in ct.upper() if c in labels)
    cands = []
    for k in range(min_k, max_k + 1):
        if len(body) % k:
            continue                       # complete grid only
        for order in permutations(range(k)):
            frac = columnar_decrypt(body, order)
            pt = _defractionate(frac, square, labels)
            cands.append((eng_score(pt), k, order, pt))
    cands.sort(key=lambda t: -t[0])
    return cands[:top]


def adfgvx_keylen_candidates(ct: str, labels: str = ADFGVX_LABELS,
                             max_k: int = 12) -> list[int]:
    """Transposition key lengths consistent with a complete grid."""
    n = sum(1 for c in ct.upper() if c in labels)
    return [k for k in range(2, max_k + 1) if n % k == 0]


# ------------------------------- Nihilist ----------------------------------
def nihilist_encrypt(pt: str, square_key: str, key: str) -> list[int]:
    square = make_square(square_key, ALPHA25)
    def num(ch):
        r, c = divmod(square.index(ch), 5)
        return (r + 1) * 10 + (c + 1)
    p = clean(pt, ALPHA25)
    k = clean(key, ALPHA25)
    return [num(p[i]) + num(k[i % len(k)]) for i in range(len(p))]


def nihilist_decrypt(nums, square_key: str, key: str) -> str:
    square = make_square(square_key, ALPHA25)
    def num(ch):
        r, c = divmod(square.index(ch), 5)
        return (r + 1) * 10 + (c + 1)
    k = clean(key, ALPHA25)
    out = []
    for i, v in enumerate(nums):
        p = v - num(k[i % len(k)])
        r, c = divmod(p, 10)
        out.append(square[(r - 1) * 5 + (c - 1)])
    return "".join(out)


def nihilist_key_from_known_plaintext(nums, pt: str, square_key: str,
                                      keylen: int) -> str:
    """K = C - P, read off the first `keylen` positions."""
    square = make_square(square_key, ALPHA25)
    def num(ch):
        r, c = divmod(square.index(ch), 5)
        return (r + 1) * 10 + (c + 1)
    p = clean(pt, ALPHA25)
    key = []
    for i in range(keylen):
        kv = nums[i] - num(p[i])
        r, c = divmod(kv, 10)
        key.append(square[(r - 1) * 5 + (c - 1)])
    return "".join(key)


def nihilist_guess_keylen(nums, max_len: int = 12) -> list[tuple[int, float]]:
    """Per-period variance: the true period makes each residue class low-spread."""
    scores = []
    for m in range(1, max_len + 1):
        spread = 0.0
        for j in range(m):
            col = nums[j::m]
            if len(col) < 2:
                continue
            mean = sum(col) / len(col)
            spread += sum((v - mean) ** 2 for v in col) / len(col)
        scores.append((m, spread / m))
    return sorted(scores, key=lambda t: t[1])


if __name__ == "__main__":
    # --- plain Polybius ---------------------------------------------------
    sq = make_square("POLYBIUS")
    enc = polybius_encode("ATTACKATDAWN", sq)
    assert polybius_decode(enc, sq) == "ATTACKATDAWN"
    assert polybius_encode("A", ALPHA25) == "11"
    assert polybius_decode("11", ALPHA25) == "A"
    print(f"[ok] polybius round trip: {enc}")

    # --- ADFGX (5 labels, 25 letters) ------------------------------------
    m5 = "ATTACKATONCEANDTAKETHEBRIDGE"
    c5 = adfgvx_encrypt(m5, "BIRTHDAY", "CARGO", ADFGX_LABELS)
    assert set(c5) <= set(ADFGX_LABELS)
    assert adfgvx_decrypt(c5, "BIRTHDAY", "CARGO", ADFGX_LABELS).startswith(m5)
    print(f"[ok] adfgx round trip: {c5[:32]}...")

    # --- ADFGVX (6 labels, 36 symbols incl. digits) ----------------------
    m6 = "ATTACKAT1200AMTHEFLAGIS4DFGVXFUN"
    c6 = adfgvx_encrypt(m6, "NACHRICHT", "PRIVAT")
    assert set(c6) <= set(ADFGVX_LABELS)
    assert adfgvx_decrypt(c6, "NACHRICHT", "PRIVAT").startswith(m6)
    print(f"[ok] adfgvx round trip: {c6[:32]}...")

    # --- break the transposition with a known square ---------------------
    long_msg = ("WEATTACKATDAWNTOMORROWBRINGTHEARTILLERYFORWARDANDHOLDTHE"
                "BRIDGEUNTILRELIEFARRIVESFROMTHENORTHERNSECTOR")
    ct = adfgvx_encrypt(long_msg, "NACHRICHT", "ABCDE")   # order = identity, k=5
    hits = crack_adfgvx_transposition(ct, "NACHRICHT", 2, 6)
    assert hits[0][3].startswith("WEATTACKATDAWN"), hits[0][3][:40]
    print(f"[ok] adfgvx transposition cracked: k={hits[0][1]} order={hits[0][2]}")

    secret_order = key_order("PRIVAT")
    ct2 = adfgvx_encrypt(long_msg, "NACHRICHT", "PRIVAT")
    hits2 = crack_adfgvx_transposition(ct2, "NACHRICHT", 2, 6)
    assert hits2[0][2] == tuple(secret_order), (hits2[0][2], secret_order)
    print(f"[ok] recovered PRIVAT column order {hits2[0][2]}")

    # --- Nihilist ---------------------------------------------------------
    nums = nihilist_encrypt("DYNAMITEWINTERPALACE", "ZEBRAS", "RUSSIAN")
    assert all(22 <= v <= 110 for v in nums)
    assert nihilist_decrypt(nums, "ZEBRAS", "RUSSIAN") == "DYNAMITEWINTERPALACE"
    rec_key = nihilist_key_from_known_plaintext(nums, "DYNAMITE", "ZEBRAS", 7)
    assert rec_key == "RUSSIAN", rec_key
    print(f"[ok] nihilist key recovered from known plaintext: {rec_key}")

    periods = nihilist_guess_keylen(nihilist_encrypt(long_msg, "ZEBRAS", "RUSSIAN"))
    print(f"[ok] nihilist period ranking (best first): {[p for p, _ in periods[:4]]}")
    assert 7 in [p for p, _ in periods[:4]]
    print("all self-tests passed")
```

## Variants & pitfalls

- **ADFGX vs ADFGVX.** Five labels and 25 letters (I=J, no digits) vs six labels,
  36 symbols. Count the distinct symbols before anything else.
- **Padding.** The intermediate string is padded to fill the grid; the historical
  cipher used an incomplete last row instead. Try both `columnar_decrypt` modes.
- **The square keyword is separate from the transposition keyword.** Two independent
  keys. CTFs usually reuse one word for both, or give you one of them.
- **Solving the square without a guess** is a 36-symbol monoalphabetic substitution on
  digraphs - hill-climb it with digraph frequencies once the transposition is undone.
  The very common digraphs correspond to `E`, `N`, `I`, `R` in German messages.
- **Parity constraint.** After the correct transposition, every pair of symbols must be
  a valid `(row, col)`. With 6 labels every pair is valid, so that check is useless for
  ADFGVX - but for a 5x5 ADFGX with a 25-letter square it is also always valid. The
  useful structural test is the *frequency profile* of the resulting digraphs, not
  validity.
- **Nihilist carries.** Some implementations reduce mod 10 per digit (no carry), some
  add as plain integers. If decryption produces coordinates outside `1..5`, you have
  the wrong convention.
- **Nihilist over a 6x6 square** exists (with digits), giving numbers up to 132.
- **Straddling checkerboard** output has no fixed pairing, so do not try to split it
  into 2-digit groups. Look for the two "escape" digits - they appear far more often
  than the others and are never the last digit of the message.
- **Polybius with letter labels other than ADFGVX**: any 5 or 6 distinct characters
  work (`12345`, `ABCDE`, `.-/|*`). Treat the label set as a parameter.
- **Tap code** is a 5x5 Polybius with unary counts - see `classical-symbol-ciphers`.

## Tools

- **dcode.fr**: ADFGVX, ADFGX, Polybius, Nihilist, Straddling Checkerboard - all with
  solvers that accept a partial key.
- **CyberChef**: `ADFGVX Cipher Decode`, `Polybius Square`.
- **CrypTool 2**: ADFGVX component plus a transposition analyser you can chain.
- **`secretpy` (PyPI)**: implementations of Polybius, ADFGX, ADFGVX, Nihilist.

## References

- dcode.fr ADFGVX cipher - <https://www.dcode.fr/adfgvx-cipher>
- dcode.fr Nihilist cipher - <https://www.dcode.fr/nihilist-cipher>
- dcode.fr Polybius square - <https://www.dcode.fr/polybius-cipher>
- CyberChef - <https://gchq.github.io/CyberChef/>
