---
title: "Playfair, Bifid, Trifid and Four-Square - Polybius-Grid Ciphers"
category: crypto
subcategory: classical
type: technique
tags: [playfair, bifid, trifid, four-square, foursquare, two-square, polybius, polybius-square, digraph, digraphic, fractionation, delastelle, 5x5-grid, keyword-square, cryptool, dcode, cyberchef, classical-cipher]
difficulty: medium
summary: "Grid ciphers map letters to coordinates: Playfair/Four-square substitute digraphs, Bifid/Trifid fractionate and transpose the coordinates."
when_to_use:
  - "Ciphertext length is even and contains no J (or no Q) - 25-letter alphabet"
  - "No doubled letters ever appear inside a digraph pair (classic Playfair tell)"
  - "IoC is between 0.045 and 0.060 - flatter than monoalphabetic but not random"
  - "Challenge text mentions a 5x5 square, a keyword square, Delastelle, or a period"
tools: [python, cryptool, dcode, cyberchef]
related: [classical-adfgvx-polybius, classical-substitution-hillclimb, classical-transposition, cipher-identification]
---

## TL;DR

All four ciphers start from a keyword-seeded Polybius square. **Playfair** and
**Four-square** are digraphic substitutions (two letters in, two letters out).
**Bifid** and **Trifid** are *fractionating*: they split each letter into
coordinates, transpose the coordinate stream, then reassemble. In a CTF the key is
almost always a dictionary word, so a keyword brute force over a wordlist beats
hill climbing.

## Recognise it

- **Playfair**: ciphertext length is always even; `J` (or sometimes `Q`) never
  appears; no digraph at an even offset has two identical letters. IoC ~0.045-0.060.
- **Four-square / Two-square**: same evenness, but `J` *can* appear if the squares use
  a different omission; doubled letters within a pair are allowed (unlike Playfair).
- **Bifid**: 25-letter alphabet, no `J`; ciphertext length equals plaintext length;
  IoC is low (~0.04) because fractionation destroys letter statistics. A *period*
  parameter is usually small (5, 7, 10).
- **Trifid**: 27 symbols (26 letters + one filler such as `.` or `+`), period-based.
- A plain **Polybius square** encoding shows up as digit pairs `11`-`55` - see
  `classical-adfgvx-polybius`.

## Theory

**The keyed square.** Write the keyword (deduplicated), then the rest of the alphabet.
For 5x5 drop `J` (merge into `I`); for 6x6 include `0-9`; for Trifid use 27 symbols in
a 3x3x3 cube.

**Playfair** encrypts digraphs `(a, b)`:
- same row -> take the letter to the right of each (wrap);
- same column -> take the letter below each (wrap);
- otherwise -> rectangle rule: each letter takes the column of the other.

Preprocessing: split into pairs; if a pair would be a double letter, insert `X` (or
`Q`) between them; pad the tail with `X`. Decryption reverses row/column shifts; the
rectangle rule is self-inverse.

**Four-square** uses four 5x5 squares laid out as a 2x2 block: top-left and
bottom-right are *plain* alphabets, top-right and bottom-left are *keyed*. For a
plaintext pair `(a, b)`: locate `a` in the top-left, `b` in the bottom-right, then
output the letter at `(row_a, col_b)` of the **top-right** square and the letter at
`(row_b, col_a)` of the **bottom-left** square. **Two-square** is the degenerate case
where only two squares are used.

**Bifid** (Delastelle). For each letter take `(row, col)` from the square. Within each
block of `period` letters, write the rows on one line and the cols beneath, then read
the two lines left-to-right as a single stream of numbers and re-pair them into
`(row, col)` to get the ciphertext letters. Period 1 degenerates to a simple
substitution; an infinite period spreads the mixing over the whole message.

**Trifid** is the same idea in 3 dimensions: each letter becomes
`(layer, row, col)` in a 3x3x3 cube; three lines per block instead of two.

**Why fractionation matters.** Bifid/Trifid diffuse each plaintext letter across
several ciphertext letters, so single-letter and digraph statistics carry very little
information. Attacks therefore target the *period* first (a period-aware IoC), then
hill-climb the square.

## Attack

1. Count the alphabet. 25 symbols, no `J` -> 5x5 family. 27 symbols -> Trifid.
2. Even length + no doubled pair -> Playfair or Four-square.
3. **Try the wordlist first.** CTF keys are words: `SECRET`, `PLAYFAIR`, `CRYPTO`,
   the challenge name, the CTF name. Generate the square from each candidate, decrypt,
   score with n-grams, keep the best. A 10k-word list runs in a second.
4. If you have a crib (e.g. `FLAG`), locate it: a Playfair crib gives you several
   grid constraints (same row / same column / rectangle) that usually pin most of the
   square immediately.
5. For Bifid, sweep `period = 1..30` and pick the one whose "even-position letters"
   IoC spikes; then hill-climb the 25-letter square.
6. Failing all of that, use CrypTool 2 / the BION online solvers, which ship tuned
   simulated-annealing implementations with full quadgram tables.

## Code

```python
#!/usr/bin/env python3
"""Playfair, Four-square, Bifid and Trifid: encrypt, decrypt, and a keyword
brute-force attack against Playfair. Run directly for a self-test."""
from __future__ import annotations

import math
import string
from collections import Counter

ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"          # no J
ALPHA27 = string.ascii_uppercase + "."          # trifid filler

# --- tiny embedded English model (bigram+trigram) for candidate ranking ----
_CORPUS = (
    "the history of the world is in many ways the history of the ordinary people "
    "who lived through it and not only of the kings and generals whose names are "
    "written in the books that children read at school in every village there were "
    "farmers who watched the weather and the price of grain women who carried water "
    "from the well before the sun was high and children who learned to count the "
    "days until the harvest they did not think of themselves as living in a period "
    "that would one day be given a name by scholars they thought about the rain the "
    "road to the market and whether there would be enough bread in the house for "
    "the winter that was coming when a traveller came to such a village he brought "
    "news from the city and the news was often wrong but it was the only news there "
    "was he would sit by the fire in the evening and tell of the great river that "
    "runs to the sea of the ships that come from the islands with salt and iron and "
    "of the men who build walls of stone around their houses because they are afraid "
    "of what may come out of the forest at night the children listened with open "
    "mouths and the old men said that in their own time the stories had been better"
)


def clean(text: str, alphabet: str = ALPHA25) -> str:
    t = text.upper()
    if "J" not in alphabet:
        t = t.replace("J", "I")
    return "".join(c for c in t if c in alphabet)


def _model(n: int):
    s = clean(_CORPUS)
    c = Counter(s[i:i + n] for i in range(len(s) - n + 1))
    tot, vocab = sum(c.values()), 25 ** n
    return ({g: math.log10((v + 1) / (tot + vocab)) for g, v in c.items()},
            math.log10(1 / (tot + vocab)))


_TRI, _TRIF = _model(3)
_BI, _BIF = _model(2)


def eng_score(s: str) -> float:
    """Higher = more English-like."""
    s = clean(s)
    if len(s) < 3:
        return -1e9
    return (sum(_TRI.get(s[i:i + 3], _TRIF) for i in range(len(s) - 2))
            + 0.5 * sum(_BI.get(s[i:i + 2], _BIF) for i in range(len(s) - 1)))


def make_square(key: str, alphabet: str = ALPHA25) -> str:
    """Keyword square: dedup(key) then the remaining alphabet, row-major."""
    out, seen = [], set()
    for ch in clean(key, alphabet) + alphabet:
        if ch in alphabet and ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def _rc(square: str, ch: str, width: int = 5):
    return divmod(square.index(ch), width)


# --------------------------- Playfair -------------------------------------
def playfair_pairs(pt: str, filler: str = "X") -> list[str]:
    s = clean(pt)
    pairs, i = [], 0
    while i < len(s):
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else filler
        if a == b:
            b = filler
            i += 1
        else:
            i += 2
        pairs.append(a + b)
    return pairs


def playfair_encrypt(pt: str, key: str, filler: str = "X") -> str:
    sq = make_square(key)
    out = []
    for a, b in playfair_pairs(pt, filler):
        r1, c1 = _rc(sq, a)
        r2, c2 = _rc(sq, b)
        if r1 == r2:
            out.append(sq[r1 * 5 + (c1 + 1) % 5] + sq[r2 * 5 + (c2 + 1) % 5])
        elif c1 == c2:
            out.append(sq[((r1 + 1) % 5) * 5 + c1] + sq[((r2 + 1) % 5) * 5 + c2])
        else:
            out.append(sq[r1 * 5 + c2] + sq[r2 * 5 + c1])
    return "".join(out)


def playfair_decrypt(ct: str, key: str) -> str:
    sq = make_square(key)
    t = clean(ct)
    out = []
    for i in range(0, len(t) - 1, 2):
        a, b = t[i], t[i + 1]
        r1, c1 = _rc(sq, a)
        r2, c2 = _rc(sq, b)
        if r1 == r2:
            out.append(sq[r1 * 5 + (c1 - 1) % 5] + sq[r2 * 5 + (c2 - 1) % 5])
        elif c1 == c2:
            out.append(sq[((r1 - 1) % 5) * 5 + c1] + sq[((r2 - 1) % 5) * 5 + c2])
        else:
            out.append(sq[r1 * 5 + c2] + sq[r2 * 5 + c1])
    return "".join(out)


def crack_playfair_keyword(ct: str, words, top: int = 5):
    """The CTF-realistic attack: try every word in a list as the key."""
    scored = []
    for w in words:
        if not w.strip():
            continue
        pt = playfair_decrypt(ct, w)
        scored.append((eng_score(pt), w.upper(), pt))
    scored.sort(key=lambda t: -t[0])
    return scored[:top]


# -------------------------- Four-square ------------------------------------
def four_square_encrypt(pt: str, key1: str, key2: str, filler: str = "X") -> str:
    plain_sq = ALPHA25
    tr, bl = make_square(key1), make_square(key2)
    s = clean(pt)
    if len(s) % 2:
        s += filler
    out = []
    for i in range(0, len(s), 2):
        r1, c1 = _rc(plain_sq, s[i])
        r2, c2 = _rc(plain_sq, s[i + 1])
        out.append(tr[r1 * 5 + c2] + bl[r2 * 5 + c1])
    return "".join(out)


def four_square_decrypt(ct: str, key1: str, key2: str) -> str:
    plain_sq = ALPHA25
    tr, bl = make_square(key1), make_square(key2)
    t = clean(ct)
    out = []
    for i in range(0, len(t) - 1, 2):
        r1, c1 = _rc(tr, t[i])
        r2, c2 = _rc(bl, t[i + 1])
        out.append(plain_sq[r1 * 5 + c2] + plain_sq[r2 * 5 + c1])
    return "".join(out)


# ----------------------------- Bifid ---------------------------------------
def bifid_encrypt(pt: str, key: str, period: int = 5) -> str:
    sq = make_square(key)
    s = clean(pt)
    out = []
    for blk_start in range(0, len(s), period):
        blk = s[blk_start:blk_start + period]
        rows, cols = [], []
        for ch in blk:
            r, c = _rc(sq, ch)
            rows.append(r)
            cols.append(c)
        stream = rows + cols
        for i in range(0, len(stream), 2):
            out.append(sq[stream[i] * 5 + stream[i + 1]])
    return "".join(out)


def bifid_decrypt(ct: str, key: str, period: int = 5) -> str:
    sq = make_square(key)
    t = clean(ct)
    out = []
    for blk_start in range(0, len(t), period):
        blk = t[blk_start:blk_start + period]
        stream = []
        for ch in blk:
            r, c = _rc(sq, ch)
            stream += [r, c]
        half = len(stream) // 2
        rows, cols = stream[:half], stream[half:]
        for r, c in zip(rows, cols):
            out.append(sq[r * 5 + c])
    return "".join(out)


# ----------------------------- Trifid --------------------------------------
def _trifid_coords(square: str, ch: str):
    i = square.index(ch)
    return i // 9, (i // 3) % 3, i % 3


def trifid_encrypt(pt: str, key: str, period: int = 5) -> str:
    sq = make_square(key, ALPHA27)
    s = clean(pt, ALPHA27)
    out = []
    for start in range(0, len(s), period):
        blk = s[start:start + period]
        a, b, c = [], [], []
        for ch in blk:
            x, y, z = _trifid_coords(sq, ch)
            a.append(x)
            b.append(y)
            c.append(z)
        stream = a + b + c
        for i in range(0, len(stream), 3):
            out.append(sq[stream[i] * 9 + stream[i + 1] * 3 + stream[i + 2]])
    return "".join(out)


def trifid_decrypt(ct: str, key: str, period: int = 5) -> str:
    sq = make_square(key, ALPHA27)
    t = clean(ct, ALPHA27)
    out = []
    for start in range(0, len(t), period):
        blk = t[start:start + period]
        stream = []
        for ch in blk:
            stream += list(_trifid_coords(sq, ch))
        third = len(stream) // 3
        a, b, c = stream[:third], stream[third:2 * third], stream[2 * third:]
        for x, y, z in zip(a, b, c):
            out.append(sq[x * 9 + y * 3 + z])
    return "".join(out)


def bifid_period_scan(ct: str, key: str, max_period: int = 20):
    """Rough period detector: which period makes the decryption most English?"""
    return sorted(((eng_score(bifid_decrypt(ct, key, p)), p)
                   for p in range(1, max_period + 1)), reverse=True)


if __name__ == "__main__":
    pt = "HIDETHEGOLDINTHETREESTUMPNEARTHEOLDCHURCHYARDBEFORESUNRISE"

    # --- Playfair round trip ---------------------------------------------
    ct = playfair_encrypt(pt, "PLAYFAIREXAMPLE")
    rec = playfair_decrypt(ct, "PLAYFAIREXAMPLE")
    # The X inserted between the doubled EE comes back out; strip fillers to compare.
    assert rec.replace("X", "").startswith("HIDETHEGOLDINTHETREESTUMP")
    assert playfair_decrypt(playfair_encrypt(pt, "MONARCHY"), "MONARCHY").startswith("HIDE")
    print(f"[ok] playfair round trip: {ct[:24]}...")

    # Known historical vector: key MONARCHY, "HIDETHEGOLDINTHETREXESTUMP"
    assert make_square("MONARCHY").startswith("MONARCHYBDEFGIKLPQSTUVWXZ")
    print("[ok] playfair keyed square matches the MONARCHY textbook square")

    # --- Playfair keyword brute force ------------------------------------
    long_pt = ("THE ART OF WAR TEACHES US TO RELY NOT ON THE LIKELIHOOD OF THE ENEMY "
               "NOT COMING BUT ON OUR OWN READINESS TO RECEIVE HIM AND ON THE FACT "
               "THAT WE HAVE MADE OUR POSITION UNASSAILABLE IN EVERY RESPECT")
    secret_key = "MONARCHY"
    ct2 = playfair_encrypt(long_pt, secret_key)
    wordlist = ["password", "secret", "crypto", "monarchy", "playfair",
                "example", "keyword", "cipher", "square", "flag"]
    hits = crack_playfair_keyword(ct2, wordlist)
    assert hits[0][1] == "MONARCHY", hits[:2]
    print(f"[ok] playfair keyword brute force -> {hits[0][1]} (score {hits[0][0]:.0f})")

    # --- Four-square round trip ------------------------------------------
    fs = four_square_encrypt("HELPMEOBIWANKENOBI", "EXAMPLE", "KEYWORD")
    assert four_square_decrypt(fs, "EXAMPLE", "KEYWORD") == "HELPMEOBIWANKENOBI"
    print(f"[ok] four-square round trip: {fs}")

    # --- Bifid round trip -------------------------------------------------
    for period in (1, 3, 5, 7, 10):
        b = bifid_encrypt(pt, "BIFIDKEY", period)
        assert bifid_decrypt(b, "BIFIDKEY", period) == clean(pt), period
    print("[ok] bifid round trip for periods 1,3,5,7,10")

    # --- Bifid period detection ------------------------------------------
    b5 = bifid_encrypt(long_pt, "BIFIDKEY", 5)
    scan = bifid_period_scan(b5, "BIFIDKEY", 12)
    assert scan[0][1] == 5, scan[:3]
    print(f"[ok] bifid period detected = {scan[0][1]}")

    # --- Trifid round trip ------------------------------------------------
    for period in (1, 4, 5, 9):
        t = trifid_encrypt(pt, "TRIFIDKEY", period)
        assert trifid_decrypt(t, "TRIFIDKEY", period) == clean(pt, ALPHA27), period
    print("[ok] trifid round trip for periods 1,4,5,9")
    print("all self-tests passed")
```

## Variants & pitfalls

- **The `J` question.** Most Playfair implementations merge `I/J`; some drop `Q`
  instead. If a decryption is readable except for one impossible letter, you picked
  the wrong omission. dcode.fr lets you choose.
- **The filler letter.** `X` is standard, `Q` and `Z` are used too. A decryption full
  of stray `X`s between doubled letters is *correct* - strip them mentally.
- **Odd-length Playfair ciphertext is impossible.** If you have one, you mis-copied
  it or it is not Playfair.
- **Playfair is not key-unique.** Rotating all rows or all columns of the square
  produces an equivalent key; so does a full row/column cyclic shift. A hill climber
  will return one of many equivalent squares - the *plaintext* is what matters.
- **Four-square vs Two-square.** Two-square (vertical or horizontal) reuses the plain
  alphabet differently and can output a pair identical to the input pair, which
  Four-square cannot. That is a useful distinguisher.
- **Bifid period off by one.** Getting the period wrong produces text that is right in
  the first block and garbage afterwards - a very recognisable failure mode.
- **Conjugated matrix bifid / "bifid with two squares"** exists; if a simple bifid
  never converges, check for a second square.
- **Trifid alphabet.** The 27th symbol varies: `.`, `+`, `#`, or a repeated letter.
  Try each; the round trip only works with the right one.
- **Hill climbing these grids is genuinely hard** with a small n-gram model. Use the
  full `english_quadgrams.txt` and simulated annealing, or hand it to CrypTool 2.
  In CTFs the keyword attack almost always lands first.

## Tools

- **dcode.fr** - Playfair, Four-square, Two-square, Bifid, Trifid solvers, each with
  automatic key search and a manual square editor.
- **CyberChef** - `Bifid Cipher Encode/Decode`, `Playfair`. No key recovery.
- **CrypTool 2** - proper simulated-annealing analysers for Playfair and Bifid with
  full quadgram statistics; the best free offline option.
- **`cipher-tools` / `secretpy` (PyPI)** - implementations of all four if you want to
  avoid writing the grid code.
- Your own wordlist: `rockyou.txt`, `/usr/share/dict/words`, the CTF's own name.

## References

- dcode.fr Playfair cipher - <https://www.dcode.fr/playfair-cipher>
- dcode.fr Bifid cipher - <https://www.dcode.fr/bifid-cipher>
- dcode.fr Four-square cipher - <https://www.dcode.fr/four-square-cipher>
- Practical Cryptography, "Playfair Cipher" - <http://practicalcryptography.com/ciphers/playfair-cipher/>
- CrypTool 2 - <https://www.cryptool.org/en/ct2/>
