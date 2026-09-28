---
title: "Baconian, Tap Code, Morse, Pigpen, Dancing Men and Other Symbol Ciphers"
category: crypto
subcategory: classical
type: technique
tags: [baconian, bacon-cipher, biliteral, morse-code, fractionated-morse, tap-code, pigpen, masonic-cipher, dancing-men, braille, semaphore, standard-galactic-alphabet, hexahue, multi-tap, t9, dtmf, symbol-cipher, steganography, cyberchef, dcode]
difficulty: easy
summary: "Symbol ciphers are 1:1 glyph substitutions or binary/ternary encodings - identify the alphabet size, transcribe to letters, then it is a substitution problem."
when_to_use:
  - "The challenge is an image of strange glyphs, boxes-with-dots, dancing figures or flags"
  - "Text is two alternating symbols in groups of five (A/B, 0/1, case, bold/italic)"
  - "Text is dots, dashes, slashes and spaces - Morse, possibly with separators removed"
  - "Text is groups of knocks/taps, or digit runs like 44 33 555 555 666"
tools: [python, cyberchef, dcode, stegsolve]
related: [classical-substitution-hillclimb, classical-adfgvx-polybius, cipher-identification, encoding-cheatsheet]
---

## TL;DR

Two families. **Glyph ciphers** (pigpen, dancing men, Standard Galactic, Hexahue,
runes, Daedric) are plain monoalphabetic substitutions wearing a costume: transcribe
the glyphs to arbitrary letters and hill-climb. **Encodings with a small symbol
alphabet** (Bacon = 2 symbols x 5, Morse = 3 symbols, tap code = unary pairs, Braille
= 6 bits) are decoded outright once you spot the grouping. The hard part is always
*noticing* which one it is.

## Recognise it

- **Baconian**: only two distinct symbols, and the length is a multiple of 5. The
  symbols may be `A`/`B`, `0`/`1`, upper/lower case, bold/plain, two fonts, two
  colours, or serif/sans - Bacon's original point was steganographic.
- **Morse**: `.`, `-`, `/`, spaces. If separators are missing, decoding is ambiguous
  and you must search all splits. "Cut Morse" replaces dots/dashes with other symbol
  pairs (`|` and `_`, `x` and `o`).
- **Fractionated Morse**: letters `A-Z` but the plaintext IoC is very flat; the
  intermediate alphabet is `{., -, x}` in trigrams.
- **Tap code**: runs of a repeated character separated by gaps, each run 1-5 long,
  in pairs: `.. ... / .... .` etc. No `K` (it is written as `C`).
- **Pigpen / Masonic / Templar / Rosicrucian**: grid and X shapes with or without a
  dot. 26 distinct glyphs.
- **Dancing men**: stick figures; flags held indicate word ends.
- **Standard Galactic Alphabet** (Commander Keen / Minecraft enchanting table),
  **Hexahue** (2x3 colour blocks), **Betamaze**, **Daedric**, **Elder Futhark runes**,
  **Ogham**, **Braille**, **Semaphore**, **Maritime flags**, **Wingdings**.
- **Multi-tap / T9**: digit runs `2-9` where a repeated digit selects a letter.
- **DTMF**: an audio file of dual tones - decode with `multimon-ng` or by FFT.

## Theory

**Baconian.** Each letter is 5 binary symbols. Two variants:
- *24-letter* (the original): `I=J` and `U=V` share codes.
- *26-letter*: every letter distinct.
Because it is binary, any two distinguishable features of a carrier text can hide it -
this is the classic "the capital letters spell something" puzzle. `AAAAA`=A,
`AAAAB`=B, ... `BABBB`=Z in the 26-letter version.

**Morse.** A prefix-free code *when separators are present*. Remove the separators and
`...` could be `S`, `EEE`, `IE`, or `EI` - so recovery becomes a search over splits
scored by English likelihood. There are Catalan-ish many splits, so use dynamic
programming with a word or n-gram model rather than brute force.

**Fractionated Morse.** Write the message in Morse with `x` between letters and `xx`
between words, then read the `{., -, x}` stream three symbols at a time and map each
trigram to a letter via a keyed alphabet. The 26 usable trigrams are all combinations
of `. - x` in lexicographic order except `xxx`. It hides Morse's statistics completely
and looks like an ordinary 26-letter cipher.

**Tap code.** A 5x5 Polybius square over 25 letters (`K` written as `C`). Each letter
becomes `row` taps, pause, `col` taps. Used by prisoners because it needs no
equipment; it shows up in CTFs as `. . / . . . .`-style text or as an audio file.

**Braille.** 6 dots = 6 bits. Unicode maps them to `U+2800 + bitmask` where dot 1 is
bit 0, dot 2 bit 1, dot 3 bit 2, dot 4 bit 3, dot 5 bit 4, dot 6 bit 5. Grade 1
braille is a plain letter substitution; grade 2 adds contractions.

**Glyph substitutions.** Once transcribed, they are exactly the monoalphabetic problem
from `classical-substitution-hillclimb`. Usually you do not even need that - pigpen and
Standard Galactic have *fixed, published* mappings, so it is a lookup.

## Attack

1. Count the distinct symbols. 2 -> Bacon/binary. 3 -> Morse or fractionated Morse.
   5-6 -> Polybius/ADFGVX family. 26ish -> glyph substitution.
2. For 2 symbols, check `len % 5 == 0` and try both Bacon variants and both symbol
   polarities (A=0 and A=1).
3. For images: reverse-image-search the glyph set, or check the usual suspects list.
   `dcode.fr/symbols-ciphers` has a searchable glyph gallery.
4. For Morse without separators, run a WORD-level DP (see `morse_segment`) and
   read the top few candidates; a letter-level score alone is not enough.
5. For steganographic Bacon, extract the binary feature: case, bold, font, colour,
   whitespace, or two similar Unicode characters.
6. If the transcription is right but the text is still scrambled, it is a glyph cipher
   with a *non-standard* mapping - hill-climb it.

## Code

```python
#!/usr/bin/env python3
"""Baconian, Morse (including separator-less recovery by word-level DP), fractionated
Morse, tap code, Braille, multi-tap/T9, and a generic glyph-to-substitution
transcriber. Pure stdlib, self-testing."""
from __future__ import annotations

import heapq
import string
from itertools import product

ALPHA = string.ascii_uppercase

# --------------------------------- Baconian --------------------------------
BACON26 = {ch: format(i, "05b").replace("0", "A").replace("1", "B")
           for i, ch in enumerate(ALPHA)}
BACON26_REV = {v: k for k, v in BACON26.items()}

# 24-letter variant: I/J share a code and U/V share a code.
_B24_ORDER = ["A", "B", "C", "D", "E", "F", "G", "H", "IJ", "K", "L", "M",
              "N", "O", "P", "Q", "R", "S", "T", "UV", "W", "X", "Y", "Z"]
BACON24 = {}
for _i, _group in enumerate(_B24_ORDER):
    for _ch in _group:
        BACON24[_ch] = format(_i, "05b").replace("0", "A").replace("1", "B")
BACON24_REV = {}
for _i, _group in enumerate(_B24_ORDER):
    BACON24_REV[format(_i, "05b").replace("0", "A").replace("1", "B")] = _group[0]


def bacon_encode(pt: str, variant: int = 26) -> str:
    table = BACON26 if variant == 26 else BACON24
    return "".join(table[c] for c in pt.upper() if c in table)


def bacon_decode(ct: str, variant: int = 26, symbols: str = "AB") -> str:
    """symbols[0] -> 'A', symbols[1] -> 'B'. Pass '01' for binary Bacon."""
    rev = BACON26_REV if variant == 26 else BACON24_REV
    body = "".join("A" if c == symbols[0] else "B"
                   for c in ct if c in symbols)
    return "".join(rev.get(body[i:i + 5], "?") for i in range(0, len(body) - 4, 5))


def bacon_from_case(text: str, variant: int = 26, upper_is_b: bool = True) -> str:
    """Steganographic Bacon hidden in letter case."""
    bits = []
    for ch in text:
        if ch.isalpha():
            hi = ch.isupper()
            bits.append("B" if hi == upper_is_b else "A")
    return bacon_decode("".join(bits), variant)


# ----------------------------------- Morse ---------------------------------
MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "/": "-..-.", "-": "-....-",
    "'": ".----.", "!": "-.-.--", "(": "-.--.", ")": "-.--.-", ":": "---...",
    "=": "-...-", "+": ".-.-.", "@": ".--.-.",
}
MORSE_REV = {v: k for k, v in MORSE.items()}


def morse_encode(pt: str, letter_sep: str = " ", word_sep: str = " / ") -> str:
    words = pt.upper().split()
    return word_sep.join(letter_sep.join(MORSE[c] for c in w if c in MORSE)
                         for w in words)


def morse_decode(ct: str, letter_sep: str = " ", word_sep: str = "/") -> str:
    out = []
    for word in ct.replace(word_sep, " | ").split():
        if word == "|":
            out.append(" ")
        else:
            out.append(MORSE_REV.get(word, "?"))
    return "".join(out)


# A compact word list for segmenting Morse that has lost its separators.
# Extend it with the challenge's own vocabulary when you have one.
COMMON_WORDS = """
the be to of and a in that have it for not on with he as you do at this
but his by from they we say her she or an will my one all would there their what so
up out if about who get which go me when make can like time no just him know take
people into year your good some could them see other than then now look only come
its over think also back after use two how our work first well way even new want
because any these give day most us man men said each she which their time would
attack dawn flag here is are was were meet bridge midnight secret message hidden
under gold river castle enemy north south east west return relief arrives sector
tomorrow key cipher code text plain crypto capture point flags ctf
""".split()


def _word_morse(words):
    out = {}
    for w in {x.upper() for x in words}:
        if all(c in MORSE for c in w):
            out[w] = "".join(MORSE[c] for c in w)
    return out


def morse_segment(stream: str, words=None, beam: int = 400, topk: int = 10):
    """Morse with ALL separators stripped: recover the word split.

    Unseparated Morse is genuinely ambiguous (`...` is S, EEE, IE or EI), so a
    character-level score does not work - the decoder just picks the fewest, longest
    letters. A WORD-level DP does work: beam-search every split into dictionary
    words, scoring sum(len(word)^2) minus a constant per word so that a few long
    words beat many short ones. Returns [(score, "WORDS ...")] best first; read the
    top few with your eyes.
    """
    wm = _word_morse(words if words is not None else COMMON_WORDS)
    s = "".join(c for c in stream if c in ".-")
    n = len(s)
    lanes: list[list] = [[] for _ in range(n + 1)]
    lanes[0] = [(0.0, ())]
    for i in range(n):
        if not lanes[i]:
            continue
        for sc, ws in lanes[i]:
            for w, m in wm.items():
                if s.startswith(m, i):
                    lanes[i + len(m)].append((sc + len(w) ** 2 - 9.0, ws + (w,)))
        for j in range(i + 1, n + 1):
            if len(lanes[j]) > beam:
                lanes[j] = heapq.nlargest(beam, lanes[j])
        lanes[i] = []
    return [(sc, " ".join(ws)) for sc, ws in heapq.nlargest(topk, lanes[n])]


def morse_all_letter_splits(stream: str, limit: int = 2000):
    """Every valid letter-level split, for short streams. Use when you have a crib."""
    s = "".join(c for c in stream if c in ".-")
    results: list[str] = []

    def walk(i, acc):
        if len(results) >= limit:
            return
        if i == len(s):
            results.append(acc)
            return
        for L in range(1, 6):
            ch = MORSE_REV.get(s[i:i + L])
            if ch is not None and ch in ALPHA:
                walk(i + L, acc + ch)

    walk(0, "")
    return results


# --------------------------- fractionated Morse ----------------------------
TRIGRAMS = [a + b + c for a, b, c in product(".-x", repeat=3)]
TRIGRAMS.remove("xxx")                       # 26 usable trigrams


def _keyed_alphabet(key: str) -> str:
    out, seen = [], set()
    for ch in (key.upper() + ALPHA):
        if ch in ALPHA and ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def fractionated_morse_encrypt(pt: str, key: str = "") -> str:
    alpha = _keyed_alphabet(key)
    words = [w for w in pt.upper().split() if w]
    stream = "xx".join("x".join(MORSE[c] for c in w if c in MORSE) for w in words)
    stream += "x" * ((-len(stream)) % 3)
    return "".join(alpha[TRIGRAMS.index(stream[i:i + 3])]
                   for i in range(0, len(stream), 3))


def fractionated_morse_decrypt(ct: str, key: str = "") -> str:
    alpha = _keyed_alphabet(key)
    stream = "".join(TRIGRAMS[alpha.index(c)] for c in ct.upper() if c in alpha)
    out = []
    for word in stream.strip("x").split("xx"):
        out.append("".join(MORSE_REV.get(t, "?") for t in word.split("x") if t))
    return " ".join(out)


# --------------------------------- tap code --------------------------------
TAP_ALPHA = "ABCDEFGHIJLMNOPQRSTUVWXYZ"      # no K: it is tapped as C


def tap_encode(pt: str, tap: str = ".", gap: str = " ", sep: str = " / ") -> str:
    out = []
    for ch in pt.upper():
        if ch == "K":
            ch = "C"
        if ch not in TAP_ALPHA:
            continue
        r, c = divmod(TAP_ALPHA.index(ch), 5)
        out.append(tap * (r + 1) + gap + tap * (c + 1))
    return sep.join(out)


def tap_decode(ct: str, tap: str = ".", sep: str = "/") -> str:
    out = []
    for group in ct.replace(sep, " ").split("  ") if "  " in ct else \
            [g.strip() for g in ct.split(sep)]:
        parts = [p for p in group.split() if p and set(p) == {tap}]
        if len(parts) == 2:
            out.append(TAP_ALPHA[(len(parts[0]) - 1) * 5 + (len(parts[1]) - 1)])
    return "".join(out)


# ---------------------------------- Braille --------------------------------
BRAILLE_DOTS = {
    "A": "1", "B": "12", "C": "14", "D": "145", "E": "15", "F": "124",
    "G": "1245", "H": "125", "I": "24", "J": "245", "K": "13", "L": "123",
    "M": "134", "N": "1345", "O": "135", "P": "1234", "Q": "12345",
    "R": "1235", "S": "234", "T": "2345", "U": "136", "V": "1236",
    "W": "2456", "X": "1346", "Y": "13456", "Z": "1356",
}


def _dots_to_char(dots: str) -> str:
    mask = sum(1 << (int(d) - 1) for d in dots)
    return chr(0x2800 + mask)


BRAILLE = {k: _dots_to_char(v) for k, v in BRAILLE_DOTS.items()}
BRAILLE_REV = {v: k for k, v in BRAILLE.items()}


def braille_encode(pt: str) -> str:
    return "".join(BRAILLE.get(c, " ") for c in pt.upper())


def braille_decode(ct: str) -> str:
    return "".join(BRAILLE_REV.get(c, " ") for c in ct)


# ------------------------------- multi-tap / T9 ----------------------------
T9_KEYS = {"2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL",
           "6": "MNO", "7": "PQRS", "8": "TUV", "9": "WXYZ"}
T9_REV = {ch: (k, i + 1) for k, v in T9_KEYS.items() for i, ch in enumerate(v)}


def multitap_encode(pt: str, sep: str = " ") -> str:
    out = []
    for ch in pt.upper():
        if ch in T9_REV:
            k, n = T9_REV[ch]
            out.append(k * n)
        elif ch == " ":
            out.append("0")
    return sep.join(out)


def multitap_decode(ct: str, sep: str = " ") -> str:
    out = []
    for group in ct.split(sep):
        if not group:
            continue
        if group == "0":
            out.append(" ")
        elif group[0] in T9_KEYS and set(group) == {group[0]}:
            letters = T9_KEYS[group[0]]
            out.append(letters[(len(group) - 1) % len(letters)])
    return "".join(out)


# ------------------- generic glyph -> substitution transcriber -------------
def transcribe_glyphs(symbols) -> tuple[str, dict]:
    """Map an arbitrary sequence of glyph tokens onto A-Z in order of appearance.

    Feed the result to a monoalphabetic solver (see classical-substitution-hillclimb).
    """
    mapping: dict = {}
    out = []
    for s in symbols:
        if s not in mapping:
            if len(mapping) >= 26:
                raise ValueError("more than 26 distinct glyphs - not a simple "
                                 "substitution")
            mapping[s] = ALPHA[len(mapping)]
        out.append(mapping[s])
    return "".join(out), mapping


if __name__ == "__main__":
    # --- Baconian ---------------------------------------------------------
    assert bacon_encode("A") == "AAAAA"
    assert bacon_encode("FLAG") == BACON26["F"] + BACON26["L"] + BACON26["A"] + BACON26["G"]
    assert bacon_decode(bacon_encode("ATTACKATDAWN")) == "ATTACKATDAWN"
    assert bacon_decode(bacon_encode("HELLO", 24), 24) == "HELLO"
    binary = bacon_encode("HI").replace("A", "0").replace("B", "1")
    assert bacon_decode(binary, symbols="01") == "HI"
    stego = "tHe QuIcK bRoWn FoX JuMpS oVeR tHe LaZy dOg ToDaY oK"
    hidden = bacon_from_case(stego)
    assert len(hidden) == len([c for c in stego if c.isalpha()]) // 5
    print(f"[ok] bacon: 26/24-letter, binary, and case-stego -> {hidden!r}")

    # --- Morse ------------------------------------------------------------
    m = morse_encode("SOS FLAG")
    assert m.startswith("... --- ...")
    assert morse_decode(m) == "SOS FLAG"
    print(f"[ok] morse round trip: {m}")

    # --- ambiguous Morse (all separators stripped) ------------------------
    for target, expected in (("THEFLAGISHERE", "THE FLAG IS HERE"),
                             ("ATTACKATDAWN", "ATTACK AT DAWN"),
                             ("MEETMEATTHEBRIDGEATMIDNIGHT",
                              "MEET ME AT THE BRIDGE AT MIDNIGHT")):
        stream = "".join(MORSE[c] for c in target)
        cands = [txt for _, txt in morse_segment(stream)]
        assert expected in cands[:3], (target, cands[:3])
    print(f"[ok] unseparated morse: word-DP put the true reading in the top 3")
    splits = morse_all_letter_splits("".join(MORSE[c] for c in "SOS"))
    assert "SOS" in splits and len(splits) > 1
    print(f"[ok] '...---...' has {len(splits)} valid letter splits, SOS among them")

    # --- fractionated Morse ----------------------------------------------
    fm = fractionated_morse_encrypt("ATTACK AT DAWN", "ROUNDTABLE")
    assert set(fm) <= set(ALPHA)
    assert fractionated_morse_decrypt(fm, "ROUNDTABLE") == "ATTACK AT DAWN"
    print(f"[ok] fractionated morse round trip: {fm}")

    # --- tap code ---------------------------------------------------------
    tc = tap_encode("WATER")
    assert tap_decode(tc) == "WATER", tap_decode(tc)
    assert tap_decode(tap_encode("KNOCK")) == "CNOCC"       # K is tapped as C
    print(f"[ok] tap code: WATER -> {tc}")

    # --- Braille ----------------------------------------------------------
    br = braille_encode("FLAG")
    assert [hex(ord(c)) for c in br] == ['0x280b', '0x2807', '0x2801', '0x281b']
    assert braille_decode(br) == "FLAG"
    print(f"[ok] braille round trip: {br}")

    # --- multi-tap / T9 ---------------------------------------------------
    mt = multitap_encode("HELLO WORLD")
    assert mt == "44 33 555 555 666 0 9 666 777 555 3", mt
    assert multitap_decode(mt) == "HELLO WORLD"
    print(f"[ok] multi-tap round trip: {mt}")

    # --- glyph transcription ---------------------------------------------
    glyphs = ["pig1", "pig2", "pig1", "pig3", "pig2", "pig4"]
    text, mapping = transcribe_glyphs(glyphs)
    assert text == "ABACBD", text
    assert mapping["pig1"] == "A"
    print(f"[ok] glyph transcription: {glyphs} -> {text}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Bacon polarity and variant.** Four combinations (24/26 letters x A=0/A=1). Try all
  four; only one gives words.
- **Bacon carriers.** Case is the obvious one, but also: bold/italic runs in a `.docx`,
  two visually identical Unicode characters (Latin `a` U+0061 vs Cyrillic small
  letter a, U+0430),
  trailing spaces vs tabs, two shades of the same colour in HTML, two fonts in a PDF.
  Extract the feature first, decode second.
- **Morse ambiguity.** Without separators a stream has exponentially many valid splits.
  The DP above returns the highest-scoring one, not necessarily *the* one - check it
  reads as English and try the top-k if not.
- **Morse `0` vs `O`.** `-----` is zero, `---` is the letter. Easy to mistype.
- **Morse prosigns.** `<AR>` `<SK>` `<BT>` are run-together letters; they appear in
  radio-flavoured challenges as unexpected long sequences.
- **Tap code has no K.** If you decode a word that should contain `K` and get `C`,
  you are right, not wrong.
- **Braille grade 2** uses contractions (`the`, `and`, `ing` as single cells) and
  number/capital prefixes (`U+283C` = number sign). A grade-1 decoder will produce
  gibberish on grade-2 text.
- **Pigpen has several layouts.** Classic Masonic, the "with dots in the second grid"
  variant, Templar (triangles), Rosicrucian. If the standard mapping gives nonsense but
  the letter frequencies look English, it is a variant - treat it as a substitution.
- **Standard Galactic Alphabet** maps 1:1 to English letters with no permutation, so
  it is a pure lookup, not a cipher.
- **Semaphore and maritime flags** are images; count distinct flags (26-30) and look up.
- **Hexahue** uses a 2x3 grid of six colours per character - extract the pixel colours
  programmatically, do not eyeball it.
- **Audio challenges.** Morse in a WAV: look at the spectrogram in Audacity/Sonic
  Visualiser, or run `multimon-ng -a MORSE_CW`. DTMF: `multimon-ng -a DTMF`.
- **More than 26 glyphs** means it is not a simple substitution - possibly homophonic,
  or the glyph set includes punctuation/nulls.

## Tools

- **dcode.fr symbol gallery** - <https://www.dcode.fr/symbols-ciphers> - searchable by
  glyph shape; the fastest way to identify an unknown alphabet.
- **CyberChef**: `From Morse Code`, `Bacon Cipher Decode`, `From Braille`,
  `Multi-tap decode` (via `Substitute`), `From Binary`.
- **multimon-ng** - decodes Morse (`-a MORSE_CW`), DTMF, POCSAG from audio.
- **Audacity / Sonic Visualiser** - spectrogram view for audio Morse.
- **Stegsolve / zsteg** - when the glyphs are hidden in an image's bit planes.
- **`morse-talk`, `pymorse` (PyPI)** - Morse helpers if you want a library.

## References

- dcode.fr symbols and ciphers index - <https://www.dcode.fr/symbols-ciphers>
- dcode.fr Baconian cipher - <https://www.dcode.fr/bacon-cipher>
- dcode.fr tap code - <https://www.dcode.fr/tap-code>
- CyberChef - <https://gchq.github.io/CyberChef/>
- multimon-ng - <https://github.com/EliasOenal/multimon-ng>
