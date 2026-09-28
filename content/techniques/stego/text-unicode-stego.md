---
title: "Text Stego - Whitespace, Zero-Width and Homoglyphs"
category: stego
subcategory: text
type: technique
tags: [text-stego, whitespace, zero-width, zwsp, zwnj, zwj, bom, homoglyph, confusables, unicode, snow, stegsnow, variation-selector, bidi, rtlo, tags-block, stego]
difficulty: medium
summary: "If a text file is bigger than its visible characters, the payload is in invisible codepoints, trailing whitespace, or lookalike letters."
when_to_use:
  - "You are given a .txt/.md/source file and told the flag is 'in plain sight'"
  - "Copying the text into a hex editor shows bytes you did not expect (e2 80 8b, ef bb bf)"
  - "A word renders normally but does not match a grep for its ASCII spelling"
  - "Lines have trailing spaces/tabs that survive into the challenge artifact"
tools: [xxd, hexdump, python3, stegsnow, uniname, grep, cat]
related: [metadata-hiding, image-triage, polyglot-files, stego-cheatsheet, osint-documents-and-code]
---

## TL;DR

Four families: **trailing whitespace** (space/tab as 0/1, what `snow`/`stegsnow` does),
**zero-width codepoints** (U+200B/200C/200D/FEFF and the Unicode Tags block U+E0000-U+E007F),
**homoglyph substitution** (Cyrillic `а` for Latin `a`), and **bidi/format controls**
(U+202E RTL override). All are invisible when rendered and obvious in hex.

## Recognise it

```bash
# 1. do the bytes match the glyphs? non-ASCII in a "plain" text file is the tell
file -i chal.txt
LC_ALL=C grep -n '[^ -~\t]' chal.txt | head

# 2. trailing whitespace
cat -A chal.txt | head -40           # $ marks EOL, ^I marks tab
grep -nP '[ \t]+$' chal.txt | wc -l

# 3. hex dump and look for e2 80 8b / e2 80 8c / e2 80 8d / ef bb bf / e2 80 ae
xxd chal.txt | grep -E 'e280 8[bcd]|efbb bf|e280 ae'

# 4. count of visible characters vs byte length
python3 -c "d=open('chal.txt','rb').read(); print(len(d), len(d.decode().encode('ascii','ignore')))"
```

## Theory

### The invisible codepoints

| Codepoint | UTF-8 | Name | Notes |
| --- | --- | --- | --- |
| U+200B | e2 80 8b | ZERO WIDTH SPACE | the classic `0` bit |
| U+200C | e2 80 8c | ZERO WIDTH NON-JOINER | the classic `1` bit |
| U+200D | e2 80 8d | ZERO WIDTH JOINER | third symbol for base-3/4 schemes |
| U+FEFF | ef bb bf | ZERO WIDTH NO-BREAK SPACE / BOM | often a delimiter |
| U+2060 | e2 81 a0 | WORD JOINER | |
| U+180E | e1 a0 8e | MONGOLIAN VOWEL SEPARATOR | zero-width in many fonts |
| U+00AD | c2 ad | SOFT HYPHEN | invisible unless line-wrapped |
| U+202E | e2 80 ae | RIGHT-TO-LEFT OVERRIDE | reverses displayed order |
| U+202D | e2 80 ad | LEFT-TO-RIGHT OVERRIDE | |
| U+E0020-U+E007E | f3 a0 80 a0 .. | TAG characters | map 1:1 onto ASCII 0x20-0x7E |
| U+FE00-U+FE0F | ef b8 80.. | VARIATION SELECTORS 1-16 | 4 bits each, attach to any base char |

The **Tags block** is the sneakiest: U+E0000 + n encodes ASCII character n directly, so
`"".join(chr(0xE0000 + ord(c)) for c in "flag{}")` is a fully invisible copy of the string.
Decoding is a one-liner once you know to look.

### Whitespace schemes

`snow` (Steganographic Nature Of Whitespace) appends tabs and spaces after the end of each
line. The common hand-rolled scheme is simply `space = 0, tab = 1`, read line by line,
packed MSB-first into bytes. Variants encode in the *number* of trailing spaces, or in
"space vs double space" between words.

### Homoglyphs

Unicode confusables: `a` U+0061 vs `а` U+0430 (Cyrillic), `o` U+006F vs `о` U+043E vs `ο`
U+03BF (Greek), `e` U+0065 vs `е` U+0435, `p`, `c`, `x`, `y`, `i`, `j`, `s`, `A`, `B`, `E`,
`K`, `M`, `H`, `O`, `P`, `T`, `X`. A message is encoded by choosing Latin (`0`) or the
lookalike (`1`) for each substitutable character. The tell is that the file is not pure ASCII
even though it reads as English.

## Attack

1. Hexdump. Any multi-byte sequence in a "plain English" file is the payload.
2. Strip everything printable-ASCII and look at what is left, in order.
3. If the residue is two distinct codepoints -> binary, MSB-first, then LSB-first.
4. If three or four distinct codepoints -> base-3/base-4 digits.
5. If the residue is Tag characters -> subtract 0xE0000 and you have ASCII directly.
6. If there is no residue, check trailing whitespace per line.
7. If neither, normalise homoglyphs and diff against the original.

```bash
# stegsnow (package name is often 'stegsnow'), decode with and without a password
stegsnow -C chal.txt
stegsnow -C -p password chal.txt

# list every non-ascii codepoint with its name (uniutils)
uniname chal.txt | head -40

# normalise to NFKC and diff - homoglyphs that fold will change
python3 -c "import unicodedata,sys;d=open(sys.argv[1],encoding='utf-8').read();print(unicodedata.normalize('NFKC',d))" chal.txt > norm.txt
diff chal.txt norm.txt
```

## Code

```python
#!/usr/bin/env python3
"""Text stego toolkit: zero-width, Unicode tags, whitespace and homoglyph codecs.

Usage:
  python3 text_stego.py scan     file.txt
  python3 text_stego.py decode   file.txt
  python3 text_stego.py encode   "cover text" "secret"
  python3 text_stego.py --selftest
"""
from __future__ import annotations

import sys
import unicodedata

# --- zero-width binary scheme ------------------------------------------------
ZW_ZERO = "​"   # ZERO WIDTH SPACE
ZW_ONE = "‌"    # ZERO WIDTH NON-JOINER
ZW_SEP = "‍"    # ZERO WIDTH JOINER, used as a separator by some encoders

INVISIBLES = {
    "​": "ZWSP", "‌": "ZWNJ", "‍": "ZWJ", "﻿": "BOM/ZWNBSP",
    "⁠": "WORD JOINER", "᠎": "MONGOLIAN VOWEL SEP", "­": "SOFT HYPHEN",
    "‪": "LRE", "‫": "RLE", "‬": "PDF", "‭": "LRO", "‮": "RLO",
    "⁡": "FUNCTION APPLICATION", "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR", "⁤": "INVISIBLE PLUS",
}

HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р",
    "x": "х", "y": "у", "i": "і", "s": "ѕ", "j": "ј",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н",
    "K": "К", "M": "М", "O": "О", "P": "Р", "T": "Т",
    "X": "Х",
}
REVERSE_HOMOGLYPHS = {v: k for k, v in HOMOGLYPHS.items()}


def bits_of(data: bytes) -> list[int]:
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]


def bytes_of(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


# --- zero width --------------------------------------------------------------
def zw_encode(cover: str, secret: bytes, after: int = 1) -> str:
    """Insert the payload as zero-width bits after character index `after`."""
    payload = "".join(ZW_ZERO if b == 0 else ZW_ONE for b in bits_of(secret))
    return cover[:after] + payload + cover[after:]


def zw_decode(text: str) -> bytes:
    bits = [0 if ch == ZW_ZERO else 1 for ch in text if ch in (ZW_ZERO, ZW_ONE)]
    return bytes_of(bits)


# --- unicode tags block ------------------------------------------------------
def tags_encode(secret: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in secret)


def tags_decode(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F)


# --- variation selectors -----------------------------------------------------
def vs_encode(base: str, secret: bytes) -> str:
    """Four bits per variation selector (VS1..VS16), attached after each base char."""
    nibbles = []
    for b in secret:
        nibbles.append(b >> 4)
        nibbles.append(b & 0x0F)
    out = []
    for i, nib in enumerate(nibbles):
        out.append(base[i % len(base)])
        out.append(chr(0xFE00 + nib))
    return "".join(out)


def vs_decode(text: str) -> bytes:
    nibbles = [ord(c) - 0xFE00 for c in text if 0xFE00 <= ord(c) <= 0xFE0F]
    out = bytearray()
    for i in range(0, len(nibbles) - 1, 2):
        out.append((nibbles[i] << 4) | nibbles[i + 1])
    return bytes(out)


# --- trailing whitespace (snow-style) ---------------------------------------
def ws_encode(lines: list[str], secret: bytes) -> list[str]:
    """One bit per line: trailing space = 0, trailing tab = 1."""
    bits = bits_of(secret)
    out = []
    for i, line in enumerate(lines):
        suffix = ""
        if i < len(bits):
            suffix = " " if bits[i] == 0 else "\t"
        out.append(line.rstrip(" \t") + suffix)
    return out


def ws_decode(lines: list[str]) -> bytes:
    bits = []
    for line in lines:
        stripped = line.rstrip("\r\n")
        if stripped.endswith("\t"):
            bits.append(1)
        elif stripped.endswith(" "):
            bits.append(0)
    return bytes_of(bits)


def ws_decode_runs(lines: list[str]) -> bytes:
    """Variant: the COUNT of trailing spaces is the character code."""
    codes = []
    for line in lines:
        stripped = line.rstrip("\r\n")
        n = len(stripped) - len(stripped.rstrip(" "))
        if n:
            codes.append(n)
    return bytes(c for c in codes if 0 < c < 256)


# --- homoglyphs --------------------------------------------------------------
def homo_encode(cover: str, secret: bytes) -> str:
    bits = bits_of(secret)
    out = []
    bi = 0
    for ch in cover:
        if ch in HOMOGLYPHS and bi < len(bits):
            out.append(HOMOGLYPHS[ch] if bits[bi] else ch)
            bi += 1
        else:
            out.append(ch)
    return "".join(out)


def homo_decode(text: str) -> bytes:
    bits = []
    for ch in text:
        if ch in REVERSE_HOMOGLYPHS:
            bits.append(1)
        elif ch in HOMOGLYPHS:
            bits.append(0)
    return bytes_of(bits)


def homo_normalize(text: str) -> str:
    return "".join(REVERSE_HOMOGLYPHS.get(ch, ch) for ch in text)


# --- scanning ----------------------------------------------------------------
def scan(text: str) -> list[str]:
    notes = []
    counts: dict[str, int] = {}
    for ch in text:
        if ch in INVISIBLES:
            counts[ch] = counts.get(ch, 0) + 1
    for ch, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        notes.append(f"{INVISIBLES[ch]} (U+{ord(ch):04X}) x{n}")
    tags = [c for c in text if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        notes.append(f"Unicode TAG characters x{len(tags)} -> {tags_decode(text)!r}")
    vs = [c for c in text if 0xFE00 <= ord(c) <= 0xFE0F]
    if vs:
        notes.append(f"variation selectors x{len(vs)} -> {vs_decode(text)!r}")
    homo = [c for c in text if c in REVERSE_HOMOGLYPHS]
    if homo:
        notes.append(f"homoglyphs x{len(homo)}: {sorted(set(homo))} -> bits give {homo_decode(text)!r}")
    lines = text.splitlines()
    trailing = [ln for ln in lines if ln != ln.rstrip(" \t")]
    if trailing:
        notes.append(f"{len(trailing)}/{len(lines)} lines have trailing whitespace "
                     f"-> {ws_decode(lines)!r}")
    nonascii = {c for c in text if ord(c) > 127 and c not in INVISIBLES}
    if nonascii:
        names = []
        for c in sorted(nonascii)[:20]:
            try:
                names.append(f"U+{ord(c):04X} {unicodedata.name(c)}")
            except ValueError:
                names.append(f"U+{ord(c):04X} <unnamed>")
        notes.append("other non-ascii: " + "; ".join(names))
    return notes


def decode_all(text: str) -> dict[str, bytes | str]:
    return {
        "zero_width": zw_decode(text),
        "tags_block": tags_decode(text),
        "variation_selectors": vs_decode(text),
        "whitespace_bits": ws_decode(text.splitlines()),
        "whitespace_runs": ws_decode_runs(text.splitlines()),
        "homoglyphs": homo_decode(text),
    }


def main() -> int:
    cmd = sys.argv[1]
    if cmd == "scan":
        text = open(sys.argv[2], encoding="utf-8", errors="replace").read()
        for n in scan(text):
            print(n)
    elif cmd == "decode":
        text = open(sys.argv[2], encoding="utf-8", errors="replace").read()
        for k, v in decode_all(text).items():
            if v:
                print(f"{k:22}: {v!r}")
    elif cmd == "encode":
        print(zw_encode(sys.argv[2], sys.argv[3].encode()))
    else:
        print(__doc__)
        return 1
    return 0


def _selftest() -> None:
    secret = b"flag{inv1sible}"

    cover = "The quick brown fox jumps over the lazy dog."
    stego = zw_encode(cover, secret)
    assert zw_decode(stego) == secret
    assert "".join(c for c in stego if c not in (ZW_ZERO, ZW_ONE)) == cover

    t = "hello" + tags_encode("flag{tagged}") + "world"
    assert tags_decode(t) == "flag{tagged}"

    v = vs_encode("abcdefghij", secret)
    assert vs_decode(v) == secret

    lines = [f"line number {i} of the cover text" for i in range(8 * len(secret))]
    wl = ws_encode(lines, secret)
    assert ws_decode(wl) == secret

    h_cover = "a considerable amount of ordinary prose, repeated. " * 10
    h = homo_encode(h_cover, secret[:4])
    assert homo_decode(h).startswith(secret[:4]), homo_decode(h)
    assert homo_normalize(h) == h_cover

    notes = scan(stego + "\n" + t)
    assert any("ZWSP" in n for n in notes), notes
    assert any("TAG characters" in n for n in notes), notes

    bad = "pl" + "е" + "ase l" + "о" + "gin"   # cyrillic e and o
    assert homo_normalize(bad) == "please login"
    print(f"selftest ok: zero-width, tags, variation selectors, whitespace, homoglyphs "
          f"({len(notes)} scan notes)")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        sys.exit(main())
    _selftest()
```

## Variants and pitfalls

- **Copy-paste destroys some schemes.** Terminals, Discord and some editors strip zero-width
  characters and trailing whitespace. Always work from the original file bytes, never from a
  pasted copy.
- **`grep` for the ASCII spelling fails** on homoglyph text. That is often the intended "aha".
- **U+202E (RTLO)** makes `exe.txt` display as `txt.exe`; in a stego challenge it usually just
  reverses a section of the flag. Strip the control character and re-read.
- **Base-3/4 schemes**: if the residue uses three or four distinct invisible codepoints, map
  them to digits in codepoint order and convert from that base, both MSB- and LSB-first.
- **The payload may be per-word, not per-line**: double spaces between words is a common
  variant of the whitespace scheme.
- **`snow` encrypts by default with ICE** if a password was given; `stegsnow -C` alone then
  returns garbage. Try common passwords from the challenge text.
- **Normalisation is destructive.** `unicodedata.normalize("NFKC", text)` folds many confusables
  and *deletes* zero-width characters in some cases - do it on a copy, for detection only.
- **Check git history and diffs.** In source-code challenges the invisible characters were often
  added in a specific commit; `git show` with `--word-diff` or `cat -A` exposes them.
- **Do not forget plain old ASCII tricks**: text hidden in HTML comments, in Markdown link
  titles, in white-on-white text in a PDF, or in a file's second half after many blank lines.

## Tools

`xxd`/`hexdump`, `cat -A`, `grep -P`, `stegsnow`, `uniutils` (`uniname`, `unidesc`), Python
`unicodedata`, any editor that can show invisible characters (VS Code "Render Whitespace" and
"Highlight Non-ASCII").

## References

- Unicode Standard Annex #9 (Bidirectional Algorithm) for the override controls.
- Unicode Technical Standard #39 (Security Mechanisms) and the confusables data file, which is
  the authoritative homoglyph list.
- The Unicode Tags block (U+E0000-U+E007F) definition in the Unicode character database.
