---
title: "Reference - Encoding Detection: base64 vs base32 vs hex vs base58"
category: misc
subcategory: encoding
type: reference
tags: [encoding-detection, base64, base32, base58, base85, ascii85, hex, url-encoding, rot13, alphabet, padding, decode, cyberchef, what-encoding-is-this, uuencode, yenc, punycode]
summary: "Alphabet tables, length and padding rules, and a decision procedure for identifying any text encoding on sight."
related: [unknown-file, crypto-triage, flag-formats, cyberchef, regex-recipes]
---

## 1. Identify on sight

| Alphabet observed | Encoding | Giveaway |
|---|---|---|
| `A-Z a-z 0-9 + /` with `=` padding | **base64** | mixed case, `+` and `/`, length is a multiple of 4 |
| `A-Z a-z 0-9 - _` | **base64url** | `-` and `_` instead of `+` and `/`; often unpadded |
| `A-Z 2-7` with `=` padding | **base32** | uppercase only, no `0 1 8 9`, length multiple of 8 |
| `0-9 a-f` (or `0-9 A-F`) | **hex** | only 16 symbols, even length |
| `1-9 A-H J-N P-Z a-k m-z` | **base58** | no `0`, `O`, `I`, `l`; used by Bitcoin/IPFS |
| 85 printable symbols incl. `!#$%&()*+-;<=>?@^_` | **base85 / ascii85** | often wrapped in `<~ ~>`; very dense |
| `0-9 A-Z a-z !#$%&()*+-;<=>?@^_` + `{}` | **base85 (RFC1924/z85)** | variant alphabets exist |
| `%` followed by 2 hex digits | **percent / URL encoding** | `%20`, `%2F` |
| `&#NN;` or `&#xNN;` or `&amp;` | **HTML entities** | |
| `\xNN`, `\uNNNN`, `\0NN` | **escape sequences** | source-code style |
| Only `0` and `1`, length a multiple of 8 | **binary text** | |
| Space-separated decimals, each < 256 | **byte ordinals** | |
| `.` `-` and spaces/slashes only | **Morse** | `ctfbrain search morse` |
| Only 2 distinct letters, groups of 5 | **Baconian** | |
| `begin 644 name` header | **uuencode** | lines start with `M` typically |
| `=ybegin` header | **yEnc** | usenet binaries |
| `xn--` prefix on a domain | **punycode** | IDN homograph territory |
| `Z` `Q` `R` heavy, no lowercase, 4-char groups | possibly a classical cipher, not an encoding | `ctfbrain search cipher-identification` |
| High-entropy raw bytes, no text alphabet | not an encoding: compressed or encrypted | `ctfbrain search unknown-file` |

---

## 2. Alphabet tables

### base64 (RFC 4648 standard)
```
index : 0         1         2         3         4         5         6
        0123456789012345678901234567890123456789012345678901234567890123
chars : ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
pad   : =
```
Variants:
| Variant | Chars 62, 63 | Padding |
|---|---|---|
| standard (RFC 4648 section 4) | `+` `/` | `=` |
| URL/filename safe (section 5) | `-` `_` | usually omitted |
| IMAP UTF-7 modified | `+` `,` | none |
| crypt / bcrypt (radix-64) | `.` `/` (and the whole order differs: `./0-9A-Za-z`) | none |
| XML Name / Y64 | `.` `_` | `-` |
| Regular expression-safe | `!` `-` | - |
| uuencode (not base64, but 6-bit) | starts at space/backtick | - |

**A custom alphabet is a very common CTF twist.** If `base64 -d` yields garbage but the length and shape are right, the alphabet has been permuted. Recover it:
```python
#!/usr/bin/env python3
"""Decode base64 that uses a custom alphabet."""
import base64

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def decode_custom(data: str, alphabet: str, pad: str = "=") -> bytes:
    assert len(alphabet) == 64, "alphabet must be 64 characters"
    table = str.maketrans(alphabet + pad, STD + "=")
    s = data.translate(table)
    return base64.b64decode(s + "=" * (-len(s) % 4))

if __name__ == "__main__":
    custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    enc = "".join(custom[STD.index(c)] if c in STD else c
                  for c in base64.b64encode(b"flag{custom_alphabet}").decode())
    assert decode_custom(enc, custom) == b"flag{custom_alphabet}"
    print("ok:", enc, "->", decode_custom(enc, custom))
```

### base32 (RFC 4648)
```
chars : ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
pad   : =
```
Variants: base32hex uses `0123456789ABCDEFGHIJKLMNOPQRSTUV`; Crockford base32 uses `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `I L O U`) and is case-insensitive; z-base-32 uses `ybndrfg8ejkmcpqxot1uwisza345h769`.

### base58
```
Bitcoin : 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
Ripple  : rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
Flickr  : 123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ
```
Removed from base58: `0`, `O`, `I`, `l` (visually ambiguous). No padding; the output length is not a fixed function of the input length.

### base85
```
ascii85 (Adobe) : chars 33..117  ('!' through 'u'), plus 'z' for four zero bytes
                  often wrapped in <~ ... ~>
Z85 (ZeroMQ)    : 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#
RFC 1924        : 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~
```

### hex
`0-9`, `a-f` or `A-F`. Common separators: none, space, `:`, `\x`, `0x`, newline every 16 bytes.

### base16/base36/base62
base36 is `0-9a-z` (case-insensitive), base62 is `0-9A-Za-z`. Both are usually **integer** encodings, not byte encodings - decode with `int(s, 36)`.

---

## 3. Length and padding rules (the decisive test)

| Encoding | Bits per char | Input bytes -> output chars | Padding rule |
|---|---|---|---|
| hex | 4 | n -> 2n | none; length always even |
| base32 | 5 | n -> `ceil(n/5)*8` | `=` to a multiple of 8. Valid counts: 0, 1, 3, 4, 6 |
| base64 | 6 | n -> `ceil(n/3)*4` | `=` to a multiple of 4. Valid counts: 0, 1, 2 |
| base85 | 6.4 | n -> `ceil(n/4)*5` | none (partial groups shortened) |
| base58 | ~5.86 | variable | none |

**Invalid padding counts are a tell**: three `=` at the end of a "base64" string means it is not base64 (or it is double-encoded). A base32 string ending in `==` (2 pads) is invalid - base32 padding is only ever 0, 1, 3, 4, or 6 characters.

```python
def looks_like(s: str) -> list[str]:
    """Return the encodings whose alphabet and length rules `s` satisfies."""
    import re
    s = "".join(s.split())
    out = []
    body = s.rstrip("=")
    pad = len(s) - len(body)
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        out.append("hex")
    if re.fullmatch(r"[A-Za-z0-9+/]+", body) and len(s) % 4 == 0 and pad in (0, 1, 2):
        out.append("base64")
    if re.fullmatch(r"[A-Za-z0-9_-]+", body) and pad in (0, 1, 2):
        out.append("base64url")
    if re.fullmatch(r"[A-Z2-7]+", body) and len(s) % 8 == 0 and pad in (0, 1, 3, 4, 6):
        out.append("base32")
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", s):
        out.append("base58")
    if re.fullmatch(r"[!-u]+", s) and not out:
        out.append("base85")
    if re.fullmatch(r"[01]+", s) and len(s) % 8 == 0:
        out.append("binary")
    return out
```

---

## 4. The decision procedure

```
Look at the character set of the whole string.
 |
 |-- Only 0-9 a-f (case-consistent), even length
 |      -> hex.   xxd -r -p
 |
 |-- Only A-Z and 2-7, ends with 0/1/3/4/6 '='
 |      -> base32.  base32 -d
 |
 |-- Mixed case + digits + (+ /) or (- _)
 |      |-- length % 4 == 0 and <=2 '='  -> base64 / base64url
 |      |-- starts with eyJ              -> JWT (3 dot-separated base64url parts)
 |      |-- decodes to more base64       -> double-encoded, repeat
 |      |-- decodes to garbage           -> custom alphabet, or it is base58
 |
 |-- Mixed case + digits, NO 0 O I l, no + / =
 |      -> base58.  base58 -d
 |
 |-- Wrapped in <~ ~> or uses !#$%&*+
 |      -> ascii85.  python3 -c "import base64,sys;print(base64.a85decode(sys.stdin.read().strip()))"
 |
 |-- Contains % followed by hex pairs
 |      -> URL encoding.  python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.stdin.read()))"
 |
 |-- Contains &# or &amp;
 |      -> HTML entities.  python3 -c "import html,sys;print(html.unescape(sys.stdin.read()))"
 |
 |-- Only 0 and 1
 |      -> binary text, 8-bit (or 7-bit ASCII if length % 7 == 0)
 |
 |-- Only . and - and spaces
 |      -> Morse
 |
 |-- Plain English letters, similar frequency profile to English
 |      -> a classical cipher, not an encoding. `ctfbrain search cipher-identification`
 |
 |-- None of the above / raw bytes
        -> compressed or encrypted. `ctfbrain search unknown-file`
```

---

## 5. Command reference

```sh
# base64
echo -n 'flag{x}' | base64
echo 'ZmxhZ3t4fQ==' | base64 -d
echo 'ZmxhZ3t4fQ' | base64 -d 2>/dev/null || python3 -c "import base64,sys;print(base64.b64decode(sys.argv[1]+'=='))" 'ZmxhZ3t4fQ'
# base64url
python3 -c "import base64,sys;print(base64.urlsafe_b64decode(sys.argv[1]+'='*(-len(sys.argv[1])%4)))" 'ZmxhZ3t4fQ'
# base32
echo -n 'flag{x}' | base32 ; echo 'MZWGCZ33MHYFQ===' | base32 -d
# hex
echo -n 'flag{x}' | xxd -p ; echo '666c61677b787d' | xxd -r -p
python3 -c "import binascii,sys;print(binascii.unhexlify(sys.argv[1]))" 666c61677b787d
# base58 (pip install base58)
python3 -c "import base58,sys;print(base58.b58decode(sys.argv[1]))" '<blob>'
# base85 / ascii85
python3 -c "import base64,sys;print(base64.a85decode(sys.argv[1]))" '<blob>'
python3 -c "import base64,sys;print(base64.b85decode(sys.argv[1]))" '<blob>'
# url
python3 -c "import urllib.parse,sys;print(urllib.parse.unquote_plus(sys.argv[1]))" 'flag%7Bx%7D'
# html
python3 -c "import html,sys;print(html.unescape(sys.argv[1]))" '&#102;lag'
# rot13 / rot-n
tr 'A-Za-z' 'N-ZA-Mn-za-m'
# binary text
python3 -c "import sys;b=sys.argv[1].replace(' ','');print(bytes(int(b[i:i+8],2) for i in range(0,len(b),8)))" '0110011001101100'
# ordinals
python3 -c "import sys;print(bytes(int(x) for x in sys.argv[1].split()))" '102 108 97 103'
# uuencode
uudecode file.uu
# quoted-printable
python3 -c "import quopri,sys;print(quopri.decodestring(sys.argv[1].encode()))" '=66lag'
# punycode
python3 -c "import sys;print(sys.argv[1].encode().decode('idna'))" 'xn--80ak6aa92e.com'
```

---

## 6. Automatic multi-layer decoder

```python
#!/usr/bin/env python3
"""Peel encoding layers off a blob until printable text appears.

Usage: ./peel.py 'WlhoaGJYQnNaUT09'
"""
import base64
import binascii
import codecs
import gzip
import sys
import urllib.parse
import zlib

MAX_DEPTH = 12


def printable(b: bytes) -> bool:
    if not b:
        return False
    good = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(b) > 0.90


def attempts(data: bytes):
    s = data.decode("latin1")
    yield "b64", lambda: base64.b64decode(data + b"=" * (-len(data) % 4), validate=True)
    yield "b64url", lambda: base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))
    yield "b32", lambda: base64.b32decode(data.upper() + b"=" * (-len(data) % 8))
    yield "b85", lambda: base64.b85decode(data)
    yield "a85", lambda: base64.a85decode(data)
    yield "hex", lambda: binascii.unhexlify(data.strip())
    yield "url", lambda: urllib.parse.unquote_to_bytes(s)
    yield "zlib", lambda: zlib.decompress(data)
    yield "gzip", lambda: gzip.decompress(data)
    yield "rot13", lambda: codecs.encode(s, "rot13").encode("latin1")


def peel(data: bytes, depth: int = 0, path=()):
    if depth >= MAX_DEPTH:
        return
    for name, fn in attempts(data):
        try:
            out = fn()
        except Exception:
            continue
        if not out or out == data:
            continue
        chain = path + (name,)
        if printable(out):
            print(" -> ".join(chain), ":", out[:300])
        peel(out, depth + 1, chain)


if __name__ == "__main__":
    blob = sys.argv[1].encode() if len(sys.argv) > 1 else sys.stdin.buffer.read().strip()
    peel(blob)
```
Run it and read the results top-down; the shortest chain that yields a flag is almost always the intended one.

For an interactive equivalent, CyberChef's **Magic** operation does the same thing with a much larger operation set: `ctfbrain search cyberchef`.

---

## 7. Gotchas

- **Whitespace and newlines** break decoders. Always `tr -d ' \n\r\t'` first.
- **Unpadded base64** is extremely common in JWTs and URLs; add `=` yourself.
- `base64 -d` on GNU coreutils errors on invalid characters; use `base64 -di` to ignore them.
- A base64 string that decodes to more base64 is **double encoded**. Keep going.
- Uppercase hex vs lowercase hex is not meaningful, but a *mix* often means it is not hex.
- Base32 of ASCII text almost always contains long runs of the same few letters; base64 does not.
- A blob whose length is a multiple of 4 AND a multiple of 8 could be either base64 or base32 - decide by alphabet, not length.
- If a decode produces bytes with high entropy, you decoded correctly but the result is compressed or encrypted, not wrong.
- CyberChef and `ciphey` exist; use them, but understand the chain afterwards so you can script it.
