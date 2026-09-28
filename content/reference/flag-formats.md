---
title: "Reference - Flag Formats and How to Grep for Them"
category: misc
subcategory: flags
type: reference
tags: [flag-formats, flag-regex, grep, find-the-flag, picoctf, htb, thm, base64-flag, hex-flag, rot13-flag, utf16-flag, flag-detection, submission, stuck]
summary: "Common CTF flag formats, the regexes that match them, and how to find flags that are encoded, split, or stored in unusual encodings."
related: [regex-recipes, encoding-detection, stuck]
---

## 1. The universal grep

```sh
# the one command to run against everything, always
grep -rniaE '[a-z0-9_-]{2,20}\{[^}]{4,120}\}' . 2>/dev/null | head -50

# the classic narrower version
grep -rniE '(flag|ctf|key|pass|pwn|crypto|web|rev)\{[^}]*\}' . 2>/dev/null

# binary-safe, including UTF-16LE (Windows memory dumps, .NET strings)
strings -a -n 6 target | grep -aiE '[a-z0-9_]{2,20}\{[^}]{4,}\}'
strings -a -e l target | grep -aiE '[a-z0-9_]{2,20}\{[^}]{4,}\}'
strings -a -e b target | grep -aiE '[a-z0-9_]{2,20}\{[^}]{4,}\}'

# recursive across a whole extracted tree, including binaries, showing the filename
grep -rIaniE --binary-files=text 'flag\{|ctf\{|FLAG\{' . | head -50
```

Flag-shaped but no braces (hash-style flags):
```sh
grep -rnoE '\b[0-9a-f]{32}\b' .      # MD5-style (HTB, THM)
grep -rnoE '\b[0-9a-f]{40}\b' .      # SHA1-style
grep -rnoE '\b[0-9a-f]{64}\b' .      # SHA256-style
```

---

## 2. Format table by platform / event family

| Platform / family | Format | Regex |
|---|---|---|
| Generic | `flag{...}` | `flag\{[^}]+\}` |
| Generic uppercase | `FLAG{...}` | `FLAG\{[^}]+\}` |
| Generic | `CTF{...}` | `CTF\{[^}]+\}` |
| picoCTF | `picoCTF{...}` | `picoCTF\{[^}]+\}` |
| Hack The Box (challenges) | `HTB{...}` | `HTB\{[^}]+\}` |
| Hack The Box (machines) | 32 hex chars, no wrapper | `\b[0-9a-f]{32}\b` |
| TryHackMe | `THM{...}` | `THM\{[^}]+\}` |
| Google CTF | `CTF{...}` | `CTF\{[^}]+\}` |
| DEF CON quals (historical) | varies per year, often a raw string | - |
| HITCON | `hitcon{...}` | `hitcon\{[^}]+\}` |
| CSAW | `flag{...}` | `flag\{[^}]+\}` |
| PlaidCTF | `PCTF{...}` | `PCTF\{[^}]+\}` |
| RCTF / *CTF family | `<name>{...}` | `[A-Za-z]+\{[^}]+\}` |
| OverTheWire | a bare password string on a line | `^[A-Za-z0-9]{20,}$` |
| Root-Me | a bare password string | - |
| pwnable.kr / pwnable.tw | a sentence-like string | `^[ -~]{20,}$` |
| Vulnhub / boot2root | `root.txt` / `user.txt` contents | `\b[0-9a-f]{32}\b` |

**Do not assume.** The scoreboard/rules page always states the exact format. Pin it in your team chat at minute zero. `ctfbrain search ctf-start`

Common inner-content conventions: underscores instead of spaces, leetspeak, the challenge name as a prefix, and a random suffix. Inner content is usually `[A-Za-z0-9_!@#$%^&*()\-+=.,:;?/\\]`.

---

## 3. Encoded flags: detection recipes

### Base64
A base64'd `flag{` begins with a predictable prefix because the first 3 bytes map to 4 chars:

| Plaintext prefix | Base64 prefix (offset 0) |
|---|---|
| `flag{` | `ZmxhZ3` |
| `FLAG{` | `RkxBR3` |
| `CTF{` | `Q1RGe` |
| `ctf{` | `Y3Rme` |
| `picoCTF{` | `cGljb0NURn` |
| `HTB{` | `SFRCe` |
| `THM{` | `VEhNe` |

Because base64 alignment depends on the offset, also search for the 1- and 2-byte-shifted forms:
```sh
# all three alignments of "flag{"
grep -raoiE 'ZmxhZ3|mbGFne|ZsYWd7' . | head
# generic: find every base64 blob and decode it, keeping hits
grep -raoE '[A-Za-z0-9+/]{16,}={0,2}' . | sed 's/^[^:]*://' | sort -u | \
  while read -r b; do printf '%s' "$b" | base64 -d 2>/dev/null | grep -aiE 'flag|ctf\{'; done
```

Generate the shifted prefixes yourself for any flag format:
```python
#!/usr/bin/env python3
"""Print the base64/base32/hex forms of a flag prefix at all byte alignments."""
import base64

def b64_prefixes(prefix: str):
    out = []
    for pad in range(3):
        blob = base64.b64encode(b"\x00" * pad + prefix.encode()).decode()
        # drop the characters that encode the padding bytes
        start = (pad * 8 + 5) // 6
        out.append(blob[start:start + 6])
    return out

def b32_prefixes(prefix: str):
    out = []
    for pad in range(5):
        blob = base64.b32encode(b"\x00" * pad + prefix.encode()).decode()
        start = (pad * 8 + 4) // 5
        out.append(blob[start:start + 6])
    return out

if __name__ == "__main__":
    for p in ("flag{", "FLAG{", "CTF{", "picoCTF{", "HTB{"):
        print(f"{p:12} b64 {b64_prefixes(p)}  b32 {b32_prefixes(p)}  hex {p.encode().hex()}")
```

### Hex
```sh
# "flag{" = 666c61677b ; "FLAG{" = 464c41477b ; "CTF{" = 4354467b
grep -raoiE '666c61677b|464c41477b|4354467b|63746[66]7b' . | head
# any long hex blob, decoded
grep -raoE '\b[0-9a-fA-F]{20,}\b' . | sed 's/^[^:]*://' | sort -u | \
  while read -r h; do printf '%s' "$h" | xxd -r -p 2>/dev/null | grep -aiE 'flag|ctf\{'; done
```

### Base32
`flag{` -> `MZWGCZ33` (aligned). Search `MZWGCZ` and its shifts (use the script above).
```sh
grep -raoE '[A-Z2-7]{16,}={0,6}' . | sed 's/^[^:]*://' | sort -u | \
  while read -r b; do printf '%s' "$b" | base32 -d 2>/dev/null | grep -aiE 'flag|ctf\{'; done
```

### ROT13 / Caesar
`flag{` under ROT13 is `sbnt{`. Under any Caesar shift the `{` and `}` survive, so:
```sh
# the braces are the invariant: find any 4-6 letter word followed by {
grep -raoE '[A-Za-z]{2,10}\{[^}]{4,}\}' . | head -40
# then rotate every candidate
python3 -c "
import sys, codecs
s = sys.argv[1]
for k in range(26):
    print(k, ''.join(chr((ord(c)-97+k)%26+97) if c.islower() else chr((ord(c)-65+k)%26+65) if c.isupper() else c for c in s))" 'synt{grfg}'
```

### URL / HTML / percent encoding
```sh
grep -raoiE 'flag%7[bB]|%66%6c%61%67|&#102;&#108;&#97;&#103;' .
python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))" 'flag%7Btest%7D'
```

### Other transforms worth a single try
| Transform | Detector |
|---|---|
| Reversed | `grep -raoiE '\}[^{]{4,}\{galf'` |
| XOR with a single byte | brute-force all 256 keys and grep (script below) |
| Base58 | no `0`, `O`, `I`, `l`; `base58 -d` |
| Base85/ascii85 | `<~ ... ~>` wrapper, or a very wide alphabet |
| Binary text (`01100110...`) | `grep -raoE '[01]{40,}'` then 8-bit chunks |
| Decimal ordinals | `102 108 97 103 123` |
| Morse | `.-.. ..-. ` and only `.-/ ` characters |
| Braille unicode | `U+2800` block |
| Whitespace (Whitespace lang / snow) | trailing spaces+tabs; `cat -A` |
| Zero-width characters | `grep -P '[\x{200b}-\x{200f}\x{feff}]'` |
| UTF-16 | `strings -e l` |
| Gzip/zlib | `binwalk`, or `python3 -c "import zlib,sys;print(zlib.decompress(open(sys.argv[1],'rb').read()))"` |

Single-byte XOR sweep:
```python
#!/usr/bin/env python3
"""Brute-force single-byte XOR over a file and report any flag-shaped hit."""
import re
import sys

PAT = re.compile(rb"[A-Za-z0-9_-]{2,20}\{[^}]{4,120}\}")

def sweep(path: str):
    data = open(path, "rb").read()
    hits = []
    for k in range(256):
        x = bytes(b ^ k for b in data)
        for m in PAT.finditer(x):
            hits.append((k, m.group()))
    return hits

if __name__ == "__main__":
    for k, hit in sweep(sys.argv[1] if len(sys.argv) > 1 else "target.bin"):
        print(hex(k), hit)
```

---

## 4. Flags split across a file

Some challenges scatter the flag. Detect that:

```sh
# every single-character-in-braces pattern, in file order
grep -raoE '\{[A-Za-z0-9_]\}' . | head -60
# flag characters with indices, e.g. flag[3] = 'x'
grep -rnoE 'flag\s*\[\s*[0-9]+\s*\]\s*=\s*.' .
# the flag as a list of ordinals
grep -rnoE '\[\s*(1[0-9]{2}|[0-9]{1,2})\s*(,\s*(1[0-9]{2}|[0-9]{1,2})\s*){8,}\]' .
```

---

## 5. A general-purpose flag hunter

```python
#!/usr/bin/env python3
"""Search a file (or a tree) for flags, trying many decodings at once.

Usage: ./flaghunt.py <path> [pattern]
"""
import base64
import binascii
import codecs
import gzip
import os
import re
import sys
import zlib

DEFAULT = r"[A-Za-z0-9_-]{2,20}\{[^}\n]{3,150}\}"


def candidates(data: bytes):
    """Yield (label, bytes) for a set of cheap decodings of `data`."""
    yield "raw", data
    yield "rev", data[::-1]
    try:
        yield "utf16le", data.decode("utf-16-le", "ignore").encode()
    except Exception:
        pass
    for k in range(1, 256):
        yield f"xor{k:02x}", bytes(b ^ k for b in data)
    try:
        yield "rot13", codecs.encode(data.decode("latin1"), "rot13").encode("latin1")
    except Exception:
        pass
    for label, fn in (
        ("b64", lambda d: base64.b64decode(d + b"=" * (-len(d) % 4))),
        ("b32", lambda d: base64.b32decode(d.upper() + b"=" * (-len(d) % 8))),
        ("b85", base64.b85decode),
        ("hex", binascii.unhexlify),
        ("zlib", zlib.decompress),
        ("gzip", gzip.decompress),
    ):
        try:
            yield label, fn(data)
        except Exception:
            pass


def scan(path: str, pattern: str):
    pat = re.compile(pattern.encode())
    with open(path, "rb") as fh:
        data = fh.read()
    seen = set()
    for label, blob in candidates(data):
        for m in pat.finditer(blob):
            key = m.group()
            if key in seen:
                continue
            seen.add(key)
            print(f"{path}\t{label}\t{key.decode('latin1')}")


def walk(root: str, pattern: str):
    if os.path.isfile(root):
        scan(root, pattern)
        return
    for dirpath, _, names in os.walk(root):
        for n in names:
            try:
                scan(os.path.join(dirpath, n), pattern)
            except Exception:
                pass


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    pattern = sys.argv[2] if len(sys.argv) > 2 else DEFAULT
    walk(target, pattern)
```

---

## 6. Before you submit

```sh
# see exactly what you have, byte for byte
printf '%s' "$FLAG" | xxd
```
Checklist:
- [ ] No trailing newline or space (`xxd` will show `0a` / `20`)
- [ ] Correct case (some scoreboards are case-sensitive)
- [ ] `1` vs `l` vs `I`, `0` vs `O`, `5` vs `S` - re-read from the source, not from a screenshot
- [ ] Correct wrapper: if the challenge gave you `s3cr3t_p455`, submit `flag{s3cr3t_p455}`
- [ ] No smart quotes or non-ASCII introduced by copy-paste
- [ ] Not URL-encoded (`%7B` should be `{`)
- [ ] Not truncated by your terminal width
- [ ] Underscores not converted to spaces

If it is rejected, `ctfbrain search stuck` section 2.
