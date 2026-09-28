---
title: "Single-Byte XOR and XOR with Known Plaintext"
category: crypto
subcategory: xor
type: technique
tags: [xor, single-byte-xor, brute-force, chi-squared, frequency-analysis, known-plaintext, crib, flag-format, magic-bytes, file-header, png, zip, pdf, elf, gzip, cyberchef, xortool, cryptopals, key-recovery]
difficulty: trivial
summary: "256 keys is nothing: brute-force single-byte XOR with an English score, or skip scoring entirely when you know any stretch of plaintext - key = ciphertext xor plaintext."
when_to_use:
  - "A hex/base64 blob decodes to bytes in a narrow range, or one byte dominates"
  - "You know the file type of the encrypted data (PNG, ZIP, PDF, ELF, gzip)"
  - "You know the plaintext starts with `flag{`, `CTF{`, `{\"`, `HTTP/`, or a username"
  - "One line out of many in a file has been xored with a single byte"
  - "A key is short and you already recovered part of the plaintext"
tools: [xortool, cyberchef, python, xxd]
source:
  name: "Cryptopals Set 1"
  url: "https://cryptopals.com/sets/1"
related: [xor-repeating-key, aes-ctr-nonce-reuse, stream-rc4-attacks]
---

## TL;DR

XOR is its own inverse, so `key = ciphertext xor plaintext` for any stretch of
plaintext you know. If you know none, there are only 256 single-byte keys - try them
all and score the output against English. If the plaintext is a file, its magic bytes
are free known plaintext and give you the first few key bytes immediately.

## Recognise it

- A hex string whose bytes all sit in a narrow range (e.g. `0x30-0x7f` xored by one
  value stays in a 96-wide window).
- A histogram with one byte far more frequent than the rest: that byte is
  `0x20 xor key` (the space) or `0x00 xor key` (padding).
- The challenge is named `xor`, `single byte`, `cipher`, or gives you 60 hex lines and
  says "one of these has been encrypted".
- `file` says "data" but the size and structure smell like a PNG or a ZIP.
- The first 4 bytes repeat in a pattern matching a known header xored with something.

## Theory

**Brute force with scoring.** For each `k` in `0..255`, compute `P = C xor k` and
score it. Two cheap, effective scores:

- *Chi-squared against English frequencies.* Count letters, compare to the expected
  distribution, sum `(O-E)^2/E`. Lowest wins.
- *Printability + space ratio.* Reject anything containing control bytes; prefer the
  candidate with a space frequency near 15-20%.

Chi-squared alone misfires on very short inputs; combine with a hard printability
filter and it is almost never wrong on 20+ bytes.

**Most-frequent-byte shortcut.** In English, the most common byte is the space
`0x20`. So `k = argmax_b count(b) xor 0x20` is a one-line guess that works surprisingly
often. In binary data the most common byte is usually `0x00`, so `k = argmax_b count(b)`.

**Known plaintext.** If `P[i..j]` is known then `K[i..j] = C[i..j] xor P[i..j]`
exactly. For a single-byte key, any one known byte is enough. For a repeating key of
length `n`, a known run of `n` consecutive bytes is enough - and a file header usually
provides it.

Useful headers:

| format | magic (hex) |
|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` then `00 00 00 0D 49 48 44 52` |
| ZIP | `50 4B 03 04` |
| PDF | `25 50 44 46 2D` (`%PDF-`) |
| GZIP | `1F 8B 08` |
| ELF | `7F 45 4C 46` |
| JPEG | `FF D8 FF E0` then `00 10 4A 46 49 46` |
| GIF | `47 49 46 38 39 61` |
| BMP | `42 4D` |
| RIFF/WAV | `52 49 46 46` ... `57 41 56 45` |
| Class | `CA FE BA BE` |

**Flag cribs.** `flag{`, `CTF{`, `HTB{`, `picoCTF{`, `{"`, `-----BEGIN `. Drag them
across the ciphertext; the offset that yields a plausible repeating key is the answer.

## Attack

1. Decode the blob from hex/base64.
2. Try the one-liner: `key = most_common_byte xor 0x20`, decrypt, look at it.
3. If that fails, brute-force all 256 with chi-squared and print the top 5.
4. If the plaintext is binary, identify the type from context (file size, challenge
   name, surrounding files) and xor the expected magic against the ciphertext head.
   The result repeated is your key; if the derived bytes are not periodic, the key is
   longer than the header or your guess of the type is wrong.
5. If you only know a word but not where it is, crib-drag it.

## Code

```python
#!/usr/bin/env python3
"""Single-byte XOR brute force, detection among many candidates, and key recovery
from known plaintext or a file magic header.

Self-test builds every case locally and asserts exact key recovery.
"""

import os
import secrets
from collections import Counter
from itertools import cycle

ENGLISH_FREQ = {
    " ": 18.00, "e": 10.23, "t": 7.51, "a": 6.54, "o": 6.31, "n": 5.71, "i": 5.67,
    "s": 5.32, "r": 5.06, "h": 4.90, "l": 3.38, "d": 3.29, "u": 2.30, "c": 2.25,
    "m": 2.06, "f": 1.83, "w": 1.72, "y": 1.66, "g": 1.63, "p": 1.57, "b": 1.25,
    "v": 0.80, "k": 0.59, "x": 0.14, "q": 0.09, "j": 0.09, "z": 0.05,
}

MAGIC = {
    "png": bytes.fromhex("89504E470D0A1A0A0000000D49484452"),
    "zip": bytes.fromhex("504B0304"),
    "pdf": b"%PDF-",
    "gzip": bytes.fromhex("1F8B08"),
    "elf": bytes.fromhex("7F454C46"),
    "jpeg": bytes.fromhex("FFD8FFE000104A464946"),
    "gif": b"GIF89a",
    "class": bytes.fromhex("CAFEBABE"),
}

FLAG_CRIBS = [b"flag{", b"FLAG{", b"CTF{", b"HTB{", b"picoCTF{", b"-----BEGIN "]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, cycle(key)))


# ----------------------------------------------------------------- scoring
def score_english(data: bytes) -> float:
    """Chi-squared distance to English. Lower is better, inf for obvious junk."""
    if not data:
        return float("inf")
    if any(b < 9 or (13 < b < 32) or b > 126 for b in data):
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
        exp = letters * pct / 100.0
        chi += (counts.get(c, 0) - exp) ** 2 / exp
    return chi


def single_byte_xor_bruteforce(data: bytes, top: int = 5
                               ) -> list[tuple[float, int, bytes]]:
    """All 256 keys, ranked. Returns (score, key, plaintext) best first."""
    out = []
    for k in range(256):
        pt = bytes(b ^ k for b in data)
        out.append((score_english(pt), k, pt))
    out.sort(key=lambda r: r[0])
    return out[:top]


def guess_key_by_frequency(data: bytes, expected: int = 0x20) -> int:
    """One-liner: the most common ciphertext byte is probably `expected` xored."""
    return Counter(data).most_common(1)[0][0] ^ expected


def detect_single_byte_xor(buffers: list[bytes]) -> tuple[int, int, bytes]:
    """Which buffer out of many is single-byte-xored English? -> (index, key, pt)."""
    best = (float("inf"), -1, 0, b"")
    for i, buf in enumerate(buffers):
        score, key, pt = single_byte_xor_bruteforce(buf, top=1)[0]
        if score < best[0]:
            best = (score, i, key, pt)
    return best[1], best[2], best[3]


# ------------------------------------------------------- known plaintext
def key_from_known_plaintext(ct: bytes, pt: bytes, offset: int = 0) -> bytes:
    """key = ciphertext xor plaintext. Exact, no guessing."""
    return xor_bytes(ct[offset:offset + len(pt)], pt)


def key_from_magic(ct: bytes, fmt: str) -> bytes:
    """Recover key bytes from a known file header."""
    magic = MAGIC[fmt]
    return key_from_known_plaintext(ct, magic)


def reduce_period(key: bytes) -> bytes:
    for d in range(1, len(key)):
        if len(key) % d == 0 and key == key[:d] * (len(key) // d):
            return key[:d]
    return key


def crib_drag(ct: bytes, crib: bytes):
    """Slide a crib over the ciphertext; yield (offset, key fragment at that offset)."""
    for off in range(len(ct) - len(crib) + 1):
        yield off, xor_bytes(ct[off:off + len(crib)], crib)


def find_keys_by_crib(ct: bytes, crib: bytes, keylen: int) -> list[bytes]:
    """Every repeating key of length `keylen` consistent with `crib` somewhere in ct.

    At offset `off`, fragment byte i belongs to key position (off + i) % keylen, so a
    crib at least one key length long pins the whole key -- and the rest of the
    fragment then has to agree, which throws out most wrong offsets.
    """
    assert len(crib) >= keylen, "crib must be at least one key length long"
    out = []
    for off, frag in crib_drag(ct, crib):
        cand = bytes(frag[(j - off) % keylen] for j in range(keylen))
        if all(frag[i] == cand[(off + i) % keylen] for i in range(len(frag))):
            if cand not in out:
                out.append(cand)
    return out


def best_key_by_crib(ct: bytes, crib: bytes, keylen: int) -> bytes | None:
    """Pick the crib candidate whose full decryption looks most like text."""
    cands = find_keys_by_crib(ct, crib, keylen)
    scored = [(score_english(repeating_key_xor(ct, k)), k) for k in cands]
    scored = [s for s in scored if s[0] != float("inf")] or scored
    return min(scored)[1] if scored else None


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    MSG = (b"Cooking MC's like a pound of bacon, and the flag is "
           b"flag{single_byte_xor_has_only_256_keys}.")

    # --- 1. brute force ----------------------------------------------------
    key = 0x5B
    ct = bytes(b ^ key for b in MSG)
    ranked = single_byte_xor_bruteforce(ct)
    print("[+] top candidate:", ranked[0][1], ranked[0][2][:40])
    assert ranked[0][1] == key, ranked[0][1]
    assert ranked[0][2] == MSG
    print("[+] PASS single-byte brute force")

    # --- 2. the frequency one-liner ---------------------------------------
    assert guess_key_by_frequency(ct) == key
    print("[+] PASS most-frequent-byte shortcut")

    # --- 3. detect the xored line among decoys -----------------------------
    decoys = [os.urandom(len(MSG)) for _ in range(60)]
    haystack = decoys[:23] + [ct] + decoys[23:]
    idx, k, pt = detect_single_byte_xor(haystack)
    assert idx == 23 and k == key and pt == MSG, (idx, k)
    print(f"[+] PASS detection: line {idx} of {len(haystack)}, key 0x{k:02x}")

    # --- 4. known plaintext with a multi-byte key --------------------------
    real_key = b"SUPERSECRET"
    ct2 = repeating_key_xor(MSG, real_key)
    got = reduce_period(key_from_known_plaintext(ct2, MSG[:22]))
    assert got == real_key, got
    print("[+] PASS key from known plaintext:", got)

    # --- 5. file magic bytes -----------------------------------------------
    png = MAGIC["png"] + os.urandom(512)
    file_key = secrets.token_bytes(8)
    enc = repeating_key_xor(png, file_key)
    recovered = reduce_period(key_from_magic(enc, "png"))
    assert recovered == reduce_period(file_key), (recovered.hex(), file_key.hex())
    assert repeating_key_xor(enc, recovered) == png
    print("[+] PASS key from PNG magic:", recovered.hex())

    for fmt in ("zip", "pdf", "gzip", "elf", "gif", "class"):
        blob = MAGIC[fmt] + os.urandom(200)
        k4 = secrets.token_bytes(len(MAGIC[fmt]))
        e = repeating_key_xor(blob, k4)
        assert reduce_period(key_from_magic(e, fmt)) == reduce_period(k4)
    print("[+] PASS key recovery from zip/pdf/gzip/elf/gif/class headers")

    # --- 6. crib at an unknown offset --------------------------------------
    short_key = b"k3y!"
    body = b"nothing to see here, move along. " + b"flag{crib_dragging_works}" + b" bye"
    ct3 = repeating_key_xor(body, short_key)
    cands = find_keys_by_crib(ct3, b"flag{crib", len(short_key))
    print(f"[+] {len(cands)} candidate keys from the crib")
    assert short_key in cands, cands
    found = best_key_by_crib(ct3, b"flag{crib", len(short_key))
    assert found == short_key, found
    assert repeating_key_xor(ct3, found) == body
    print("[+] PASS crib-dragged key:", found)

    # --- 7. all the standard flag cribs -------------------------------------
    for crib in FLAG_CRIBS:
        probe = repeating_key_xor(b"nothing here at all " + crib
                                  + b"payload_payload_payload", short_key)
        assert short_key in find_keys_by_crib(probe, crib, len(short_key)), crib
    print("[+] PASS every standard flag crib recovers the key")

    print("\nall checks passed")
```

## Variants & pitfalls

- **Key byte `0x00`.** The "ciphertext" is the plaintext. Always look at the raw bytes
  first; people miss this.
- **Short ciphertexts.** Below ~10 bytes, chi-squared is meaningless. Print all 256
  candidates and read them.
- **Non-English plaintext.** Replace the frequency table, or score by "fraction of
  bytes in the expected alphabet" (base64, hex, JSON).
- **The magic bytes trick fails when the key is longer than the header.** PNG gives 16
  known bytes (signature plus the IHDR length and type), ZIP only 4. Chain more known
  structure: a PNG always has `IHDR` at offset 12 and `IEND` at the end; a ZIP has
  `PK\x05\x06` for the end-of-central-directory record.
- **Trailing key bytes.** If you recover a key of length `2n` that is `k || k`, reduce
  it. `reduce_period` above does this.
- **Multiple candidates from crib dragging.** Filter by "does the rest of the
  plaintext look sane". A wrong offset gives a key that decrypts the crib region
  correctly and garbage everywhere else.
- **XOR with a rotating or position-dependent key** (`c[i] = p[i] ^ key ^ i`) is
  common in easy reversing challenges. Check by looking at whether the derived key
  from known plaintext is constant, incrementing, or following a simple recurrence.
- **Base64 first.** Many challenges base64 the xored bytes. Decode before doing
  anything else, or your statistics run on base64's 64-symbol alphabet.

## Tools

- `xortool -c 20 -b <file>` - brute-force key lengths and key bytes.
- CyberChef - "XOR Brute Force" shows all 256 decryptions at once.
- `xxd -l 64 file` - eyeball the first bytes for a recognisable header pattern.
- `binwalk` on the recovered plaintext to confirm the file type.

## References

- Cryptopals Set 1, challenges 3 (single-byte XOR cipher) and 4 (detect single-character
  XOR): <https://cryptopals.com/sets/1>
