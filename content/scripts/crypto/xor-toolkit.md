---
title: "XOR Toolkit - Single-Byte Brute Force, Keylength Detection, Crib Dragging, Many-Time Pad"
category: crypto
subcategory: xor
type: script
tags: [xor, toolkit, single-byte-xor, repeating-key-xor, vigenere, many-time-pad, crib-dragging, hamming-distance, index-of-coincidence, chi-squared, frequency-analysis, keylength, known-plaintext, magic-bytes, xortool, cryptopals, stdlib]
summary: "Stdlib-only module: chi-squared single-byte XOR solver, Hamming/IoC key-length detection, repeating-key recovery, crib dragging and a many-time-pad keystream solver."
tools: [xortool, cyberchef]
related: [xor-repeating-key, xor-known-plaintext, aes-ctr-nonce-reuse, aes-toolkit]
---

## Usage

No dependencies beyond the standard library. Save as `xor_toolkit.py` and run it to
execute the self-test, which generates its own ciphertexts and asserts exact recovery:

```sh
python3 xor_toolkit.py
```

Typical session against a challenge file:

```text
from xor_toolkit import *

data = bytes.fromhex(open("cipher.hex").read().strip())      # or base64.b64decode

# 1. is it a single byte?
for score, key, pt in single_byte_xor_bruteforce(data)[:3]:
    print(hex(key), pt[:60])

# 2. otherwise find the key length, then the key
print(guess_keysizes_hamming(data))
print(guess_keysizes_ioc(data))
key, plaintext = break_repeating_key_xor(data)
print(key, plaintext[:200])

# 3. known plaintext or a file header
print(reduce_period(xor_bytes(data[:16], PNG_MAGIC)))

# 4. many ciphertexts, one keystream
ks = solve_many_time_pad([ct1, ct2, ct3, ct4, ct5, ct6, ct7, ct8])
print(xor_bytes(ct1, ks))
```

## What it does

| function | purpose |
|---|---|
| `xor_bytes(a, b)` / `repeating_key_xor(data, key)` | the two primitives |
| `score_english(data)` | chi-squared distance to English, `inf` for junk |
| `single_byte_xor_bruteforce(data)` | all 256 keys, ranked best first |
| `detect_single_byte_xor(buffers)` | which of many buffers is the xored one |
| `guess_key_by_frequency(data)` | one-liner: most common byte xor `0x20` |
| `hamming_distance(a, b)` | bit-level distance |
| `guess_keysizes_hamming(data)` | key lengths ranked by normalised distance |
| `index_of_coincidence(data)` / `guess_keysizes_ioc` | the more robust detector |
| `guess_keysize(data)` | the smallest key length whose columns look English |
| `reduce_period(key)` | collapse `abcabc` to `abc` |
| `break_repeating_key_xor(data)` | `(key, plaintext)` end to end |
| `crib_drag(ct, crib)` / `find_keys_by_crib` | key from a guessed word at unknown offset |
| `solve_many_time_pad(cts)` | shared keystream from several ciphertexts |

## Code

```python
#!/usr/bin/env python3
"""xor_toolkit -- everything you need for xor-based CTF crypto. Stdlib only.

Run this file to self-test: it builds its own ciphertexts and asserts exact recovery
of single-byte keys, repeating keys, keys from cribs, and many-time-pad keystreams.
"""

from __future__ import annotations

import math
import os
import secrets
from collections import Counter
from itertools import cycle

# Relative frequency of each character in English prose, including the space.
ENGLISH_FREQ = {
    " ": 18.00, "e": 10.23, "t": 7.51, "a": 6.54, "o": 6.31, "n": 5.71, "i": 5.67,
    "s": 5.32, "r": 5.06, "h": 4.90, "l": 3.38, "d": 3.29, "u": 2.30, "c": 2.25,
    "m": 2.06, "f": 1.83, "w": 1.72, "y": 1.66, "g": 1.63, "p": 1.57, "b": 1.25,
    "v": 0.80, "k": 0.59, "x": 0.14, "q": 0.09, "j": 0.09, "z": 0.05,
}

PNG_MAGIC = bytes.fromhex("89504E470D0A1A0A0000000D49484452")
ZIP_MAGIC = bytes.fromhex("504B0304")
PDF_MAGIC = b"%PDF-"
GZIP_MAGIC = bytes.fromhex("1F8B08")
ELF_MAGIC = bytes.fromhex("7F454C46")
GIF_MAGIC = b"GIF89a"
FLAG_CRIBS = [b"flag{", b"FLAG{", b"CTF{", b"HTB{", b"picoCTF{", b"-----BEGIN "]


# ================================================================ primitives
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Byte-wise xor, truncated to the shorter input."""
    return bytes(x ^ y for x, y in zip(a, b))


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    """Encrypt/decrypt with a repeating key. Its own inverse."""
    return bytes(d ^ k for d, k in zip(data, cycle(key)))


# =================================================================== scoring
def score_english(data: bytes) -> float:
    """Chi-squared distance to English. Lower is better; inf for obvious junk."""
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
        expected = letters * pct / 100.0
        chi += (counts.get(c, 0) - expected) ** 2 / expected
    return chi


# Log-likelihood per character: the right statistic for columns of 8-20 bytes, where
# chi-squared is far too noisy.
_LOGP: dict[int, float] = {}
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


# ========================================================= single-byte xor
def single_byte_xor_bruteforce(data: bytes, top: int | None = None
                               ) -> list[tuple[float, int, bytes]]:
    """All 256 keys ranked. Returns (score, key_byte, plaintext), best first."""
    out = [(score_english(bytes(b ^ k for b in data)), k,
            bytes(b ^ k for b in data)) for k in range(256)]
    out.sort(key=lambda r: r[0])
    return out if top is None else out[:top]


def guess_key_by_frequency(data: bytes, expected: int = 0x20) -> int:
    """The most common ciphertext byte is usually a space (or a NUL in binary)."""
    return Counter(data).most_common(1)[0][0] ^ expected


def detect_single_byte_xor(buffers: list[bytes]) -> tuple[int, int, bytes]:
    """Which buffer out of many is single-byte-xored English? -> (index, key, pt)."""
    best = (float("inf"), -1, 0, b"")
    for i, buf in enumerate(buffers):
        score, key, pt = single_byte_xor_bruteforce(buf, top=1)[0]
        if score < best[0]:
            best = (score, i, key, pt)
    return best[1], best[2], best[3]


# ======================================================= key-length detection
def hamming_distance(a: bytes, b: bytes) -> int:
    """Number of differing bits between two equal-length buffers."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keysizes_hamming(data: bytes, lo: int = 2, hi: int = 40,
                           top: int = 5) -> list[tuple[float, int]]:
    """Rank key lengths by normalised Hamming distance. Lower is better.

    English-vs-English gives ~2.5-3.0 bits per byte; random gives ~4.0.
    """
    scores = []
    for n in range(lo, min(hi, max(lo, len(data) // 4)) + 1):
        chunks = [data[i * n:(i + 1) * n] for i in range(len(data) // n)]
        pairs = [(chunks[i], chunks[i + 1]) for i in range(min(len(chunks) - 1, 20))]
        if not pairs:
            continue
        scores.append((sum(hamming_distance(x, y) for x, y in pairs)
                       / (len(pairs) * n), n))
    return sorted(scores)[:top]


def index_of_coincidence(data: bytes) -> float:
    """~0.065 for English text, ~0.0039 for uniform random bytes."""
    n = len(data)
    if n < 2:
        return 0.0
    counts = Counter(data)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def guess_keysizes_ioc(data: bytes, lo: int = 2, hi: int = 40,
                       top: int = 5) -> list[tuple[float, int]]:
    """Rank key lengths by the average IoC of their columns. Higher is better."""
    scores = [(sum(index_of_coincidence(data[j::n]) for j in range(n)) / n, n)
              for n in range(lo, min(hi, max(lo, len(data) // 4)) + 1)]
    return sorted(scores, reverse=True)[:top]


def guess_keysize(data: bytes, lo: int = 2, hi: int = 40,
                  ioc_threshold: float = 0.055) -> int | None:
    """Smallest key length whose columns have an English-like IoC.

    Multiples of the true length also pass, so scanning upwards and returning the
    FIRST hit gives the true length instead of a multiple.
    """
    for n in range(lo, min(hi, max(lo, len(data) // 4)) + 1):
        if sum(index_of_coincidence(data[j::n]) for j in range(n)) / n >= ioc_threshold:
            return n
    return None


# ============================================================ repeating key
def reduce_period(key: bytes) -> bytes:
    """Collapse `abcabcabc` to `abc`."""
    n = len(key)
    for d in range(1, n):
        if n % d == 0 and key == key[:d] * (n // d):
            return key[:d]
    return key


def break_repeating_key_xor(data: bytes, keysizes: list[int] | None = None,
                            tolerance: float = 1.3) -> tuple[bytes, bytes]:
    """Recover (key, plaintext) from repeating-key xor ciphertext."""
    if keysizes is None:
        n = guess_keysize(data)
        if n is not None:
            keysizes = [n]
        else:
            cand = {m for _, m in guess_keysizes_hamming(data, top=6)}
            cand |= {m for _, m in guess_keysizes_ioc(data, top=6)}
            keysizes = sorted(cand)
    results = []
    for n in sorted(keysizes):
        key = reduce_period(bytes(single_byte_xor_bruteforce(data[j::n], top=1)[0][1]
                                  for j in range(n)))
        pt = repeating_key_xor(data, key)
        results.append((score_english(pt), len(key), key, pt))
    finite = [r for r in results if r[0] != float("inf")] or results
    best = min(r[0] for r in finite)
    for score, _n, key, pt in sorted(finite, key=lambda r: r[1]):
        if score <= best * tolerance:
            return key, pt
    return finite[0][2], finite[0][3]


# =============================================================== crib dragging
def crib_drag(data: bytes, crib: bytes):
    """Slide `crib` along `data`; yields (offset, data xor crib at that offset).

    Against `C1 xor C2` the yielded bytes are the OTHER plaintext.
    Against a ciphertext they are key material.
    """
    for off in range(len(data) - len(crib) + 1):
        yield off, xor_bytes(data[off:off + len(crib)], crib)


def find_keys_by_crib(ct: bytes, crib: bytes, keylen: int) -> list[bytes]:
    """Every repeating key of length `keylen` consistent with `crib` somewhere."""
    if len(crib) < keylen:
        raise ValueError("crib must be at least one key length long")
    out: list[bytes] = []
    for off, frag in crib_drag(ct, crib):
        cand = bytes(frag[(j - off) % keylen] for j in range(keylen))
        if all(frag[i] == cand[(off + i) % keylen] for i in range(len(frag))):
            if cand not in out:
                out.append(cand)
    return out


def best_key_by_crib(ct: bytes, crib: bytes, keylen: int) -> bytes | None:
    """The crib candidate whose full decryption looks most like English."""
    cands = find_keys_by_crib(ct, crib, keylen)
    if not cands:
        return None
    scored = [(score_english(repeating_key_xor(ct, k)), k) for k in cands]
    usable = [s for s in scored if s[0] != float("inf")] or scored
    return min(usable)[1]


# ============================================================ many-time pad
def is_letter(b: int) -> bool:
    return 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def space_statistic(cts: list[bytes]) -> bytes:
    """Cheap keystream guess: `letter xor 0x20` is a letter with flipped case, so the
    ciphertext that xors to a letter against most others is holding a space."""
    longest = max(len(c) for c in cts)
    ks = bytearray(longest)
    for pos in range(longest):
        present = [i for i, c in enumerate(cts) if len(c) > pos]
        best, best_votes = None, -1
        for i in present:
            votes = sum(1 for j in present
                        if j != i and (is_letter(cts[i][pos] ^ cts[j][pos])
                                       or cts[i][pos] == cts[j][pos]))
            if votes > best_votes:
                best, best_votes = i, votes
        if best is not None:
            ks[pos] = cts[best][pos] ^ 0x20
    return bytes(ks)


def solve_many_time_pad(cts: list[bytes]) -> bytes:
    """Recover the shared keystream. Each column is a single-byte-xor problem across
    messages; score all 256 candidates with the English character model."""
    longest = max(len(c) for c in cts)
    ks = bytearray(longest)
    for pos in range(longest):
        column = bytes(c[pos] for c in cts if len(c) > pos)
        best, best_score = 0, float("-inf")
        for k in range(256):
            s = score_column(bytes(b ^ k for b in column))
            if s > best_score:
                best, best_score = k, s
        ks[pos] = best
    return bytes(ks)


# ================================================================= self-test
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
    b"flag{xor_is_not_encryption_it_is_a_transformation}. "
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
    b"the flag is flag{many_time_pad_is_no_pad_at_all} and nothing more",
    b"repeating key xor is a vigenere cipher over the whole byte range",
    b"transposing the ciphertext turns one hard problem into easy ones",
    b"one time pads are only unbreakable when used exactly one time each",
    b"the space character is the single strongest statistical signal so",
    b"column scoring beats chi squared badly on very short byte samples",
    b"do not roll your own crypto unless you are doing it for a puzzle",
    b"every additional ciphertext makes the statistics noticeably better",
    b"an attacker with ten messages recovers nearly the whole keystream",
]

if __name__ == "__main__":
    print("== single-byte xor ==")
    k = 0x5B
    ct = bytes(b ^ k for b in PLAIN)
    score, key, pt = single_byte_xor_bruteforce(ct, top=1)[0]
    assert key == k and pt == PLAIN, hex(key)
    assert guess_key_by_frequency(ct) == k
    print(f"[+] PASS brute force and frequency shortcut both found 0x{k:02x}")

    decoys = [os.urandom(len(PLAIN)) for _ in range(60)]
    haystack = decoys[:17] + [ct] + decoys[17:]
    idx, found_key, found_pt = detect_single_byte_xor(haystack)
    assert (idx, found_key, found_pt) == (17, k, PLAIN)
    print(f"[+] PASS found the xored line at index {idx} of {len(haystack)}")

    print("\n== repeating-key xor ==")
    real_key = bytes(secrets.choice(b"abcdefghijklmnopqrstuvwxyz_") for _ in range(9))
    ct = repeating_key_xor(PLAIN, real_key)
    print("[+] hamming:", [(round(s, 3), n) for s, n in guess_keysizes_hamming(ct)])
    print("[+] ioc    :", [(round(s, 4), n) for s, n in guess_keysizes_ioc(ct)])
    assert guess_keysize(ct) == len(real_key), guess_keysize(ct)
    got_key, got_pt = break_repeating_key_xor(ct)
    assert got_key == real_key and got_pt == PLAIN, got_key
    print(f"[+] PASS recovered {got_key!r} and the exact plaintext")
    assert break_repeating_key_xor(ct, keysizes=[len(real_key)])[0] == real_key
    print("[+] PASS solve with a known key length")

    print("\n== known plaintext and file magic ==")
    assert reduce_period(xor_bytes(ct[:36], PLAIN[:36])) == real_key
    png = PNG_MAGIC + os.urandom(400)
    fk = secrets.token_bytes(8)
    assert reduce_period(xor_bytes(repeating_key_xor(png, fk)[:16], PNG_MAGIC)) \
        == reduce_period(fk)
    for magic in (ZIP_MAGIC, PDF_MAGIC, GZIP_MAGIC, ELF_MAGIC, GIF_MAGIC):
        blob = magic + os.urandom(100)
        mk = secrets.token_bytes(len(magic))
        enc = repeating_key_xor(blob, mk)
        assert reduce_period(xor_bytes(enc[:len(magic)], magic)) == reduce_period(mk)
    print("[+] PASS key recovered from known plaintext and 6 file headers")

    print("\n== crib dragging ==")
    short_key = b"k3y!"
    body = b"nothing to see here, move along. flag{crib_dragging_works} bye now"
    ct3 = repeating_key_xor(body, short_key)
    cands = find_keys_by_crib(ct3, b"flag{crib", len(short_key))
    assert short_key in cands, cands
    assert best_key_by_crib(ct3, b"flag{crib", len(short_key)) == short_key
    print(f"[+] PASS {len(cands)} candidate(s), best is {short_key!r}")
    for crib in FLAG_CRIBS:
        probe = repeating_key_xor(b"nothing here at all " + crib
                                  + b"payload_payload_payload", short_key)
        assert short_key in find_keys_by_crib(probe, crib, len(short_key)), crib
    print("[+] PASS every standard flag crib recovers the key")

    print("\n== many-time pad ==")
    ks = os.urandom(max(len(m) for m in MANY))
    cts = [xor_bytes(m, ks[:len(m)]) for m in MANY]
    common = min(len(m) for m in MANY)

    cheap = space_statistic(cts)
    cheap_acc = sum(1 for i in range(common) if cheap[i] == ks[i]) / common
    print(f"[+] space heuristic accuracy : {cheap_acc:.0%}")

    guess = solve_many_time_pad(cts)
    acc = sum(1 for i in range(common) if guess[i] == ks[i]) / common
    print(f"[+] column scoring accuracy  : {acc:.0%}")
    assert acc >= 0.90, acc
    recovered = xor_bytes(cts[9], guess[:len(cts[9])])
    print("[+] recovered:", recovered)
    assert b"flag{many_time_pad_is_no_pad_at_all}" in recovered
    print("[+] PASS many-time-pad keystream recovery")

    print("\n== crib dragging on C1 xor C2 ==")
    hits = [(o, c) for o, c in crib_drag(xor_bytes(cts[0], cts[1]), b"cryptography")
            if score_english(c) != float("inf")]
    assert any(c == b"the quick br" for _, c in hits), hits[:5]
    print("[+] PASS crib drag over two ciphertexts:", hits[0])

    print("\nall checks passed")
```

## Notes

- **Order of attack.** Try single-byte first (256 candidates, free), then key-length
  detection, then cribs. Do not start with `xortool` unless the plaintext is English
  or the most common byte really is `0x20`.
- **`guess_keysize` beats scoring alone.** Multiples of the true key length always fit
  at least as well, so the smallest length whose columns look like English is the
  right answer. That is why it scans upwards and returns the first hit.
- **`score_english` returns `inf`** for anything with control bytes or fewer than 60%
  letters. That hard filter does most of the work; the chi-squared value only breaks
  ties. Swap the frequency table for another language or another format (JSON, base64)
  when the plaintext is not English.
- **`score_column` is the right statistic for many-time pads**, where each column has
  only as many samples as you have ciphertexts. Chi-squared on 10 bytes is noise.
- **Crib dragging returns several candidates.** `best_key_by_crib` picks by full-text
  score; check the output by eye before trusting it.
- **Non-English plaintext.** For a base64 payload, replace the score with "fraction of
  bytes inside the base64 alphabet"; for JSON, weight `"`, `:`, `,` and `{`.
- **Binary plaintext.** Use `guess_key_by_frequency(data, expected=0x00)` - long runs
  of NUL are the equivalent of English spaces.
- See `xor-repeating-key` and `xor-known-plaintext` for the theory, and `aes-toolkit`
  for the block-cipher side.
