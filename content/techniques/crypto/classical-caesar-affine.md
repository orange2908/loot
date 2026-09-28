---
title: "Caesar / ROT-n / Affine - Full Keyspace Brute Force with Scoring"
category: crypto
subcategory: classical
type: technique
tags: [caesar, rot13, rot-n, rotn, shift-cipher, affine, atbash, caesar-brute-force, keyspace-brute-force, chi-squared, quadgram, frequency-analysis, modular-inverse, cyberchef, dcode, classical-cipher]
difficulty: trivial
summary: "Shift and affine ciphers have <=312 keys; enumerate all of them and rank plaintext candidates with a chi-squared or quadgram score."
when_to_use:
  - "Ciphertext is pure A-Z (or a-z) and roughly English-length-distributed"
  - "Index of coincidence is near 0.066 (English) but the text is unreadable"
  - "Flag format is known (e.g. `flag{`) so you can filter candidates by substring"
  - "Letter frequency histogram of the ciphertext is a rotated copy of English's"
tools: [python, cyberchef, dcode, quipqiup]
related: [classical-substitution-hillclimb, classical-vigenere, cipher-identification]
---

## TL;DR

Caesar is `c = p + k mod 26` (26 keys, one of which is identity). Affine is
`c = a*p + b mod 26` with `gcd(a,26)==1`, so 12 * 26 = 312 keys. Both keyspaces are
trivially enumerable. The only real work is **automatically picking the right
candidate**, which you do with a chi-squared letter-frequency fit or an English
quadgram log-probability score.

## Recognise it

- Charset is exactly the 26 Latin letters, punctuation and spacing preserved.
- Index of coincidence (IoC) ~= 0.066 - monoalphabetic, so *not* Vigenere.
- The frequency histogram looks like English's but cyclically shifted: the tallest
  bar is 4 positions right of `E` for ROT4, etc.
- ROT13 specifically: `synt{` is `flag{`, `Gur` is `The`, `PGS` is `CTF`.
- Affine but not Caesar: histogram is a *permutation* of English's that is not a
  rotation, yet the cipher is still an arithmetic progression of letters
  (`A -> b`, `B -> a+b`, `C -> 2a+b`, ... constant difference `a`).
- Atbash is the special affine case `a = 25, b = 25` (i.e. `c = 25 - p`).

## Theory

Encode `A..Z` as `0..25`.

- **Caesar / ROT-n**: `E(p) = p + k (mod 26)`, `D(c) = c - k (mod 26)`.
- **Affine**: `E(p) = a*p + b (mod 26)`. Decryption needs `a^-1 mod 26`, which exists
  only when `gcd(a, 26) == 1`, i.e. `a` in `{1,3,5,7,9,11,15,17,19,21,23,25}` (12 values).
  `D(c) = a^-1 * (c - b) (mod 26)`.
- **Atbash**: `a = -1 = 25`, `b = -1 = 25`.
- **ROT47**: not mod 26 at all - it rotates the 94 printable ASCII characters
  `!` (33) through `~` (126) by 47: `c = 33 + ((p - 33 + 47) mod 94)`. Self-inverse.

**Chi-squared scoring.** For candidate text with observed letter counts $O_i$ and
English expected frequencies $f_i$ over $N$ letters, $E_i = N f_i$ and

$$\chi^2 = \sum_{i=0}^{25} \frac{(O_i - E_i)^2}{E_i}$$

Lower is better. It is cheap and perfect for Caesar/affine because those ciphers
permute the whole alphabet uniformly, so single-letter statistics fully determine
the key.

**Quadgram scoring.** Sum of $\log_{10} P(\text{quadgram})$ over all overlapping
4-grams. Higher (less negative) is better. Needed once word boundaries are gone or
the text is short (< 40 letters), and it is what drives hill-climbing attacks on
full substitution.

## Attack

1. Strip to `A-Z`, remember positions of non-letters so you can restore formatting.
2. For Caesar: loop `k` in `0..25`, decrypt, score, keep the best 3.
3. For affine: loop over the 12 valid `a` and 26 `b`, decrypt, score.
4. If a flag format is known, short-circuit: print any candidate containing `flag{`,
   `ctf{`, `picoCTF`, etc. That beats any statistical score.
5. If nothing scores well, the cipher is not monoalphabetic-by-arithmetic - move on
   to keyword substitution (hill-climbing) or Vigenere.
6. Non-26 alphabets: if the ciphertext includes digits, try mod 36 (`A-Z0-9`) or
   mod 62 (`A-Za-z0-9`) shifts; CTFs love `rot` over base64 alphabets.

## Code

```python
#!/usr/bin/env python3
"""Caesar / ROT-n / Affine / Atbash / ROT47 brute force with chi-squared scoring.

Self-contained: the English frequency table is embedded. Run directly for a self-test.
"""
from __future__ import annotations

import string
from math import gcd

# English letter frequencies (percent), A..Z. Source: standard corpus counts.
ENGLISH_FREQ = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
]

ALPHA = string.ascii_uppercase
COPRIME_26 = [a for a in range(1, 26) if gcd(a, 26) == 1]


def only_letters(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPHA)


def chi_squared(text: str) -> float:
    """Lower = more English-like. Returns +inf for empty text."""
    letters = only_letters(text)
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = [0] * 26
    for ch in letters:
        counts[ord(ch) - 65] += 1
    total = 0.0
    for i in range(26):
        expected = n * ENGLISH_FREQ[i] / 100.0
        total += (counts[i] - expected) ** 2 / expected
    return total


def index_of_coincidence(text: str) -> float:
    letters = only_letters(text)
    n = len(letters)
    if n < 2:
        return 0.0
    counts = [0] * 26
    for ch in letters:
        counts[ord(ch) - 65] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def caesar(text: str, k: int) -> str:
    """Shift by k, preserving case and non-letters."""
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def affine_encrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError(f"a={a} is not invertible mod 26")
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((a * (ord(ch) - 97) + b) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((a * (ord(ch) - 65) + b) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def affine_decrypt(text: str, a: int, b: int) -> str:
    a_inv = pow(a, -1, 26)
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((a_inv * (ord(ch) - 97 - b)) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((a_inv * (ord(ch) - 65 - b)) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text: str) -> str:
    """Self-inverse: affine with a=25, b=25."""
    return affine_encrypt(text, 25, 25)


def rot47(text: str) -> str:
    """Self-inverse rotation over printable ASCII 33..126."""
    return "".join(
        chr(33 + (ord(ch) - 33 + 47) % 94) if 33 <= ord(ch) <= 126 else ch
        for ch in text
    )


def break_caesar(ct: str, top: int = 3):
    """Return [(score, shift, plaintext)] sorted best-first."""
    cands = [(chi_squared(caesar(ct, -k)), k, caesar(ct, -k)) for k in range(26)]
    cands.sort(key=lambda t: t[0])
    return cands[:top]


def break_affine(ct: str, top: int = 3):
    """Return [(score, (a, b), plaintext)] sorted best-first."""
    cands = []
    for a in COPRIME_26:
        for b in range(26):
            pt = affine_decrypt(ct, a, b)
            cands.append((chi_squared(pt), (a, b), pt))
    cands.sort(key=lambda t: t[0])
    return cands[:top]


def grep_flag(ct: str, needles=("flag{", "ctf{", "FLAG{", "CTF{")):
    """Short-circuit: any Caesar or affine decryption containing a flag marker."""
    hits = []
    for k in range(26):
        pt = caesar(ct, -k)
        if any(n.lower() in pt.lower() for n in needles):
            hits.append((f"caesar k={k}", pt))
    for a in COPRIME_26:
        for b in range(26):
            pt = affine_decrypt(ct, a, b)
            if any(n.lower() in pt.lower() for n in needles):
                hits.append((f"affine a={a} b={b}", pt))
    return hits


if __name__ == "__main__":
    plain = ("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RETURNS "
             "TO THE RIVER BANK WHERE IT RESTS")

    # --- Caesar self-test -------------------------------------------------
    ct = caesar(plain, 7)
    best = break_caesar(ct)
    assert best[0][1] == 7, best[:2]
    assert best[0][2] == plain
    print(f"[ok] caesar recovered shift={best[0][1]}  chi2={best[0][0]:.1f}")

    # --- Affine self-test -------------------------------------------------
    ct2 = affine_encrypt(plain, 5, 8)
    best2 = break_affine(ct2)
    assert best2[0][1] == (5, 8), best2[:2]
    assert best2[0][2] == plain
    print(f"[ok] affine recovered a,b={best2[0][1]}  chi2={best2[0][0]:.1f}")

    # --- Atbash / ROT47 round trips --------------------------------------
    assert atbash(atbash(plain)) == plain
    assert rot47(rot47("flag{r0t47_is_self_inverse}")) == "flag{r0t47_is_self_inverse}"
    print("[ok] atbash and rot47 are self-inverse")

    # --- Flag grep --------------------------------------------------------
    hits = grep_flag(caesar("flag{caesar_is_not_crypto}", 13))
    assert any("flag{caesar_is_not_crypto}" in h[1] for h in hits)
    print(f"[ok] flag grep found {len(hits)} candidate(s): {hits[0][0]}")

    # --- IoC sanity -------------------------------------------------------
    ioc = index_of_coincidence(plain)
    assert 0.04 < ioc < 0.09, ioc
    print(f"[ok] IoC of English sample = {ioc:.4f} (expect ~0.066)")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Keyed Caesar / ROT-n over a custom alphabet.** If the challenge shows an alphabet
  string, index into that string instead of `ord(ch)-65`. Base64/base32 alphabets are
  common ("rot13 the base64, then decode").
- **ROT5 on digits, ROT18 = ROT13+ROT5, ROT47 on all printables.** CyberChef has all
  three; a "rot13" that leaves digits untouched but the flag contains numbers usually
  wants ROT18.
- **Affine with `a` not coprime to 26** is not a cipher - it is lossy. If a challenge
  hands you `a=13`, the intended structure is something else (often mod-256 byte
  affine, where the valid `a` are the odd numbers).
- **Affine over bytes (mod 256)**: same code with 26 -> 256, 128 invertible multipliers,
  keyspace 32768. Still brute-forceable; score with printable-ASCII ratio.
- **Short ciphertexts.** Under ~30 letters chi-squared is unreliable. Switch to quadgram
  scoring (see `classical-substitution-hillclimb`) or filter by known flag format.
- **Case and punctuation.** Score only the letters, but *print* the formatted text -
  spacing makes human verification instant.
- **Non-English plaintext.** Swap the frequency table. A German/French table changes
  the winner; if all 26 shifts score badly and IoC is ~0.066, suspect another language.
- **Double-encoding.** `base64 -> rot13 -> base64` is a standard misc-crypto chain.
  Always re-run detection on the decrypted output.

## Tools

- **CyberChef**: `ROT13` (with "Amount" slider = any n), `ROT47`, `Affine Cipher
  Decode`, `Atbash Cipher`, and `ROT13 Brute Force` which prints all 26 at once.
- **dcode.fr**: has automatic solvers for Caesar, Affine, Atbash with a built-in
  "cipher identifier".
- **`caesar` / `rot13` CLI**: `tr 'A-Za-z' 'N-ZA-Mn-za-m'` is ROT13 in pure shell.
- **`python3 -c 'import codecs;print(codecs.encode(s,"rot13"))'`** - stdlib ROT13.
- **quipqiup.com**: overkill for Caesar, but it solves affine as a special case of
  substitution and handles word boundaries well.

## References

- CyberChef - <https://gchq.github.io/CyberChef/>
- dcode.fr cipher identifier - <https://www.dcode.fr/cipher-identifier>
- quipqiup (automated substitution solver) - <https://quipqiup.com/>
