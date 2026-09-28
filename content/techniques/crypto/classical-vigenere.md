---
title: "Vigenere - Kasiski, Index of Coincidence, Friedman, Key Recovery"
category: crypto
subcategory: classical
type: technique
tags: [vigenere, vigenere-cipher, polyalphabetic, kasiski, kasiski-examination, index-of-coincidence, ioc, friedman-test, beaufort, gronsfeld, variant-beaufort, autokey, key-length, chi-squared, repeating-key-xor, dcode, cyberchef]
difficulty: easy
summary: "Find the key length by Kasiski repeats or per-shift IoC, split the text into that many Caesar columns, and solve each column by chi-squared."
when_to_use:
  - "Ciphertext is A-Z only but IoC is ~0.038-0.050 (flatter than English's 0.066)"
  - "Letter frequency histogram is noticeably flat - no dominant E"
  - "Repeated 3+ letter ciphertext substrings appear at distances sharing a common factor"
  - "Challenge mentions a 'keyword', a Vigenere square / tabula recta, or Beaufort"
tools: [python, cyberchef, dcode, cryptool]
related: [classical-caesar-affine, classical-running-key, classical-substitution-hillclimb, cipher-identification]
---

## TL;DR

Vigenere with key length $m$ is $m$ interleaved Caesar ciphers. Recover $m$ (Kasiski
distances / per-period IoC / Friedman estimate), slice the ciphertext into $m$ columns
by index mod $m$, and break each column independently with a chi-squared shift test.
With >= 20 letters per column this is essentially deterministic.

## Recognise it

- Charset `A-Z`; **IoC around 0.038-0.050** instead of English's 0.066. The longer the
  key, the closer IoC gets to random (0.0385).
- The frequency histogram is flattened; no letter dominates.
- `Repeated` trigrams/tetragrams at distances that share a GCD - that GCD is (a
  multiple of) the key length.
- Gronsfeld = Vigenere with a numeric key (digits 0-9 only, so shifts 0..9).
- Beaufort: $c = k - p$; Variant Beaufort: $c = p - k$. Both look identical
  statistically; try all three decryption formulas.
- If IoC of the whole text is ~0.066 but of every *column* is also ~0.066, the key
  length is 1 - it is a Caesar.

## Theory

**Encryption.** With key $k_0 \ldots k_{m-1}$ (letters as 0..25):
$$c_i = p_i + k_{i \bmod m} \pmod{26}$$

**Index of coincidence.** For text of length $n$ with letter counts $n_a$:
$$\mathrm{IoC} = \frac{\sum_a n_a (n_a - 1)}{n(n-1)}$$
English ~0.0667, uniform random over 26 letters ~0.0385. For a Vigenere with key
length $m$, the expected IoC of the full text is approximately
$$\mathrm{IoC}_m \approx \frac{1}{m}\cdot 0.0667 + \frac{m-1}{m}\cdot 0.0385$$

**Friedman test.** Solving the relation above for $m$ gives the classic estimate
$$m \approx \frac{(0.0667 - 0.0385)\, n}{(0.0667 - \mathrm{IoC}) + n\,(\mathrm{IoC} - 0.0385)}$$
Treat it as a hint only; it is noisy for short texts and long keys.

**Kasiski examination.** If a plaintext substring repeats *and* lands on the same key
offset, the ciphertext repeats too. So the distance between two identical ciphertext
n-grams (n >= 3) is a multiple of $m$. Collect all such distances, factor them, and
take the most common factor.

**Per-period IoC (the reliable method).** For each candidate $m = 1..40$, split into
$m$ columns and average their IoCs. The true $m$ (and its multiples) jump to ~0.066;
everything else sits near 0.0385. Pick the *smallest* $m$ that spikes.

**Column solving.** Column $j$ is a pure Caesar with shift $k_j$. Test all 26 shifts
with chi-squared against English unigram frequencies; the argmin is $k_j$.

**Mutual index of coincidence** is the alternative: align two columns by testing all
26 relative shifts and maximising $\sum_a f_a(\text{col}_i) f_{a+s}(\text{col}_j)$.
This recovers the key *differences* without assuming English frequencies, which is
what you need when the plaintext is not English.

## Attack

1. Strip to `A-Z`, uppercase.
2. Compute global IoC. 0.060+ -> monoalphabetic. 0.038-0.050 -> polyalphabetic.
3. Run per-period IoC for $m = 1..40$; confirm with Kasiski factors and Friedman.
4. For the winning $m$, chi-squared each column -> key letters.
5. Decrypt and read. If it is gibberish but "structured", try Beaufort
   ($p = k - c$) and Variant Beaufort ($p = c + k$).
6. If no $m$ spikes, the key is as long as the message -> running key / one-time pad
   (see `classical-running-key`), or the cipher is not Vigenere.

## Code

```python
#!/usr/bin/env python3
"""Vigenere cryptanalysis: Kasiski, IoC key-length search, Friedman, key recovery.

Handles Vigenere, Beaufort and Variant Beaufort. Run directly for a self-test.
"""
from __future__ import annotations

import string
from collections import Counter
from itertools import combinations

ALPHA = string.ascii_uppercase

ENGLISH_FREQ = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074,
]

IOC_ENGLISH = 0.0667
IOC_RANDOM = 0.0385


def clean(text: str) -> str:
    return "".join(c for c in text.upper() if c in ALPHA)


def ioc(text: str) -> float:
    s = clean(text)
    n = len(s)
    if n < 2:
        return 0.0
    c = Counter(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


def friedman_keylen(text: str) -> float:
    """Classic Friedman estimate. Noisy: use as a hint, not an answer."""
    s = clean(text)
    n = len(s)
    k = ioc(s)
    denom = (IOC_ENGLISH - k) + n * (k - IOC_RANDOM)
    if denom == 0:
        return float("inf")
    return (IOC_ENGLISH - IOC_RANDOM) * n / denom


def kasiski_distances(text: str, ngram: int = 3):
    """All distances between repeated n-grams."""
    s = clean(text)
    pos: dict[str, list[int]] = {}
    for i in range(len(s) - ngram + 1):
        pos.setdefault(s[i:i + ngram], []).append(i)
    dists = []
    for locs in pos.values():
        if len(locs) > 1:
            dists += [b - a for a, b in combinations(locs, 2)]
    return dists


def kasiski_factors(text: str, ngram: int = 3, max_len: int = 40):
    """Score each candidate key length by how many Kasiski distances it divides."""
    dists = kasiski_distances(text, ngram)
    scores = Counter()
    for d in dists:
        for f in range(2, max_len + 1):
            if d % f == 0:
                scores[f] += 1
    return scores.most_common()


def columns(text: str, m: int):
    s = clean(text)
    return ["".join(s[i::m]) for i in range(m)]


def avg_column_ioc(text: str, m: int) -> float:
    cols = columns(text, m)
    vals = [ioc(c) for c in cols if len(c) > 1]
    return sum(vals) / len(vals) if vals else 0.0


def guess_keylen(text: str, max_len: int = 40, threshold: float = 0.058):
    """Return (best_m, [(m, avg_ioc)]). Picks the SMALLEST m above threshold."""
    table = [(m, avg_column_ioc(text, m)) for m in range(1, max_len + 1)]
    spikes = [m for m, v in table if v >= threshold]
    if spikes:
        best = min(spikes)
    else:
        best = max(table, key=lambda t: t[1])[0]
    return best, table


def chi_squared_shift(col: str) -> int:
    """Best Caesar shift for one column (argmin chi-squared)."""
    n = len(col)
    best_shift, best_chi = 0, float("inf")
    for k in range(26):
        counts = [0] * 26
        for ch in col:
            counts[(ord(ch) - 65 - k) % 26] += 1
        chi = sum((counts[i] - n * ENGLISH_FREQ[i]) ** 2 / (n * ENGLISH_FREQ[i])
                  for i in range(26))
        if chi < best_chi:
            best_chi, best_shift = chi, k
    return best_shift


def recover_key(text: str, m: int) -> str:
    return "".join(chr(65 + chi_squared_shift(c)) for c in columns(text, m))


def vigenere_encrypt(pt: str, key: str) -> str:
    k = clean(key)
    out, j = [], 0
    for ch in pt:
        if ch.upper() in ALPHA:
            shift = ord(k[j % len(k)]) - 65
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(ct: str, key: str) -> str:
    k = clean(key)
    inv = "".join(chr((26 - (ord(c) - 65)) % 26 + 65) for c in k)
    return vigenere_encrypt(ct, inv)


def beaufort(text: str, key: str) -> str:
    """Beaufort: c = k - p. Self-inverse, so the same function encrypts/decrypts."""
    k = clean(key)
    out, j = [], 0
    for ch in text:
        if ch.upper() in ALPHA:
            base = 65 if ch.isupper() else 97
            out.append(chr(((ord(k[j % len(k)]) - 65) - (ord(ch) - base)) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def variant_beaufort_decrypt(ct: str, key: str) -> str:
    """Variant Beaufort: c = p - k, so p = c + k."""
    return vigenere_encrypt(ct, key)


def solve(ct: str, max_len: int = 40):
    """Full pipeline -> (key, plaintext, diagnostics dict)."""
    m, table = guess_keylen(ct, max_len)
    key = recover_key(ct, m)
    pt = vigenere_decrypt(ct, key)
    diag = {
        "global_ioc": ioc(ct),
        "friedman": friedman_keylen(ct),
        "kasiski_top": kasiski_factors(ct)[:5],
        "ioc_table": table[:max_len],
        "keylen": m,
    }
    return key, pt, diag


if __name__ == "__main__":
    plain = (
        "THE ART OF WAR TEACHES US TO RELY NOT ON THE LIKELIHOOD OF THE ENEMY NOT "
        "COMING BUT ON OUR OWN READINESS TO RECEIVE HIM NOT ON THE CHANCE OF HIS "
        "NOT ATTACKING BUT RATHER ON THE FACT THAT WE HAVE MADE OUR POSITION "
        "UNASSAILABLE AND SO IT IS THAT IN WAR THE VICTORIOUS STRATEGIST ONLY "
        "SEEKS BATTLE AFTER THE VICTORY HAS BEEN WON WHEREAS HE WHO IS DESTINED "
        "TO DEFEAT FIRST FIGHTS AND AFTERWARDS LOOKS FOR VICTORY"
    )
    key = "CRYPTOGRAM"
    ct = vigenere_encrypt(plain, key)

    print(f"global IoC = {ioc(ct):.4f}  (English ~0.0667, random ~0.0385)")
    print(f"Friedman estimate = {friedman_keylen(ct):.2f}")
    print(f"Kasiski top factors = {kasiski_factors(ct)[:5]}")

    rec_key, rec_pt, diag = solve(ct)
    print(f"[ok] key length = {diag['keylen']}, key = {rec_key}")
    assert rec_key == key, (rec_key, key)
    assert clean(rec_pt) == clean(plain)
    print("[ok] vigenere key and plaintext recovered")

    # Beaufort is self-inverse
    assert beaufort(beaufort(plain, "KEY"), "KEY").upper() == plain.upper()
    print("[ok] beaufort self-inverse")

    # Variant Beaufort round trip: c = p - k
    vb_ct = vigenere_decrypt(plain, "KEY")
    assert clean(variant_beaufort_decrypt(vb_ct, "KEY")) == clean(plain)
    print("[ok] variant beaufort round trip")

    # Key-length detector must reject a Caesar as m=1
    caesar_ct = vigenere_encrypt(plain, "F")
    m1, _ = guess_keylen(caesar_ct)
    assert m1 == 1, m1
    print("[ok] caesar detected as key length 1")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Key length detected as a multiple.** 2m, 3m also spike in the IoC table. Always
  take the smallest spiking $m$; if the recovered key looks like `ABCABC`, halve it.
- **Beaufort vs Vigenere.** Statistically identical. If the chi-squared solve gives a
  key that decrypts to garbage, re-run with $p = k - c$ (Beaufort) or $p = c + k$
  (Variant Beaufort). The code above gives all three.
- **Gronsfeld.** Numeric key; shifts limited to 0-9. Constrain `chi_squared_shift` to
  `range(10)` and the key falls out much faster.
- **Autokey.** The key is `keyword + plaintext` (or `keyword + ciphertext`). Kasiski
  and per-period IoC both fail because the key never repeats. Attack: guess a short
  primer length $m$, brute-force the first $m$ letters, then the rest of the key is
  recovered progressively as you decrypt. For $m \le 4$ that is $26^4 = 457\,976$
  trials with n-gram scoring - trivial.
- **Running key** (key is another English text): IoC of the ciphertext is around
  0.045 because *both* streams are English. Use the crib-drag technique in
  `classical-running-key`.
- **Short ciphertext / long key.** Fewer than ~20 letters per column means chi-squared
  is unreliable. Use mutual-IoC to get key *differences*, then brute-force the single
  remaining global offset (26 options) with an n-gram score.
- **Non-English plaintext.** Swap `ENGLISH_FREQ` or use mutual-IoC, which is
  language-agnostic for the differences.
- **Key derived from the flag.** Very common: the recovered key *is* the flag, or its
  keyword form is. Always print the key.
- **Vigenere over a non-26 alphabet.** If the ciphertext includes digits/symbols, the
  challenge likely uses a 36/64/95-character tabula recta. Same code with the alphabet
  and modulus swapped; score with printable ratio + n-grams on the letter subset.
- **Repeating-key XOR** is the byte-level analogue: the identical key-length and
  per-column logic applies, with Hamming distance replacing IoC.

## Tools

- **dcode.fr Vigenere** - automatic solver, also Beaufort, Gronsfeld, Autokey.
- **CyberChef** - `Vigenere Decode`, `Bifid`, `Index of Coincidence`,
  `Frequency Distribution`. No auto key-recovery, so pair it with a local script.
- **CrypTool 2** - has a full Vigenere analyser with Kasiski and Friedman built in.
- **`vigenere-solver` / `cryptanalysis` PyPI packages** - convenient but the ~150 lines
  above are usually faster than fighting an API.

## References

- dcode.fr Vigenere cipher - <https://www.dcode.fr/vigenere-cipher>
- Practical Cryptography, "Cryptanalysis of the Vigenere Cipher" - <http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher/>
- CyberChef - <https://gchq.github.io/CyberChef/>
