---
title: "Running-Key and Book Ciphers, and One-Time-Pad Misuse"
category: crypto
subcategory: classical
type: technique
tags: [running-key, running-key-cipher, book-cipher, beale-cipher, ottendorf, one-time-pad, otp, many-time-pad, key-reuse, crib-drag, crib-dragging, xor-key-reuse, space-heuristic, vigenere, autokey, depth, viterbi, beam-search]
difficulty: medium
summary: "When the key is as long as the message you cannot find a period - drag cribs instead, and exploit the fact that the key is itself English (or that it was reused)."
when_to_use:
  - "Vigenere-looking ciphertext where no key length spikes in the per-period IoC"
  - "Ciphertext IoC is 0.04-0.05: near random, nowhere near English's 0.066"
  - "The challenge ships a book / text file alongside the ciphertext"
  - "Several ciphertexts of the same length, or an XOR pad that was used twice"
tools: [python, cyberchef, dcode, xortool]
related: [classical-vigenere, classical-caesar-affine, cipher-identification]
---

## TL;DR

A **running key** is a key as long as the message, taken from a book. There is no
period to find, so Kasiski and Friedman are useless. Two levers remain: (1) the key is
*itself English*, so a joint statistical search over both streams beats random, and
(2) **crib dragging** - subtract a guessed plaintext word from every position and look
for readable key fragments. A **one-time pad reused** (a "many-time pad") collapses
completely: XOR two ciphertexts and the key vanishes.

## Recognise it

- IoC around **0.040-0.050** - at best slightly above random (0.0385) and far below
  English (0.066). On a short message it is indistinguishable from random, so the
  absence of a per-period spike matters more than the absolute value.
- Per-period IoC shows **no spike at any key length** up to 40+.
- The challenge provides a text file, a book title, a Gutenberg link, or page/line
  numbers.
- **Book cipher proper**: the ciphertext is a list of numbers (`115 73 24 807 37`),
  sometimes triples `page.line.word`. Beale/Ottendorf style.
- **Many-time pad**: several equal-length hex blobs; XOR any two and the result has
  printable-ASCII-like structure.

## Theory

**Running key Vigenere.** $c_i = p_i + k_i \bmod 26$ with $k$ drawn from a book.
Both $p$ and $k$ are English, so for each ciphertext letter the 26 possible
$(p_i, k_i)$ splits are not equally likely: `c = 'X'` decomposes far more plausibly as
`T + E` than as `Q + H`. Chain that with an n-gram model on *both* streams and you get
a beam search that recovers fragments. It will not usually give you the whole message
- the model has to be strong (quadgrams over a large corpus) and even then human
reading is needed - but it does surface anchors.

**Crib dragging** is the reliable attack. Guess a plaintext word $w$. For every offset
$o$, compute $k = c_{o..o+|w|} - w$. If $k$ is a readable English fragment, you have
found both the offset and a slice of the key; extend it left and right by guessing
words in the key stream, which reveals more plaintext, which reveals more key. It is a
zip-up. The Vigenere/running-key structure is symmetric, so plaintext and key are
interchangeable - drag cribs against both.

**Book cipher.** Ciphertext numbers index into a known text: the $n$-th word's first
letter (Beale), or `page.line.word` triples (Ottendorf). There is no cryptanalysis -
you need the book. Identify it from the numbers' range and any repeated structure, or
from the challenge files. Beale Cipher #2 used the US Declaration of Independence.

**One-time pad misuse.** With $c_1 = p_1 \oplus k$ and $c_2 = p_2 \oplus k$,
$c_1 \oplus c_2 = p_1 \oplus p_2$ - the key is gone. The classic recovery uses the
**space heuristic**: in ASCII, `space ^ letter` flips bit 5 and yields a letter of the
opposite case, while `letter ^ letter` is a control character. So for each column,
whichever ciphertext, when XORed against all the others, produces mostly alphabetic
bytes is the one whose plaintext byte is a space. That gives `k = c ^ 0x20` at that
column. With ~8-10 messages you recover nearly the whole key.

In the *letter* (mod 26) setting the same idea works with "E" instead of space, but
it is weaker; crib dragging is better there.

**Why Vigenere-with-a-short-key is not this.** If the IoC table spikes anywhere, stop
reading this page and go to `classical-vigenere`.

## Attack

1. Compute IoC and the per-period IoC table. No spike + IoC ~0.045 -> running key.
2. Collect cribs: the flag format (`FLAG`, `CTF`, `THE`), the challenge title, common
   words (`THE`, `AND`, `THAT`, `WITH`, `THERE`).
3. Crib-drag each one across every offset. Keep any offset whose derived key fragment
   is pronounceable.
4. Extend: treat the key fragment as a crib against the *other* stream and repeat.
5. If the book is supplied, just align: try every starting offset in the book and
   score the decryption. That is an instant win.
6. For XOR many-time pads: space heuristic, then fill the remaining columns by hand
   using partial words.

## Code

```python
#!/usr/bin/env python3
"""Running-key Vigenere, book ciphers, crib dragging, a joint beam search over both
English streams, and full many-time-pad (XOR key reuse) recovery. Self-testing."""
from __future__ import annotations

import heapq
import math
import os
import string
from collections import Counter

A = string.ascii_uppercase

_CORPUS = (
    "the history of the world is in many ways the history of the ordinary people who "
    "lived through it and not only of the kings and generals whose names are written "
    "in the books that children read at school in every village there were farmers "
    "who watched the weather and the price of grain women who carried water from the "
    "well before the sun was high and children who learned to count the days until "
    "the harvest they did not think of themselves as living in a period that would "
    "one day be given a name by scholars they thought about the rain the road to the "
    "market and whether there would be enough bread in the house for the winter that "
    "was coming when a traveller came to such a village he brought news from the city "
    "and the news was often wrong but it was the only news there was he would sit by "
    "the fire in the evening and tell of the great river that runs to the sea of the "
    "ships that come from the islands with salt and iron and of the men who build "
    "walls of stone around their houses because they are afraid of what may come out "
    "of the forest at night the children listened with open mouths and the old men "
    "said that in their own time the stories had been better this is what people have "
    "always said and it is probably what they will always say because memory is a "
    "kind of story that we tell ourselves about the years that are already gone"
)

_S = "".join(c for c in _CORPUS.upper() if c in A)
_UNI = Counter(_S)
_BI = Counter(_S[i:i + 2] for i in range(len(_S) - 1))
_TRI = Counter(_S[i:i + 3] for i in range(len(_S) - 2))
_N = len(_S)


def clean(t: str) -> str:
    return "".join(c for c in t.upper() if c in A)


def _lu(ch: str) -> float:
    return math.log10((_UNI.get(ch, 0) + 0.3) / (_N + 0.3 * 26))


def _lb(a: str, b: str) -> float:
    return math.log10((_BI.get(a + b, 0) + 0.3) / (_UNI.get(a, 0) + 0.3 * 26))


def cond_score(ctx: str, ch: str) -> float:
    """log10 P(ch | ctx) with trigram -> bigram -> unigram backoff."""
    if len(ctx) >= 2:
        c = ctx[-2:]
        return math.log10((_TRI.get(c + ch, 0) + 0.2) / (_BI.get(c, 0) + 0.2 * 26))
    if len(ctx) == 1:
        return _lb(ctx, ch)
    return _lu(ch)


def ioc(text: str) -> float:
    s = clean(text)
    n = len(s)
    if n < 2:
        return 0.0
    c = Counter(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


# ------------------------- running key (mod 26) ----------------------------
def rk_encrypt(pt: str, key: str) -> str:
    p, k = clean(pt), clean(key)
    if len(k) < len(p):
        raise ValueError("running key must be at least as long as the plaintext")
    return "".join(A[(A.index(a) + A.index(b)) % 26] for a, b in zip(p, k))


def rk_decrypt(ct: str, key: str) -> str:
    c, k = clean(ct), clean(key)
    return "".join(A[(A.index(a) - A.index(b)) % 26] for a, b in zip(c, k))


def crib_drag(ct: str, crib: str):
    """Subtract the crib at every offset; the result is the corresponding key slice.

    Returns [(offset, key_fragment, fragment_score)] sorted best-first.
    """
    c, w = clean(ct), clean(crib)
    out = []
    for o in range(len(c) - len(w) + 1):
        frag = "".join(A[(A.index(c[o + i]) - A.index(w[i])) % 26]
                       for i in range(len(w)))
        score = sum(cond_score(frag[:i], frag[i]) for i in range(len(frag)))
        out.append((o, frag, score))
    out.sort(key=lambda t: -t[2])
    return out


def book_align(ct: str, book: str, top: int = 5):
    """The book is known: try every starting offset and score the plaintext."""
    c = clean(ct)
    b = clean(book)
    cands = []
    for o in range(len(b) - len(c) + 1):
        pt = rk_decrypt(c, b[o:o + len(c)])
        s = sum(cond_score(pt[max(0, i - 2):i], pt[i]) for i in range(len(pt)))
        cands.append((s, o, pt))
    cands.sort(key=lambda t: -t[0])
    return cands[:top]


def joint_beam(ct: str, width: int = 2000, topk: int = 5):
    """Search both English streams at once. Returns [(score, plaintext, key)].

    This is a CANDIDATE GENERATOR, not an oracle: with a small embedded corpus it
    typically recovers 30-50% of the characters and, more usefully, surfaces real
    English fragments you can turn into cribs. Swap in a quadgram table trained on
    a large corpus for materially better output.
    """
    c = [A.index(x) for x in clean(ct)]
    beams = [(0.0, "", "")]
    for t in range(len(c)):
        cand = []
        for sc, p, k in beams:
            for pi in range(26):
                ki = (c[t] - pi) % 26
                a, b = A[pi], A[ki]
                cand.append((sc + cond_score(p, a) + cond_score(k, b), p + a, k + b))
        beams = heapq.nlargest(width, cand)
    return beams[:topk]


# ------------------------------ book cipher --------------------------------
def book_words(book: str):
    return [w.strip(string.punctuation).upper() for w in book.split() if w.strip(string.punctuation)]


def book_encode(pt: str, book: str, seed: int = 0):
    """Beale style: each plaintext letter -> index of a word starting with it."""
    words = book_words(book)
    index: dict[str, list[int]] = {}
    for i, w in enumerate(words, start=1):
        if w:
            index.setdefault(w[0], []).append(i)
    out = []
    counter = seed
    for ch in clean(pt):
        if ch not in index:
            raise ValueError(f"book has no word starting with {ch}")
        opts = index[ch]
        out.append(opts[counter % len(opts)])
        counter += 1
    return out


def book_decode(numbers, book: str) -> str:
    words = book_words(book)
    out = []
    for n in numbers:
        if 1 <= n <= len(words) and words[n - 1]:
            out.append(words[n - 1][0])
        else:
            out.append("?")
    return "".join(out)


# -------------------------- many-time pad (XOR) ----------------------------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def mtp_recover_key(ciphertexts, printable=range(32, 127)):
    """Space heuristic over a set of ciphertexts encrypted with the SAME keystream.

    For each column, the ciphertext whose XOR against the others is most often
    alphabetic almost certainly hides a space there, giving key = byte ^ 0x20.
    Returns (key_bytes, known_mask).
    """
    n = max(len(c) for c in ciphertexts)
    key = bytearray(n)
    known = bytearray(n)
    for col in range(n):
        col_bytes = [(i, c[col]) for i, c in enumerate(ciphertexts) if col < len(c)]
        if len(col_bytes) < 2:
            continue
        best_i, best_votes = None, -1
        for i, bi in col_bytes:
            votes = 0
            for j, bj in col_bytes:
                if i == j:
                    continue
                x = bi ^ bj
                if 65 <= x <= 90 or 97 <= x <= 122:
                    votes += 1
                elif x == 0:
                    votes += 0          # equal bytes: no information
                elif x not in printable:
                    votes -= 1
            if votes > best_votes:
                best_votes, best_i = votes, bi
        if best_votes >= max(1, (len(col_bytes) - 1) // 2):
            key[col] = best_i ^ 0x20
            known[col] = 1
    return bytes(key), bytes(known)


def mtp_apply(ct: bytes, key: bytes, known: bytes) -> str:
    out = []
    for i, b in enumerate(ct):
        if i < len(known) and known[i]:
            ch = b ^ key[i]
            out.append(chr(ch) if 32 <= ch < 127 else ".")
        else:
            out.append("_")
    return "".join(out)


if __name__ == "__main__":
    book = ("IT WAS THE BEST OF TIMES IT WAS THE WORST OF TIMES IT WAS THE AGE OF "
            "WISDOM IT WAS THE AGE OF FOOLISHNESS IT WAS THE EPOCH OF BELIEF IT WAS "
            "THE EPOCH OF INCREDULITY IT WAS THE SEASON OF LIGHT IT WAS THE SEASON "
            "OF DARKNESS IT WAS THE SPRING OF HOPE IT WAS THE WINTER OF DESPAIR")
    plain = "THEFLAGISBURIEDUNDERTHEOLDOAKTREENEARTHERIVERBANKATMIDNIGHT"

    # --- running key round trip -------------------------------------------
    keystream = clean(book)
    ct = rk_encrypt(plain, keystream)
    assert rk_decrypt(ct, keystream) == clean(plain)
    print(f"[ok] running key round trip: {ct[:32]}...")

    # --- IoC sits between English and random ------------------------------
    v = ioc(ct)
    assert 0.030 < v < 0.060, v
    print(f"[ok] running-key IoC = {v:.4f} (English 0.066, random 0.0385)")

    # --- crib drag: THEFLAGIS is at offset 0, key fragment is ITWASTHEB ---
    hits = crib_drag(ct, "THEFLAGIS")
    top_offsets = [o for o, _, _ in hits[:5]]
    assert 0 in top_offsets, hits[:3]
    frag = dict((o, f) for o, f, _ in hits)[0]
    assert frag == "ITWASTHEB", frag
    print(f"[ok] crib drag recovered key fragment {frag!r} at offset 0")

    # --- the drag is symmetric: drag a KEY word to find the plaintext ------
    hits2 = crib_drag(ct, "ITWASTHE")
    assert any(o == 0 and f == "THEFLAGI" for o, f, _ in hits2[:5]), hits2[:3]
    print("[ok] crib drag is symmetric (key word -> plaintext fragment)")

    # --- book known: align it ---------------------------------------------
    aligned = book_align(ct, book)
    assert aligned[0][1] == 0 and aligned[0][2] == clean(plain), aligned[0][:2]
    print(f"[ok] known book aligned at offset {aligned[0][1]}")

    # --- joint beam search over both streams ------------------------------
    cands = joint_beam(ct[:48], width=800, topk=3)
    best_p, best_k = cands[0][1], cands[0][2]
    assert rk_encrypt(best_p, best_k) == ct[:48]          # internally consistent
    acc = sum(a == b for a, b in zip(best_p, clean(plain))) / len(best_p)
    assert acc > 0.20, acc                                # random guessing is 1/26
    print(f"[ok] joint beam search: {acc*100:.0f}% of characters correct")
    print(f"     P: {best_p}")
    print(f"     K: {best_k}")

    # --- book cipher -------------------------------------------------------
    # Needs a book with a word starting with every plaintext letter; the Dickens
    # snippet above has no G, so use the larger corpus as the book.
    nums = book_encode("FLAG", _CORPUS)
    assert book_decode(nums, _CORPUS) == "FLAG", (nums, book_decode(nums, _CORPUS))
    print(f"[ok] book cipher: FLAG -> {nums}")

    # --- many-time pad (XOR key reuse) ------------------------------------
    msgs = [
        b"the quick brown fox jumps over the lazy dog every single morning",
        b"attack at dawn and bring the artillery forward to the north gate",
        b"we have found the secret key hidden under the old oak tree today",
        b"never reuse a one time pad because the key cancels out instantly",
        b"the flag for this challenge is hidden inside the second message",
        b"cryptography is only as strong as the discipline of its keepers",
        b"please remember to rotate your keys after every single session",
        b"a stream cipher with a repeated keystream is not a cipher at all",
        b"many time pad recovery relies on the humble ascii space charcter",
        b"read the ciphertext columns and vote for the most likely spaces",
    ]
    L = min(len(m) for m in msgs)
    msgs = [m[:L] for m in msgs]
    pad = os.urandom(L)
    cts = [xor_bytes(m, pad) for m in msgs]
    key, known = mtp_recover_key(cts)
    correct = sum(1 for i in range(L) if known[i] and key[i] == pad[i])
    coverage = sum(known) / L
    print(f"[ok] many-time pad: recovered {sum(known)}/{L} key bytes "
          f"({coverage*100:.0f}%), {correct} of them correct")
    assert coverage > 0.70 and correct == sum(known)
    print(f"     -> {mtp_apply(cts[4], key, known)}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **The key text may not start at offset 0.** When the book is known, always sweep
  every offset - CTF authors love starting at a random page.
- **Punctuation and spaces in the key.** Did the encoder strip them? If `book_align`
  fails, try keeping spaces, or keeping only letters but preserving case-derived
  offsets.
- **Running key with a *non-English* book**, or with the key text itself being the
  flag repeated - check whether the recovered "key" looks like a flag.
- **Autokey vs running key.** Autokey's key is `primer + plaintext`, so once you guess
  the primer the rest unrolls deterministically - brute force primers of length 1-4.
  Running key has no such structure.
- **Beale-style book ciphers are unbreakable without the book.** Spend your time
  identifying the book (number range, repeated numbers, provided files) rather than on
  cryptanalysis.
- **Ottendorf triples** `p.l.w` need the exact edition's pagination. If the numbers
  have three components and the challenge gives a plain text file, the "page" is
  usually a paragraph or line index instead.
- **XOR many-time pad with short messages.** The space heuristic needs depth; with
  fewer than ~6 messages many columns stay unknown. Fill them by guessing words -
  every guess in one message propagates to all the others.
- **Non-space-heavy plaintext** (base64, hex, a binary blob) breaks the space
  heuristic. Use `xortool` / frequency-based key-byte search instead.
- **`os.urandom` vs a real OTP.** A pad from a CSPRNG used once is fine; the bug is
  always reuse, a short pad, or a pad derived from a seeded PRNG - in the last case
  attack the PRNG (see the `prng-*` techniques), not the pad.
- **Mod-26 "OTP" with a key from `random.choice`** is a PRNG problem, not a pad
  problem. Look for the seeding code.

## Tools

- **dcode.fr running key cipher** - <https://www.dcode.fr/running-key-cipher>
- **CyberChef** - `Vigenere Decode` with a long key, `XOR`, `XOR Brute Force`.
- **xortool** - <https://github.com/hellman/xortool> - key-length detection and
  frequency-based key recovery for repeating-key XOR.
- **`cribdrag.py`** (part of the `xortool`-adjacent tooling ecosystem) - interactive
  crib dragging for XOR many-time pads.
- **Project Gutenberg** - where the "book" in a book cipher almost always comes from.

## References

- dcode.fr running key cipher - <https://www.dcode.fr/running-key-cipher>
- dcode.fr book cipher - <https://www.dcode.fr/book-cipher>
- xortool - <https://github.com/hellman/xortool>
- CyberChef - <https://gchq.github.io/CyberChef/>
