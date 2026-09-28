---
title: "AES-CTR / OFB - Keystream Reuse (Nonce Reuse)"
category: crypto
subcategory: ctr
type: technique
tags: [aes, ctr, ofb, cfb, nonce-reuse, iv-reuse, keystream-reuse, many-time-pad, two-time-pad, xor, stream-cipher, malleability, bit-flipping, edit-oracle, crib-dragging, known-plaintext, cryptopals, pycryptodome, chacha20]
difficulty: easy
summary: "CTR and OFB turn AES into a stream cipher; reuse the nonce and C1 xor C2 = P1 xor P2, which is a many-time pad and also fully malleable bit by bit."
when_to_use:
  - "Two or more ciphertexts were produced with the same key and the same nonce or IV"
  - "The nonce is a counter that resets, a timestamp with second resolution, or hardcoded"
  - "Ciphertext length equals plaintext length exactly (no block padding)"
  - "You know or can guess part of one plaintext (a header, a JSON key, a flag prefix)"
  - "There is an `edit(ciphertext, offset, newtext)` API that re-encrypts in place"
  - "You want to flip specific bits of the plaintext with no collateral damage"
tools: [pycryptodome, cyberchef, xortool]
source:
  name: "Cryptopals Set 3"
  url: "https://cryptopals.com/sets/3"
related: [xor-repeating-key, xor-known-plaintext, aes-cbc-bit-flipping, aes-gcm-nonce-reuse-forbidden, stream-rc4-attacks]
---

## TL;DR

CTR builds a keystream `KS = E_k(nonce||0) || E_k(nonce||1) || ...` and xors it with the
plaintext. The keystream depends only on `(key, nonce)`, so two messages under the same
pair share it: `C1 xor C2 = P1 xor P2`. One known plaintext gives the keystream and
therefore every other message. And because the transform is a plain xor, flipping any
ciphertext bit flips exactly that plaintext bit. OFB and CFB have the same reuse
property; ChaCha20 has it too.

## Recognise it

- `AES.new(key, AES.MODE_CTR, nonce=...)` where the nonce is constant, derived from a
  low-entropy value, or omitted so a default is used.
- `len(ciphertext) == len(plaintext)` - no padding, no block alignment.
- Several ciphertexts from the same service that share a visible nonce prefix, or no
  nonce at all in the wire format.
- Ciphertexts of different messages that agree on long stretches when xored together.
- An "edit my encrypted note at offset N" feature.
- `Counter.new(128, initial_value=0)` with a fixed initial value.

## Theory

$$C = P \oplus KS(k, \text{nonce}), \qquad KS_j = E_k(\text{nonce} \| j)$$

Reuse the nonce for two messages:

$$C_1 \oplus C_2 = (P_1 \oplus KS) \oplus (P_2 \oplus KS) = P_1 \oplus P_2$$

The key has vanished. What is left is a **many-time pad**, solvable with the standard
English-text techniques (see `xor-repeating-key`):

- If you know any stretch of `P_1`, then `KS = C_1 xor P_1` over that stretch, and
  every other ciphertext decrypts there for free.
- With `N >= 5` ciphertexts, the space-character statistic works: in English,
  `letter xor space = the same letter with case flipped`, which is again a letter. For
  each column, the ciphertext that xors to a letter against most of the others is very
  likely the one holding a space, which pins `KS` at that column.
- Crib dragging: slide a guessed word across `C1 xor C2` and read out the other
  plaintext.

**Malleability.** `C[j] ^= d` gives `P[j] ^= d`, per byte, per bit, with no damage to
any other byte. There is no sacrificial block as in CBC. If the plaintext is
`{"admin": false}` and you know the offset, you own it.

**Edit oracle.** An API `edit(ct, offset, newtext)` that decrypts, splices and
re-encrypts under the same nonce is a keystream dump: call
`edit(ct, 0, b"\x00" * len(ct))` and the result *is* the keystream, because
`0 xor KS = KS`. Then `P = C xor KS`.

**OFB** is `KS_0 = E_k(IV)`, `KS_{j+1} = E_k(KS_j)`, then `C = P xor KS`. Same key and
IV means the same keystream. Identical consequences. **CFB** chains on the ciphertext,
so reuse leaks only until the first differing byte - still fatal for a shared header.

## Attack

1. Confirm the reuse: xor two ciphertexts. If the result is mostly printable-ish and
   has low entropy, they share a keystream.
2. Get keystream bytes any way you can:
   - known plaintext prefix (`flag{`, `{"`, `HTTP/1.1`, a PNG or ZIP magic),
   - an edit oracle,
   - the space statistic over many ciphertexts,
   - crib dragging a guessed word.
3. Extend the keystream with cross-checking: decrypt all messages with the partial
   keystream, read the partially recovered words, guess the rest, feed the guess back.
4. Once you have `KS`, encryption is free too: `C' = P' xor KS`, so you can forge any
   message up to `len(KS)` bytes.

## Code

```python
#!/usr/bin/env python3
"""AES-CTR / OFB keystream reuse: known-plaintext recovery, the many-time-pad
statistic, bit-flipping and the edit-oracle keystream dump.

Self-contained; every attack is asserted against a locally built vulnerable service.
"""

import os
from Crypto.Cipher import AES

BS = 16


# ----------------------------------------------------------------- helpers
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ctr_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(data)


def ofb_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_OFB, iv).encrypt(data)


def keystream_from_known(ct: bytes, known_pt: bytes, offset: int = 0) -> bytes:
    """KS[offset:offset+len] = ct xor known plaintext."""
    return xor(ct[offset:offset + len(known_pt)], known_pt)


# ------------------------------------------------------- many-time-pad solve
def is_letter(b: int) -> bool:
    return 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def space_statistic(cts: list[bytes]) -> bytearray:
    """Keystream guess from the space heuristic alone.

    In English text `letter xor 0x20` is the same letter with the case flipped, so a
    column where ct[i] xor ct[j] is a letter for most j means ct[i] holds a space.
    Cheap, works with as few as 5 ciphertexts, typically 75-85% of columns correct.
    """
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
    return ks


# Rough log-likelihood of each character in English prose. Anything not listed is
# treated as impossible, which is what kills the wrong keystream bytes.
_CHAR_SCORE = {ord(" "): 3.0}
for _c, _w in zip("etaoinshrdlcumwfgypbvkjxqz",
                  [2.6, 2.5, 2.4, 2.3, 2.3, 2.2, 2.2, 2.1, 2.0, 1.9, 1.8, 1.6,
                   1.5, 1.4, 1.3, 1.3, 1.2, 1.1, 1.0, 0.9, 0.7, 0.5, 0.3, 0.2,
                   0.1, 0.05]):
    _CHAR_SCORE[ord(_c)] = _w
    _CHAR_SCORE[ord(_c.upper())] = _w - 1.2
for _c in ".,'\"!?;:-()0123456789":
    _CHAR_SCORE[ord(_c)] = 0.4
for _c in "_{}[]/@#$%&*+=<>|~^\\":
    _CHAR_SCORE[ord(_c)] = 0.05


def solve_many_time_pad(cts: list[bytes]) -> bytearray:
    """Recover the shared keystream column by column.

    Each column is an independent single-byte-xor problem across all ciphertexts, so
    score all 256 candidates with an English character model and keep the best. With
    ~10 ciphertexts this is far more accurate than the space heuristic alone.
    """
    longest = max(len(c) for c in cts)
    ks = bytearray(longest)
    for pos in range(longest):
        column = [c[pos] for c in cts if len(c) > pos]
        best, best_score = 0, float("-inf")
        for k in range(256):
            score = 0.0
            for b in column:
                score += _CHAR_SCORE.get(b ^ k, -6.0)
            if score > best_score:
                best, best_score = k, score
        ks[pos] = best
    return ks


def crib_drag(xored: bytes, crib: bytes):
    """Slide a crib across C1 xor C2; yields (offset, the other plaintext candidate)."""
    for off in range(0, len(xored) - len(crib) + 1):
        yield off, xor(xored[off:off + len(crib)], crib)


# ------------------------------------------------------------- malleability
def ctr_bitflip(ct: bytes, offset: int, known: bytes, desired: bytes) -> bytes:
    """Rewrite plaintext bytes in place. No collateral damage at all."""
    assert len(known) == len(desired)
    out = bytearray(ct)
    for i, d in enumerate(xor(known, desired)):
        out[offset + i] ^= d
    return bytes(out)


# --------------------------------------------------------- vulnerable service
class NoteService:
    """Encrypts every note with the same key AND the same nonce, and offers `edit`."""

    def __init__(self) -> None:
        self.key = os.urandom(16)
        self.nonce = os.urandom(8)          # generated once -- that is the bug

    def encrypt(self, pt: bytes) -> bytes:
        return ctr_encrypt(self.key, self.nonce, pt)

    def decrypt(self, ct: bytes) -> bytes:
        return AES.new(self.key, AES.MODE_CTR, nonce=self.nonce).decrypt(ct)

    def edit(self, ct: bytes, offset: int, newtext: bytes) -> bytes:
        """Decrypt, splice, re-encrypt under the SAME nonce. A keystream oracle."""
        pt = bytearray(self.decrypt(ct))
        pt[offset:offset + len(newtext)] = newtext
        return self.encrypt(bytes(pt))


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    svc = NoteService()

    MSGS = [
        b"Dear admin, please reset the password for the backup account soon.",
        b"The quick brown fox jumps over the lazy dog while nobody watches.",
        b"Meeting moved to eleven o'clock in the small room near the stairs.",
        b"Remember that the flag is flag{ctr_nonce_reuse_is_a_two_time_pad}.",
        b"Never encrypt two different messages under one counter mode nonce.",
        b"Sales figures for the quarter are attached to the previous email.",
        b"Please review the draft before Friday and send me your comments.",
        b"Another line of perfectly ordinary English prose for statistics.",
        b"Counter mode turns a block cipher into a very fast stream cipher.",
        b"The keystream depends only on the key and the nonce, never input.",
        b"If you reuse it, the xor of two ciphertexts is the xor of plains.",
        b"That is exactly the situation a classical cryptanalyst dreams of.",
        b"Please do not reply to this address because nobody ever reads it.",
        b"Attached you will find the minutes of the last committee meeting.",
        b"Our servers will be unavailable on Sunday morning for some hours.",
        b"Thank you for your patience while we migrate the old databases.",
        b"A stream cipher is only as strong as the uniqueness of its nonce.",
        b"Every serious protocol derives a fresh nonce for every message.",
    ]
    cts = [svc.encrypt(m) for m in MSGS]

    # --- detect the reuse --------------------------------------------------
    d = xor(cts[0], cts[1])
    assert d == xor(MSGS[0], MSGS[1])
    printable = sum(1 for b in d if 0x20 <= b <= 0x7E or b < 0x20)
    print(f"[+] C1 xor C2 is {printable}/{len(d)} low-byte -- keystream reuse")

    # --- known plaintext ---------------------------------------------------
    crib = b"Dear admin, "
    ks = keystream_from_known(cts[0], crib)
    assert xor(cts[1][:len(ks)], ks) == MSGS[1][:len(ks)]
    print("[+] PASS known-plaintext keystream:", xor(cts[1][:len(ks)], ks))

    # full keystream from one fully known message
    full_ks = keystream_from_known(cts[0], MSGS[0])
    for m, c in zip(MSGS, cts):
        assert xor(c, full_ks[:len(c)]) == m
    print("[+] PASS one known message decrypts all", len(MSGS), "messages")

    # --- statistical many-time-pad ----------------------------------------
    cheap = space_statistic(cts)
    cheap_acc = sum(1 for i in range(len(full_ks)) if cheap[i] == full_ks[i]) / len(full_ks)
    print(f"[+] space-heuristic keystream accuracy:  {cheap_acc:.0%}")

    guess_ks = solve_many_time_pad(cts)
    hits = sum(1 for i in range(len(full_ks)) if guess_ks[i] == full_ks[i])
    acc = hits / len(full_ks)
    print(f"[+] column-scoring keystream accuracy:   {acc:.0%}")
    assert acc >= 0.90, acc
    recovered = xor(cts[3], bytes(guess_ks[:len(cts[3])]))
    print("[+] partially recovered msg 4:", recovered)
    assert b"flag{" in recovered or b"FLAG{" in recovered
    print("[+] PASS many-time-pad statistic")

    # --- crib dragging -----------------------------------------------------
    hit = [(o, cand) for o, cand in crib_drag(xor(cts[0], cts[3]), b" the flag is ")
           if all(0x20 <= b <= 0x7E for b in cand)]
    assert any(b"lease reset" in cand for _, cand in hit), hit
    print("[+] PASS crib dragging found", len(hit), "printable candidates")

    # --- malleability ------------------------------------------------------
    pt = b'{"user":"guest","admin":false}'
    ct = svc.encrypt(pt)
    off = pt.index(b"guest")
    forged = ctr_bitflip(ct, off, b"guest", b"admin")
    off2 = pt.index(b"false")
    forged = ctr_bitflip(forged, off2, b"false", b"true ")
    out = svc.decrypt(forged)
    print("[+] bit-flipped plaintext:", out)
    assert out == b'{"user":"admin","admin":true }'
    print("[+] PASS ctr bit-flipping, zero collateral damage")

    # --- edit oracle -------------------------------------------------------
    secret_ct = svc.encrypt(b"top secret: flag{ctr_edit_oracle_dumps_the_keystream}")
    dumped_ks = svc.edit(secret_ct, 0, b"\x00" * len(secret_ct))
    assert dumped_ks == full_ks[:len(secret_ct)]
    print("[+] recovered:", xor(secret_ct, dumped_ks))
    assert xor(secret_ct, dumped_ks).startswith(b"top secret: flag{")
    print("[+] PASS edit oracle")

    # --- OFB has the identical property ------------------------------------
    key, iv = os.urandom(16), os.urandom(16)
    a = ofb_encrypt(key, iv, MSGS[0])
    b = ofb_encrypt(key, iv, MSGS[1])
    assert xor(a, b) == xor(MSGS[0], MSGS[1])
    assert xor(a, MSGS[0])[:len(b)] and xor(b, xor(a, MSGS[0])[:len(b)]) == MSGS[1]
    print("[+] PASS OFB keystream reuse behaves the same")

    print("\nall checks passed")
```

## Variants & pitfalls

- **ChaCha20 / Salsa20 / Trivium / RC4** - every stream cipher has this property. The
  fix is always a unique nonce, never a better cipher.
- **Nonce is a counter that resets on restart.** Very common in CTF: the service
  restarts between your two connections and starts counting from 0 again.
- **Nonce = message id, but the id is user-controlled.** Ask for the same id twice.
- **Partial overlap.** CTR blocks are indexed, so two messages of different lengths
  still share the keystream from byte 0. Align at offset 0, not at the end.
- **Random-access CTR.** `nonce || counter` layouts differ: pycryptodome's default is
  8-byte nonce + 8-byte counter; `Counter.new(128, initial_value=N)` uses the whole
  128-bit block. Get this wrong and your offsets will be off by a block.
- **Length is not hidden.** CTR leaks the exact plaintext length. Combine with a
  compression oracle for extra leverage.
- **Do not confuse CTR reuse with GCM reuse.** GCM nonce reuse additionally leaks the
  authentication key `H` and lets you forge tags - see
  `aes-gcm-nonce-reuse-forbidden`.
- **The space statistic needs English.** For base64, JSON or binary payloads use a
  different heuristic: for JSON, `"` and `:` and `,` are the frequent characters; for
  base64, all bytes are in a 64-char alphabet, which is itself a strong constraint.

## Tools

- `pycryptodome` - `AES.MODE_CTR`, `AES.MODE_OFB`, `Crypto.Util.Counter`.
- `xortool` - keylength detection and repeating-key xor solving.
- CyberChef - "XOR" and "AES Decrypt (CTR)" for quick manual work.

## References

- Cryptopals Set 3, challenges 19 and 20 (fixed-nonce CTR) and Set 4, challenge 25
  (CTR random access read/write): <https://cryptopals.com/sets/3>,
  <https://cryptopals.com/sets/4>
