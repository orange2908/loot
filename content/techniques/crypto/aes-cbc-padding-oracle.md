---
title: "AES-CBC - Padding Oracle: Full Decryption and Forged Encryption (CBC-R)"
category: crypto
subcategory: cbc
type: technique
tags: [aes, cbc, padding-oracle, cbc-r, poodle, vaudenay, pkcs7, chosen-ciphertext, decryption-oracle, forgery, xor, iv, padbuster, cryptopals, pycryptodome, side-channel, error-oracle, lucky13]
difficulty: medium
summary: "One bit of leakage - 'was the PKCS#7 padding valid?' - decrypts any AES-CBC ciphertext in 128 queries per block and also lets you encrypt any plaintext you want."
when_to_use:
  - "The server distinguishes `padding error` from `decryption succeeded but parse failed`"
  - "Different HTTP status, different error string, different response length, or a timing difference"
  - "You have an encrypted cookie/token and a endpoint that decrypts it"
  - "Source calls `unpad(...)` inside a `try` and returns a distinguishable error"
  - "You need not just to read the token but to mint a new one (CBC-R)"
tools: [pycryptodome, padbuster, pwntools, burpsuite]
source:
  name: "Cryptopals Set 3"
  url: "https://cryptopals.com/sets/3"
related: [aes-cbc-bit-flipping, aes-cbc-iv-recovery, aes-ecb-byte-at-a-time, block-cbc-mac-forgery, aes-gcm-nonce-reuse-forbidden]
---

## TL;DR

CBC decrypts as `P[i] = D_k(C[i]) xor C[i-1]` and the attacker owns `C[i-1]`. If the
server tells you whether the final PKCS#7 padding was well-formed, you can search
byte-by-byte for the `C[i-1]` values that produce padding `0x01`, `0x02 0x02`, ... and
solve for the *intermediate* `I[i] = D_k(C[i])`. With `I[i]` you get the plaintext
(`I[i] xor C[i-1]`) and, running the chain backwards, you can build a ciphertext that
decrypts to any plaintext you choose - without ever learning the key.

## Recognise it

- A `try: unpad(...) except: return "bad padding"` in provided source.
- Two distinguishable responses: HTTP 500 vs 200, `"Invalid padding"` vs `"Invalid MAC"`,
  a different body length, or a measurable timing gap (padding fails early).
- A base64/hex cookie of length `16 * (n+1)` where the first 16 bytes are an IV.
- MAC-then-encrypt (the TLS 1.0 order) rather than encrypt-then-MAC - the classic
  precondition for POODLE / Vaudenay / Lucky13.
- CBC mode plus any error channel at all. It does not have to say "padding".

## Theory

PKCS#7: a plaintext is padded with `n` copies of the byte `n`, `1 <= n <= 16`. A block
of 16 data bytes gets a whole extra block of `\x10`.

Take a two-block ciphertext `R || C` where `R` is 16 bytes you choose. The server
computes `P = D_k(C) xor R = I xor R` and checks the padding of `P`.

Set `R = [r0..r14, g]`. `P[15] = I[15] xor g`. Walk `g` from 0 to 255; when the server
says the padding is valid, almost certainly `P[15] == 0x01`, so

$$I[15] = g \oplus 0x01$$

**The 0x01/0x02 ambiguity.** `P` could instead end in `0x02 0x02` (or `03 03 03`...)
if `P[14]` happened to be `0x02`. Disambiguate by flipping `R[14]` and re-querying: if
the padding is still valid, the last byte really was `0x01`; if it breaks, you hit a
longer pad and must keep searching. Skipping this check is the single most common
reason a hand-rolled padding oracle "works 15 times out of 16".

Knowing `I[15]`, set `R[15] = I[15] xor 0x02` so `P[15] == 0x02` is forced, then search
`R[14]` for valid padding - that gives `P[14] == 0x02` and hence `I[14]`. Continue for
pad values `0x03 ... 0x10`.

At the end `I = D_k(C)` is fully known, and `P_real = I xor C_prev` where `C_prev` is
the real preceding block (or the real IV for block 0).

**CBC-R - encryption without the key.** `I = D_k(C)` for a `C` of your choosing is an
encryption primitive in reverse. To build a ciphertext for target plaintext
`T[1..n]`:

1. Pick `C[n]` at random. Oracle-solve `I[n] = D_k(C[n])`.
2. `C[n-1] = I[n] xor T[n]`.
3. Oracle-solve `I[n-1] = D_k(C[n-1])`, then `C[n-2] = I[n-1] xor T[n-1]`.
4. ... down to `IV = I[1] xor T[1]`.

Remember to PKCS#7-pad `T` first, or the server will reject your own forgery.

Cost: at most `256 * 16 = 4096` queries per block, `~2048` on average, `~128 * 16` if
you are lucky with the byte distribution.

## Attack

1. Confirm the oracle: take a valid ciphertext, flip the last byte of the
   second-to-last block, and check you get the "bad padding" answer.
2. Split `iv || ct` into blocks.
3. For each block `C[i]` (from 1 to n), run `decrypt_block` to get `I[i]`.
4. `P[i] = I[i] xor C[i-1]`.
5. Unpad and read the flag.
6. For forgery, run CBC-R with the padded target plaintext.

## Code

```python
#!/usr/bin/env python3
"""Generic AES-CBC padding oracle: full decryption and CBC-R forgery.

`oracle(ct)` must take a full `iv || body` ciphertext and return True iff the PKCS#7
padding of the decryption is valid. Nothing else about the server is assumed.

Self-test builds the vulnerable service locally with a random key and asserts both
the decryption and the forgery succeed.
"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BS = 16


# ----------------------------------------------------------------- helpers
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def blocks(data: bytes, bs: int = BS) -> list[bytes]:
    return [data[i:i + bs] for i in range(0, len(data), bs)]


# ------------------------------------------------------- the core primitive
def recover_intermediate(oracle, block: bytes, bs: int = BS) -> bytes:
    """Recover I = D_k(block) using only a valid/invalid-padding oracle."""
    inter = bytearray(bs)
    for padval in range(1, bs + 1):
        pos = bs - padval
        tail = bytes(inter[i] ^ padval for i in range(pos + 1, bs))
        found = None
        for guess in range(256):
            forged = bytearray(os.urandom(pos)) + bytes([guess]) + tail
            if not oracle(bytes(forged) + block):
                continue
            if padval == 1:
                # Disambiguate 0x01 from a longer accidental pad (0x02 0x02, ...).
                probe = bytearray(forged)
                probe[pos - 1] ^= 0xFF
                if not oracle(bytes(probe) + block):
                    continue
            found = guess
            break
        if found is None:
            raise RuntimeError(f"no valid padding byte found at pad value {padval}")
        inter[pos] = found ^ padval
    return bytes(inter)


def padding_oracle_decrypt(ct: bytes, oracle, bs: int = BS, strip: bool = True) -> bytes:
    """Decrypt a full `iv || body` ciphertext. Returns the plaintext."""
    bl = blocks(ct, bs)
    assert len(bl) >= 2, "need at least iv + one block"
    out = b""
    for i in range(1, len(bl)):
        inter = recover_intermediate(oracle, bl[i], bs)
        out += xor(inter, bl[i - 1])
    return unpad(out, bs) if strip else out


def padding_oracle_encrypt(target: bytes, oracle, bs: int = BS) -> bytes:
    """CBC-R: build `iv || body` that decrypts to `target`, without the key."""
    pt = pad(target, bs)
    chunks = blocks(pt, bs)
    cur = os.urandom(bs)                 # arbitrary final ciphertext block
    out = [cur]
    for chunk in reversed(chunks):
        inter = recover_intermediate(oracle, cur, bs)
        cur = xor(inter, chunk)
        out.insert(0, cur)
    return b"".join(out)                 # out[0] is the IV


# --------------------------------------------------------- vulnerable service
class VulnerableService:
    """Decrypts and reports padding validity -- the whole bug in three lines."""

    def __init__(self, secret: bytes) -> None:
        self.key = os.urandom(16)
        self.secret = secret
        self.queries = 0

    def token(self) -> bytes:
        iv = os.urandom(BS)
        return iv + AES.new(self.key, AES.MODE_CBC, iv).encrypt(pad(self.secret, BS))

    def oracle(self, ct: bytes) -> bool:
        self.queries += 1
        iv, body = ct[:BS], ct[BS:]
        pt = AES.new(self.key, AES.MODE_CBC, iv).decrypt(body)
        try:
            unpad(pt, BS)
            return True
        except ValueError:
            return False

    def consume(self, ct: bytes) -> bytes:
        """What a real endpoint does once padding checks out."""
        iv, body = ct[:BS], ct[BS:]
        return unpad(AES.new(self.key, AES.MODE_CBC, iv).decrypt(body), BS)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    SECRET = b"user=guest;role=user;flag=flag{padding_oracles_decrypt_and_encrypt}"

    svc = VulnerableService(SECRET)
    ct = svc.token()

    # --- confirm the oracle actually discriminates -------------------------
    assert svc.oracle(ct) is True
    broken = bytearray(ct)
    broken[-BS - 1] ^= 0xFF          # corrupt the last plaintext byte
    assert svc.oracle(bytes(broken)) is False
    print("[+] oracle confirmed: valid vs invalid padding are distinguishable")

    # --- full decryption ---------------------------------------------------
    svc.queries = 0
    recovered = padding_oracle_decrypt(ct, svc.oracle)
    print("[+] recovered:", recovered.decode())
    print(f"[+] {svc.queries} oracle queries for {len(ct) - BS} ciphertext bytes")
    assert recovered == SECRET, recovered
    print("[+] PASS decryption")

    # --- forgery (CBC-R) ---------------------------------------------------
    TARGET = b"user=admin;role=admin;flag=nope"
    svc.queries = 0
    forged = padding_oracle_encrypt(TARGET, svc.oracle)
    assert svc.oracle(forged), "our own forgery must have valid padding"
    got = svc.consume(forged)
    print("[+] forged token decrypts to:", got.decode())
    print(f"[+] {svc.queries} oracle queries to mint it")
    assert got == TARGET, got
    print("[+] PASS CBC-R forgery")

    # --- forgery of a multi-block, block-aligned plaintext ------------------
    TARGET2 = b"A" * 32                     # exactly 2 blocks -> a full pad block
    forged2 = padding_oracle_encrypt(TARGET2, svc.oracle)
    assert svc.consume(forged2) == TARGET2
    print("[+] PASS CBC-R forgery of a block-aligned plaintext")

    print("\nall checks passed")
```

## Variants & pitfalls

- **Do not skip the 0x01 disambiguation.** Without it, roughly one block in sixteen
  gives you a wrong final byte and the rest of the block goes wrong with it.
- **Block 0 needs the IV.** If the IV is not transmitted, you can still recover
  `I[1] = D_k(C[1])` but not `P[1]`, because `P[1] = I[1] xor IV`. If key == IV, see
  `aes-cbc-iv-recovery`.
- **Last-block-only oracles.** Some servers only check padding on the final block. The
  attack is unchanged - you always submit a 2-block ciphertext `R || C[i]`, so `C[i]`
  is always the final block.
- **Timing-only oracles (Lucky13 style).** Same algorithm, but `oracle()` becomes a
  statistical test: send each candidate `N` times and compare medians. Slow but real.
- **Non-PKCS#7 padding.** ANSI X.923 (`00 00 ... n`) and ISO 7816-4 (`80 00 ... 00`)
  give a padding oracle too, with a different byte search. Zero padding is weaker as
  an oracle because many plaintexts are "valid".
- **Response length as the oracle.** When both branches return HTTP 500, diff the body
  length, the `Set-Cookie` presence, or the redirect target.
- **Rate limits.** 4096 queries per block adds up. Parallelise across blocks - each
  block is independent - and cache.
- **POODLE** is the SSLv3 variant where the last block's padding is not checked
  byte-by-byte, leaking one byte per ~256 connections.
- **The fix is encrypt-then-MAC** (or an AEAD). If the server verifies an HMAC over
  the ciphertext before decrypting, there is no oracle.

## Tools

- `padbuster -u <url> -e <ciphertext> -b <blocksize> -c <cookie>` - the classic
  automated padding-oracle tool; `-plaintext` switches it into CBC-R forgery mode.
- `pycryptodome` for local reproduction.
- `pwntools` / `requests` to wrap a remote endpoint into an `oracle(ct) -> bool`.
- Burp Suite Repeater to find the distinguishing response before you script anything.

## References

- Cryptopals Set 3, challenge 17 ("The CBC padding oracle"):
  <https://cryptopals.com/sets/3>
- Serge Vaudenay, "Security Flaws Induced by CBC Padding" (EUROCRYPT 2002) - the
  original result.
