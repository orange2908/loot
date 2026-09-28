---
title: "AES-CBC - IV Recovery and the key==IV Attack"
category: crypto
subcategory: cbc
type: technique
tags: [aes, cbc, iv, iv-recovery, key-equals-iv, key-as-iv, chosen-ciphertext, error-oracle, plaintext-leak, xor, cryptopals, pycryptodome, ascii-check, exception-leak, block-cipher]
difficulty: medium
summary: "When AES-CBC uses the key as the IV, submitting C1 || 0 || C1 to an endpoint that leaks the decrypted bytes hands you the key as P1 xor P3."
when_to_use:
  - "Source shows `AES.new(key, AES.MODE_CBC, key)` or `iv = key[:16]`"
  - "An endpoint decrypts your ciphertext and echoes the plaintext back in an error message"
  - "The server rejects non-ASCII / non-printable plaintext and prints what it saw"
  - "The IV is fixed and secret and you want to read plaintext block 0"
  - "You know plaintext block 0 and the key, and need the IV that was used"
tools: [pycryptodome, pwntools]
source:
  name: "Cryptopals Set 4"
  url: "https://cryptopals.com/sets/4"
related: [aes-cbc-bit-flipping, aes-cbc-padding-oracle, aes-ecb-cut-and-paste, block-cbc-mac-forgery]
---

## TL;DR

CBC needs an IV. Lazy implementations reuse the key for it (`AES.new(key, MODE_CBC, key)`).
Because `P[0] = D_k(C[0]) xor IV`, anything that leaks `P[0]` leaks `IV`, and when
`IV == key` that is total compromise. The standard construction is to submit
`C1 || 0^16 || C1` and read `key = P1 xor P3` off the leaked plaintext.

## Recognise it

- `AES.new(key, AES.MODE_CBC, key)`, `iv = key`, `iv = key[:16]`, `iv = sha256(key)[:16]`
  where the same value also derives the key.
- A `decrypt` endpoint that raises and includes the offending bytes:
  `raise ValueError(f"Invalid message: {pt}")`, `return {"error": pt.hex()}`,
  `if not pt.isascii(): print(pt)`.
- No IV in the transmitted token - the token is exactly `16 * n` bytes, not `16 * (n+1)`.
- A "high-ASCII" / "non-printable" / "invalid UTF-8" complaint from the server.

## Theory

CBC decryption:

$$P[0] = D_k(C[0]) \oplus IV,\qquad P[i] = D_k(C[i]) \oplus C[i-1]\ (i \ge 1)$$

Now feed the server a ciphertext you built yourself:

$$C' = C_1 \,\|\, \mathbf{0}^{16} \,\|\, C_1$$

where `C_1` is any block (reuse the first block of a real token). The server computes

$$P'_1 = D_k(C_1) \oplus IV$$
$$P'_2 = D_k(\mathbf{0}^{16}) \oplus C_1$$
$$P'_3 = D_k(C_1) \oplus \mathbf{0}^{16} = D_k(C_1)$$

and therefore

$$P'_1 \oplus P'_3 = IV$$

The middle zero block exists only to make sure `P'_3`'s chaining value is zero; it also
guarantees `P'_2` is garbage, which is usually what trips the "non-ASCII" check and
makes the server print the plaintext in the first place.

If `IV == key`, you now have the key and can decrypt everything offline.

**Other IV-recovery situations.**

- *Known `P[0]`, known key, unknown IV*: `IV = D_k(C[0]) xor P[0]`. One line.
- *Known `P[0]`, unknown key, padding oracle*: recover `I[0] = D_k(C[0])` with the
  padding oracle (`aes-cbc-padding-oracle`), then `IV = I[0] xor P[0]`.
- *Fixed secret IV, many messages*: every message's first block is masked by the same
  IV, so `P[0] xor P'[0] = C_prev... ` no chaining applies - but
  `P[0] xor P'[0] = D_k(C[0]) xor D_k(C'[0])`, which is not directly useful. Get one
  known `P[0]` instead and you have the IV forever.

## Attack

1. Obtain any valid ciphertext, or just make up a random `C_1`.
2. Build `C' = C_1 || 0^16 || C_1`. Do not append padding - the server will fail the
   padding or the ASCII check, which is exactly what you want.
3. Send it to the decrypt endpoint. Capture the leaked plaintext `P'` (all 48 bytes).
4. `key = P'[0:16] xor P'[32:48]`.
5. Verify: decrypt the original token with `AES.new(key, MODE_CBC, key)` and check it
   parses.

## Code

```python
#!/usr/bin/env python3
"""AES-CBC with key == IV: recover the key from a plaintext-leaking error oracle.

Also covers plain IV recovery when the key and one plaintext block are known.
Self-test builds the vulnerable service locally and asserts the key comes back.
"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BS = 16


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class AsciiComplaintError(Exception):
    """Server error that helpfully includes the plaintext it could not parse."""

    def __init__(self, plaintext: bytes) -> None:
        super().__init__(f"Invalid message (non-ASCII): {plaintext!r}")
        self.plaintext = plaintext


# --------------------------------------------------------- vulnerable service
class Service:
    """Uses the key as the IV and echoes plaintext it does not like."""

    def __init__(self) -> None:
        self.key = os.urandom(16)

    def token(self, payload: bytes = b"comment=hello;role=user;id=0001") -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.key)   # <-- the bug
        return cipher.encrypt(pad(payload, BS))

    def consume(self, ct: bytes) -> bytes:
        pt = AES.new(self.key, AES.MODE_CBC, self.key).decrypt(ct)
        if any(b > 0x7F for b in pt):
            raise AsciiComplaintError(pt)                     # <-- the leak
        return unpad(pt, BS)


# ------------------------------------------------------------------- attack
def recover_key_from_iv_leak(oracle, sample_block: bytes, bs: int = BS) -> bytes:
    """Submit C1 || 0 || C1; the leaked plaintext gives key == IV as P1 xor P3.

    `oracle(ct)` must either return the plaintext or raise an exception carrying it
    in a `.plaintext` attribute.
    """
    crafted = sample_block + bytes(bs) + sample_block
    try:
        leaked = oracle(crafted)
    except AsciiComplaintError as exc:
        leaked = exc.plaintext
    if len(leaked) < 3 * bs:
        raise RuntimeError("oracle did not leak all three blocks")
    return xor(leaked[0:bs], leaked[2 * bs:3 * bs])


def recover_iv_known_key(key: bytes, ct_block0: bytes, pt_block0: bytes) -> bytes:
    """IV = D_k(C[0]) xor P[0]. Needs the key and one known plaintext block."""
    d = AES.new(key, AES.MODE_ECB).decrypt(ct_block0)
    return xor(d, pt_block0)


def recover_iv_from_intermediate(intermediate0: bytes, pt_block0: bytes) -> bytes:
    """IV = I[0] xor P[0], where I[0] = D_k(C[0]) came from a padding oracle."""
    return xor(intermediate0, pt_block0)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    svc = Service()

    # A normal round trip works and reveals nothing.
    tok = svc.token()
    assert svc.consume(tok) == b"comment=hello;role=user;id=0001"
    print("[+] normal token round-trips fine")

    # --- key == IV recovery ------------------------------------------------
    key = recover_key_from_iv_leak(svc.consume, tok[:BS])
    print("[+] recovered key:", key.hex())
    assert key == svc.key, (key.hex(), svc.key.hex())
    print("[+] PASS key == IV recovery")

    # Prove it: decrypt the original token offline.
    offline = unpad(AES.new(key, AES.MODE_CBC, key).decrypt(tok), BS)
    print("[+] offline decryption:", offline.decode())
    assert offline == b"comment=hello;role=user;id=0001"
    print("[+] PASS offline decryption with the recovered key")

    # ...and mint a token the server accepts.
    forged = AES.new(key, AES.MODE_CBC, key).encrypt(pad(b"role=admin;id=0000", BS))
    assert svc.consume(forged) == b"role=admin;id=0000"
    print("[+] PASS forged token accepted")

    # --- plain IV recovery, key known --------------------------------------
    k2 = os.urandom(16)
    iv2 = os.urandom(16)
    p2 = pad(b"BLOCKZERO-KNOWN!" b"and some more...", BS)
    c2 = AES.new(k2, AES.MODE_CBC, iv2).encrypt(p2)
    got_iv = recover_iv_known_key(k2, c2[:BS], p2[:BS])
    assert got_iv == iv2, (got_iv.hex(), iv2.hex())
    print("[+] PASS IV recovery from key + known plaintext block 0")

    # --- IV recovery from a padding-oracle intermediate --------------------
    inter0 = AES.new(k2, AES.MODE_ECB).decrypt(c2[:BS])   # what a padding oracle gives
    assert recover_iv_from_intermediate(inter0, p2[:BS]) == iv2
    print("[+] PASS IV recovery from a padding-oracle intermediate")

    # --- the same trick when only the IV (not the key) is secret -----------
    # A fixed secret IV leaks as soon as one first block is known.
    secret_iv = os.urandom(16)
    k3 = os.urandom(16)
    msg = pad(b"Content-Type: t" b"ext/plain......", BS)
    c3 = AES.new(k3, AES.MODE_CBC, secret_iv).encrypt(msg)
    assert recover_iv_known_key(k3, c3[:BS], msg[:BS]) == secret_iv
    print("[+] PASS fixed secret IV recovered from a known header")

    print("\nall checks passed")
```

## Variants & pitfalls

- **The leak does not have to be an exception.** A server that returns the decrypted
  bytes hex-encoded in a 400 response, logs them, or reflects them into an HTML error
  page works just as well. Anything that shows you all three plaintext blocks.
- **Only the first block is echoed.** Then you cannot compute `P1 xor P3` in one shot.
  Send `C_1 || 0^16 || C_1` twice with the blocks rotated, or use a padding oracle to
  get `D_k(C_1)` directly and xor it with the leaked `P'[0]`.
- **Padding.** The server usually unpads *after* the ASCII check, so a padding failure
  is fine. If it unpads first and never reaches the leak, append a block whose
  plaintext you control well enough to end in `\x10 * 16`, or just try many random
  `C_1` until one produces valid padding (1 in 256 on the last byte).
- **`iv = key[:16]` with a 32-byte key** still leaks the first half of an AES-256 key.
  Combine with any other leak, or brute-force the remaining 16 bytes only if the
  challenge made them low-entropy.
- **`iv = md5(key)` style derivations** do not help you directly, but they do mean the
  IV is *fixed*, so a single known first block deanonymises every message ever sent.
- **Do not send a padded `C'`.** The crafted ciphertext must be exactly three raw
  blocks; adding a padding block changes which blocks appear where.
- The fix: generate a fresh random IV per message and transmit it, or use an AEAD.

## Tools

- `pycryptodome` for reproduction.
- `pwntools` to script the remote error channel.

## References

- Cryptopals Set 4, challenge 27 ("Recover the key from CBC with IV=Key"):
  <https://cryptopals.com/sets/4>
