---
title: "CBC-MAC - Length-Extension Forgery, and CBC-MAC vs CMAC"
category: crypto
subcategory: mac
type: technique
tags: [cbc-mac, mac, mac-forgery, length-extension, cmac, omac1, ecbc-mac, aes, cbc, chosen-iv, existential-forgery, key-reuse, xor, iv, pycryptodome, cryptopals, integrity, authentication]
difficulty: medium
summary: "Raw CBC-MAC with a zero IV is only secure for fixed-length messages: two known tags splice into a valid tag for a third, never-queried message."
when_to_use:
  - "A MAC is computed as the last block of an AES-CBC encryption with IV = 0"
  - "Messages of varying length share one CBC-MAC key with no length prefix"
  - "The verifier lets you supply the IV alongside the message and tag"
  - "The same AES key is used both to encrypt (CBC) and to authenticate (CBC-MAC)"
  - "You need to forge a tag for a message the oracle will never sign for you"
tools: [pycryptodome]
source:
  name: "Cryptopals Set 7"
  url: "https://cryptopals.com/sets/7"
related: [aes-cbc-bit-flipping, hash-length-extension, aes-cbc-padding-oracle, aes-gcm-nonce-reuse-forbidden, hash-hmac-timing-attack]
---

## TL;DR

`CBC-MAC_k(m)` is "encrypt `m` in CBC mode with `IV = 0` and keep the last ciphertext
block". That is a secure PRF only over messages of one fixed length. Given
`t1 = MAC(m1)` and `t2 = MAC(m2)`, the message

```
m3 = m1 || (m2[0:16] xor t1) || m2[16:]
```

has `MAC(m3) == t2`, because the chaining value entering `m2`'s first block is
restored to zero. One query each and you own a message you never asked about. CMAC
(OMAC1) fixes this by xoring a key-derived constant into the final block.

## Recognise it

- `def mac(key, m): return AES.new(key, AES.MODE_CBC, b"\x00"*16).encrypt(m)[-16:]`.
- A protocol that sends `message || tag` where the tag is 16 bytes and the message is
  a multiple of 16.
- The verifier accepts an attacker-supplied IV: `verify(msg, iv, tag)`.
- The same key object used for both `AES.MODE_CBC` encryption and the MAC.
- No `hmac`, no `CMAC.new(...)`, no length field at the front of the message.

## Theory

CBC-MAC over blocks `m_1 ... m_n` with `IV = 0`:

$$c_0 = 0,\qquad c_i = E_k(m_i \oplus c_{i-1}),\qquad t = c_n$$

**Splicing forgery.** Suppose `t1 = MAC(m1)` and `t2 = MAC(m2)`. Feed `m1` first; the
chaining value after it is exactly `t1`. Now feed the block `m2[0] xor t1`:

$$E_k\big((m_2[0] \oplus t_1) \oplus t_1\big) = E_k(m_2[0])$$

which is precisely the first step of `MAC(m2)` with a zero IV. Everything after that
is identical, so the final tag is `t2`. Cost: two oracle queries, zero work.

**Chosen-IV forgery.** If the IV travels with the message, a *single* valid pair
`(m, iv, t)` gives you unlimited forgeries:

$$iv' = iv \oplus m[0] \oplus m'[0]$$

makes `(m', iv', t)` verify, because `m'[0] xor iv' = m[0] xor iv`. Only the first
block can be rewritten this way, but that is normally enough (`amount=`, `from=`).

**Key reuse with encryption.** If the same key encrypts in CBC mode, an encryption
oracle *is* a MAC oracle: `CBC-MAC_k(m) = E_{CBC,k,IV=0}(m)[-16:]`. Conversely, a MAC
oracle lets you compute an intermediate CBC block, which is the building block of a
chosen-ciphertext attack. Never reuse a key across primitives.

**Why CMAC is safe.** CMAC derives two subkeys `K1 = 2*L`, `K2 = 4*L` from
`L = E_k(0)` in `GF(2^128)`, and xors `K1` (complete final block) or `K2` (padded
final block) into the last block before the final encryption. The splice fails
because the last block of `m3` is processed with the same constant but the *prefix*
now contains an extra block, and more importantly the constant is unknown to the
attacker. CMAC is provably secure for variable-length messages.

Other fixes: prepend the length as the first block (`len(m) || m`), use ECBC-MAC /
EMAC (encrypt the final tag with a second key), or just use HMAC.

## Attack

1. Get `t1 = MAC(m1)` for a message you are allowed to sign (often a harmless prefix).
2. Get `t2 = MAC(m2)` where `m2` is the message you actually want authenticated, or
   any message whose tag you want to transplant.
3. Build `m3 = m1 || (m2[0] xor t1) || m2[16:]` and claim its tag is `t2`.
4. If the target parser ignores or tolerates the junk block, you are done. If not,
   choose `m1` so the junk lands inside a comment field, a padding field, or after a
   `#` / `//` / `;`. JSON, `k=v&k=v` and length-prefixed binary formats all have
   places to hide 16 bytes.

For the chosen-IV variant, a single pair suffices and there is no junk block at all.

## Code

```python
#!/usr/bin/env python3
"""CBC-MAC forgeries: two-message splicing, chosen-IV rewrite, and key reuse
between CBC encryption and CBC-MAC. Shows CMAC resisting the same attacks.

Self-contained; every forgery is verified against the real verifier.
"""

import os
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad

BS = 16


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------- the MAC
def cbc_mac(key: bytes, msg: bytes, iv: bytes = b"\x00" * BS) -> bytes:
    """Raw CBC-MAC: last ciphertext block of a CBC encryption."""
    assert len(msg) % BS == 0, "raw CBC-MAC takes whole blocks"
    return AES.new(key, AES.MODE_CBC, iv).encrypt(msg)[-BS:]


def cbc_mac_length_prefixed(key: bytes, msg: bytes) -> bytes:
    """The standard fix: bind the length by making it the first block."""
    header = len(msg).to_bytes(BS, "big")
    return cbc_mac(key, header + pad(msg, BS))


# ------------------------------------------------------- vulnerable service
class Server:
    """Signs anything, verifies anything. Zero IV, no length binding."""

    def __init__(self) -> None:
        self.key = os.urandom(16)
        self.signed: set[bytes] = set()

    def sign(self, msg: bytes) -> bytes:
        self.signed.add(msg)
        return cbc_mac(self.key, msg)

    def verify(self, msg: bytes, tag: bytes) -> bool:
        return cbc_mac(self.key, msg) == tag

    # --- the chosen-IV variant --------------------------------------------
    def sign_iv(self, msg: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(BS)
        return iv, cbc_mac(self.key, msg, iv)

    def verify_iv(self, msg: bytes, iv: bytes, tag: bytes) -> bool:
        return cbc_mac(self.key, msg, iv) == tag

    # --- the key-reuse variant --------------------------------------------
    def encrypt(self, msg: bytes, iv: bytes) -> bytes:
        """Same key as the MAC. This single method is a full MAC oracle."""
        return AES.new(self.key, AES.MODE_CBC, iv).encrypt(pad(msg, BS))


# ------------------------------------------------------------- the attacks
def splice_forgery(m1: bytes, t1: bytes, m2: bytes) -> bytes:
    """Message whose CBC-MAC equals MAC(m2), built from MAC(m1) = t1."""
    assert len(m1) % BS == 0 and len(m2) % BS == 0 and len(m2) >= BS
    return m1 + xor(m2[:BS], t1) + m2[BS:]


def chosen_iv_forgery(m: bytes, iv: bytes, m_new: bytes) -> bytes:
    """IV that makes (m_new, iv', t) verify under the tag t of (m, iv)."""
    assert len(m_new) == len(m)
    return xor(iv, xor(m[:BS], m_new[:BS]))


def mac_from_encryption_oracle(encrypt, msg: bytes) -> bytes:
    """CBC-MAC(msg) = last block of CBC-encrypt(msg) with IV = 0."""
    return encrypt(msg, b"\x00" * BS)[-BS:]


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    srv = Server()

    # --- 1. two-message splicing forgery -----------------------------------
    # A message the server is happy to sign (a "harmless" transfer).
    m1 = pad(b"from=alice&to=bob&amount=1", BS)
    t1 = srv.sign(m1)

    # The payload we want authenticated. The server signs it for a different
    # account, but we will transplant its tag onto a longer message.
    m2 = pad(b"from=victim&to=attacker&amount=1000000", BS)
    t2 = srv.sign(m2)

    m3 = splice_forgery(m1, t1, m2)
    assert m3 not in srv.signed, "m3 was never signed by the server"
    assert srv.verify(m3, t2), "splice failed"
    print("[+] forged message:", m3)
    print("[+] reusing tag   :", t2.hex())
    print("[+] PASS splicing forgery (never-signed message verifies)")
    # ...and the payload is present verbatim in the forged message
    assert b"amount=1000000" in m3

    # --- 2. length-extension flavour of the same bug -----------------------
    # Given only MAC(m), append anything at all.
    m = pad(b"role=user", BS)
    t = srv.sign(m)
    suffix = pad(b"&role=admin", BS)
    extended = m + xor(suffix[:BS], t) + suffix[BS:]
    assert srv.verify(extended, srv.sign(suffix))
    print("[+] PASS length extension onto an existing tag")

    # --- 3. chosen-IV forgery ---------------------------------------------
    # Only the FIRST block may be rewritten, so keep block 1 identical.
    orig = b"amount=000000001" b"to=bob;memo=none"
    iv, tag = srv.sign_iv(orig)
    assert srv.verify_iv(orig, iv, tag)

    evil = b"amount=999999999" b"to=bob;memo=none"
    iv2 = chosen_iv_forgery(orig, iv, evil)
    assert srv.verify_iv(evil, iv2, tag), "chosen-IV forgery failed"
    print("[+] rewritten first block:", evil[:BS])
    print("[+] PASS chosen-IV forgery (same tag, new message)")

    # --- 4. key reuse between CBC encryption and CBC-MAC -------------------
    target = b"cmd=rm -rf /;auth=yes"            # the oracle pads it for us
    forged_tag = mac_from_encryption_oracle(srv.encrypt, target)
    assert srv.verify(pad(target, BS), forged_tag)
    print("[+] PASS encryption oracle used as a MAC oracle")

    # --- 5. the length-prefixed fix resists the splice ---------------------
    key = os.urandom(16)
    a = b"A" * BS
    b = b"B" * BS
    ta = cbc_mac_length_prefixed(key, a)
    tb = cbc_mac_length_prefixed(key, b)
    spliced = splice_forgery(a, ta, b)
    assert cbc_mac_length_prefixed(key, spliced) != tb
    print("[+] PASS length-prefixed CBC-MAC rejects the splice")

    # --- 6. CMAC resists it too -------------------------------------------
    def cmac(k: bytes, msg: bytes) -> bytes:
        return CMAC.new(k, msg, ciphermod=AES).digest()

    ca, cb = cmac(key, a), cmac(key, b)
    assert cmac(key, splice_forgery(a, ca, b)) != cb
    print("[+] PASS CMAC rejects the splice")

    # CMAC also handles arbitrary lengths natively; raw CBC-MAC cannot.
    assert len(cmac(key, b"not a multiple of sixteen bytes at all")) == 16
    try:
        cbc_mac(key, b"short")
        raise SystemExit("raw CBC-MAC should have refused a partial block")
    except AssertionError:
        print("[+] raw CBC-MAC only accepts whole blocks, as expected")

    print("\nall checks passed")
```

## Variants & pitfalls

- **The junk block.** The splice inserts 16 unreadable bytes at the seam. Pick `m1`
  ending in a field the parser skips: a trailing comment, a `padding=` field, a
  base64 blob, or a length-prefixed record whose length you control.
- **`m2` must be at least one block.** And both messages must be block-aligned; if the
  scheme pads before MACing, forge on the *padded* messages.
- **Two MAC oracles are not always available.** If you can only sign `m1`, you can
  still do *length extension*: `MAC(m1 || (x xor t1) || ...)` is computable for any
  suffix once you can sign the suffix, and with a single tag you can at least append a
  block whose MAC you can predict if you also have an encryption oracle.
- **Truncated tags.** Some protocols keep only 8 bytes. The forgery is unaffected -
  the full chaining value still matches.
- **CBC-MAC over a *fixed* length is fine.** If every message is exactly 3 blocks and
  the verifier enforces that, the splice produces a 7-block message and is rejected.
  Check the length validation before assuming the bug is live.
- **Do not confuse this with `hash-length-extension`.** That one extends a
  Merkle-Damgard hash of `secret || data`; this one splices two block-cipher MACs.
  Similar smell, different algebra.
- **CMAC subkey generation** uses `GF(2^128)` doubling. If a challenge hands you
  `L = E_k(0)` you can derive `K1` and `K2`, which is occasionally the intended path
  in "implement CMAC yourself" tasks - but it does not break CMAC.
- **The right answer is always HMAC or an AEAD.** `hmac.new(key, msg, sha256)` with
  `hmac.compare_digest` for verification.

## Tools

- `pycryptodome` - `Crypto.Hash.CMAC`, `Crypto.Cipher.AES`.
- Python stdlib `hmac` for the secure alternative.

## References

- Cryptopals Set 7, challenges 49 and 50 (CBC-MAC message forgery and hash collisions):
  <https://cryptopals.com/sets/7>
- NIST SP 800-38B specifies CMAC and the `K1`/`K2` subkey derivation.
