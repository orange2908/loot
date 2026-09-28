---
title: "AES-CBC - Bit-Flipping Attack"
category: crypto
subcategory: cbc
type: technique
tags: [aes, cbc, bit-flipping, bitflip, malleability, xor, iv, chosen-ciphertext, cookie-forgery, admin-true, sacrificial-block, cryptopals, pycryptodome, integrity, unauthenticated-encryption]
difficulty: easy
summary: "CBC decryption xors the previous ciphertext block into the plaintext, so flipping a bit in C[i-1] flips the same bit in P[i] at the cost of destroying P[i-1]."
when_to_use:
  - "A cookie, token or session blob is AES-CBC encrypted with no MAC or signature"
  - "You know (or control) the plaintext of one block and want to change it"
  - "The target string is `;admin=true;`, `role=admin`, `isAdmin=1`, `user_id=1`, `amount=0001`"
  - "The IV is sent with the ciphertext and you want to change the very first block"
  - "There is a second block you can afford to turn into garbage"
tools: [pycryptodome, cyberchef, openssl]
source:
  name: "Cryptopals Set 2"
  url: "https://cryptopals.com/sets/2"
related: [aes-cbc-padding-oracle, aes-cbc-iv-recovery, aes-ecb-cut-and-paste, aes-ctr-nonce-reuse, block-cbc-mac-forgery]
---

## TL;DR

CBC decryption is `P[i] = D_k(C[i]) xor C[i-1]` (with `C[-1] = IV`). The attacker owns
`C[i-1]` and xor is linear, so `C[i-1] ^= delta` makes `P[i] ^= delta` exactly. You get
a perfectly controlled edit of block `i` and, as the price, block `i-1` turns into
16 bytes of unpredictable garbage. Encryption without authentication is malleable.

## Recognise it

- `AES.new(key, AES.MODE_CBC, iv)` with no HMAC, no GCM, no `Signature` field.
- A session cookie that is base64 and `16 * n` bytes, often with the IV as the first
  16 bytes.
- The server decrypts the cookie and parses `k=v;k=v` or JSON out of it, and it does
  not care about a corrupted block (it strips non-printables, or the garbage lands in
  a field it ignores like `comment2`).
- Source filters `;` and `=` out of your input - that filter runs on the plaintext you
  submit, which is not where you are injecting.

## Theory

Encryption:

$$C[i] = E_k(P[i] \oplus C[i-1]), \qquad C[-1] = IV$$

Decryption:

$$P[i] = D_k(C[i]) \oplus C[i-1]$$

`D_k(C[i])` does not depend on `C[i-1]` at all. So if you replace `C[i-1]` with
`C[i-1] xor delta`, block `i` decrypts to `P[i] xor delta` and every other block
except `i-1` is untouched. Block `i-1` becomes `D_k(C[i-1] xor delta) xor C[i-2]`,
which is effectively random.

To turn a known `P[i] = known` into a chosen `desired`, set

$$\delta = known \oplus desired$$

If you want to edit the **first** block, use the IV: `IV' = IV xor known xor desired`.
This costs nothing - there is no block before block 0 to sacrifice - which is why an
attacker-supplied IV is worse than it looks.

## Attack

Target: `comment1=cooking%20MCs;userdata=` + your input (with `;` and `=` escaped) +
`;comment2=%20like%20a%20pound%20of%20bacon`, AES-CBC encrypted. Goal: `;admin=true;`
in the decrypted plaintext.

1. Work out the prefix length (here 32 bytes = 2 blocks). If unknown, submit two
   inputs differing in one byte and find the first ciphertext block that changes.
2. Submit 32 bytes of filler, e.g. `b"A" * 32`. Block 2 is the sacrifice, block 3 is
   the block you will rewrite.
3. Compute `delta = b"A"*16 xor b";admin=true;AAAA"` and xor it into ciphertext block 2.
4. Send the modified ciphertext. Block 2 decrypts to junk; block 3 decrypts to
   `;admin=true;AAAA`. The `k=v;` parser sees `admin=true`.

If the parser chokes on the garbage block, pick a sacrifice block whose plaintext lands
in a field that is ignored, or one that is already junk (a nonce, a timestamp you do
not care about, base64 slack).

## Code

```python
#!/usr/bin/env python3
"""AES-CBC bit-flipping: rewrite a chosen plaintext block by xoring the previous
ciphertext block, and rewrite block 0 through the IV.

Self-contained: builds the vulnerable cookie service locally and asserts admin=true.
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


def cbc_bitflip(ct: bytes, block_index: int, known: bytes, desired: bytes,
                bs: int = BS) -> bytes:
    """Make plaintext block `block_index` decrypt to `desired` instead of `known`.

    `block_index` is 1-based against the ciphertext body (block 0 needs the IV form
    below). Block `block_index - 1` of the plaintext is destroyed.
    """
    assert len(known) == len(desired) <= bs
    assert block_index >= 1, "use cbc_bitflip_iv for block 0"
    delta = xor(known, desired)
    out = bytearray(ct)
    off = (block_index - 1) * bs
    for j, d in enumerate(delta):
        out[off + j] ^= d
    return bytes(out)


def cbc_bitflip_iv(iv: bytes, known: bytes, desired: bytes) -> bytes:
    """Rewrite plaintext block 0 for free by editing the IV."""
    assert len(known) == len(desired) <= len(iv)
    return xor(iv, xor(known, desired).ljust(len(iv), b"\x00"))


# --------------------------------------------------------- vulnerable service
class CookieService:
    PREFIX = b"comment1=cooking%20MCs;userdata="
    SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"

    def __init__(self) -> None:
        self.key = os.urandom(16)

    def make_cookie(self, userdata: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
        # "Sanitising" the metacharacters does nothing against a ciphertext edit.
        userdata = userdata.replace(b";", b"%3B").replace(b"=", b"%3D")
        pt = pad(self.PREFIX + userdata + self.SUFFIX, BS)
        iv = os.urandom(BS) if iv is None else iv
        return iv, AES.new(self.key, AES.MODE_CBC, iv).encrypt(pt)

    def decrypt(self, iv: bytes, ct: bytes) -> bytes:
        pt = AES.new(self.key, AES.MODE_CBC, iv).decrypt(ct)
        try:
            return unpad(pt, BS)
        except ValueError:
            return pt                     # server that ignores bad padding

    def is_admin(self, iv: bytes, ct: bytes) -> bool:
        return b";admin=true;" in self.decrypt(iv, ct)


# ------------------------------------------------------------------- attack
def find_prefix_blocks(service, bs: int = BS) -> int:
    """Index of the first ciphertext block our input can influence.

    Only works when the IV is reused (fixed IV, or the service lets you pick it).
    With a fresh random IV per query every block differs and you must instead read
    the source, or count blocks with a padding oracle.
    """
    iv = b"\x00" * bs
    _, a = service.make_cookie(b"A", iv=iv)
    _, b = service.make_cookie(b"B", iv=iv)
    for i, (x, y) in enumerate(zip(blocks(a, bs), blocks(b, bs))):
        if x != y:
            return i
    raise RuntimeError("input has no effect")


def forge_admin(service: CookieService) -> tuple[bytes, bytes, bytes]:
    """Sacrifice one block to write `;admin=true;` into the next one."""
    n_prefix = len(service.PREFIX) // BS          # 32 // 16 == 2 blocks
    filler = b"A" * (2 * BS)                      # sacrifice block + target block
    iv, ct = service.make_cookie(filler)
    target_index = n_prefix + 1                   # the second filler block
    known = b"A" * BS
    desired = b";admin=true;AAAA"                 # exactly 16 bytes
    return iv, ct, cbc_bitflip(ct, target_index, known, desired)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    svc = CookieService()

    # --- sanity: the plaintext filter really does block the direct route ---
    iv0, ct0 = svc.make_cookie(b";admin=true;")
    assert not svc.is_admin(iv0, ct0)
    print("[+] direct injection blocked by the server-side filter, as expected")
    assert find_prefix_blocks(svc) == 2
    print("[+] attacker-controlled data starts at ciphertext block 2")

    # --- the bit flip ------------------------------------------------------
    iv, ct_orig, forged = forge_admin(svc)
    pt = svc.decrypt(iv, forged)
    print("[+] decrypted:", pt)
    assert svc.is_admin(iv, forged), pt
    print("[+] PASS bit-flip: ;admin=true; injected")

    # exactly two plaintext blocks change: one sacrificed, one rewritten
    before = AES.new(svc.key, AES.MODE_CBC, iv).decrypt(ct_orig)
    after = AES.new(svc.key, AES.MODE_CBC, iv).decrypt(forged)
    dirty = [i for i, (x, y) in enumerate(zip(blocks(before), blocks(after))) if x != y]
    print("[+] plaintext blocks changed:", dirty, "(one sacrificed, one rewritten)")
    assert dirty == [2, 3], dirty

    # --- rewriting block 0 through the IV ---------------------------------
    key = os.urandom(16)
    iv2 = os.urandom(16)
    message = pad(b"user=guest;id=07" b"more data here!!", BS)
    ct2 = AES.new(key, AES.MODE_CBC, iv2).encrypt(message)

    iv3 = cbc_bitflip_iv(iv2, b"user=guest;id=07", b"user=admin;id=01")
    out = AES.new(key, AES.MODE_CBC, iv3).decrypt(ct2)
    print("[+] iv-flipped block 0:", out[:16])
    assert out[:16] == b"user=admin;id=01"
    assert out[16:32] == message[16:32], "no collateral damage when using the IV"
    print("[+] PASS iv flip: block 0 rewritten for free")

    # --- flipping a single bit ---------------------------------------------
    # amount=00000100 -> amount=00000000 by clearing one nibble
    key = os.urandom(16)
    iv4 = os.urandom(16)
    m = pad(b"AAAAAAAAAAAAAAAA" b"amount=0000010!!", BS)
    c = AES.new(key, AES.MODE_CBC, iv4).encrypt(m)
    c2 = cbc_bitflip(c, 1, b"amount=0000010!!", b"amount=9999999!!")
    d = AES.new(key, AES.MODE_CBC, iv4).decrypt(c2)
    assert d[16:32] == b"amount=9999999!!", d[16:32]
    print("[+] PASS value rewrite:", d[16:32])

    print("\nall checks passed")
```

## Variants & pitfalls

- **You must know the original plaintext of the target block.** If you only know part
  of it, you can only edit that part - the delta is byte-local, so unknown bytes stay
  unknown and untouched.
- **The sacrificed block must be survivable.** If the server validates every field or
  requires valid UTF-8, pick the sacrifice inside a field it ignores, or chain: use a
  padding oracle (`aes-cbc-padding-oracle`) to *fix* the garbage block afterwards.
- **PKCS#7 padding.** If your target is the last block you will also destroy the
  padding. Put the forged data earlier, or recompute the whole tail with CBC-R.
- **If the IV is fixed and secret**, you cannot edit block 0 and you cannot see `P[0]`.
  See `aes-cbc-iv-recovery`.
- **Base64/URL encoding.** Flip the bytes on the raw ciphertext, then re-encode.
  Flipping after encoding corrupts the encoding, not the plaintext.
- **CTR, OFB and CFB.** CTR and OFB are stream ciphers: flipping `C[j]` flips `P[j]`
  with no collateral damage at all. CFB behaves like CBC in reverse - flipping `C[i]`
  edits `P[i]` and destroys `P[i+1]`.
- **The real fix is authentication.** AES-GCM, AES-CCM, AES-SIV or encrypt-then-MAC
  with HMAC. If the challenge has a MAC, this attack is dead; go look for a MAC bug
  instead (`block-cbc-mac-forgery`, `hash-length-extension`).

## Tools

- `pycryptodome` - `AES.new(key, AES.MODE_CBC, iv)`.
- CyberChef - "XOR" with a key at an offset, then "AES Decrypt", for quick manual work.
- `openssl enc -aes-128-cbc -d -K <hex> -iv <hex> -nopad` to observe the garbage block.

## References

- Cryptopals Set 2, challenge 16 ("CBC bitflipping attacks"):
  <https://cryptopals.com/sets/2>
