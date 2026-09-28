---
title: "Symmetric Crypto Cheatsheet - Modes, Oracles, openssl, pycryptodome"
category: crypto
subcategory: symmetric
type: cheatsheet
tags: [aes, des, 3des, blowfish, chacha20, rc4, ecb, cbc, cfb, ofb, ctr, gcm, ccm, siv, padding-oracle, pkcs7, iv, nonce, openssl, pycryptodome]
summary: "Mode-by-mode table of what leaks and what is malleable, mode fingerprinting, openssl one-liners, pycryptodome recipes for every mode, padding helpers, oracle-to-attack map."
tools: [openssl, pycryptodome, cyberchef, python]
related: [aes-ecb-byte-at-a-time, aes-cbc-padding-oracle, aes-ctr-nonce-reuse, aes-gcm-nonce-reuse-forbidden, aes-toolkit, xor-toolkit]
---

## Mode comparison

| mode | needs | length | what it leaks | malleable? | nonce/IV reuse costs | authenticated |
|---|---|---|---|---|---|---|
| ECB | nothing | pad to 16 | equal plaintext blocks -> equal ciphertext blocks | yes, whole blocks (cut, paste, reorder, delete) | n/a (deterministic always) | no |
| CBC | random IV | pad to 16 | equality of the whole message; block-level structure after a common prefix | yes, one block at a time, destroying the previous block | two messages with equal prefixes are visible | no |
| CFB | random IV | no padding | as CBC | yes, byte-level in `P[i]`, destroys `P[i+1]` | keystream reuse until the first difference | no |
| OFB | unique IV | no padding | length only | yes, bit-exact, no damage | total: `C1 xor C2 = P1 xor P2` | no |
| CTR | unique nonce | no padding | length only | yes, bit-exact, no damage | total: many-time pad | no |
| GCM | unique 96-bit nonce | no padding, +16 tag | length only | no (tag), until the nonce repeats | catastrophic: leaks `H`, forge any tag | yes (GMAC) |
| CCM | unique 7-13 byte nonce | no padding, +tag | length only | no | keystream reuse + MAC forgery | yes (CBC-MAC) |
| SIV | nonce optional | +16 synthetic IV | equality of (nonce, aad, plaintext) | no | only reveals that two plaintexts are equal | yes, nonce-misuse resistant |
| OCB | unique nonce | +16 tag | length only | no | breaks authenticity | yes |
| XTS | sector number | no padding | equality per 16-byte position within a sector | block-level within a sector | sectors are deterministic | no |

Rules of thumb:

- No padding and `len(ct) == len(pt)` -> a stream construction (CTR/OFB/CFB/ChaCha20/RC4).
- `len(ct) == len(pt) + 16` -> an AEAD tag is attached.
- `len(ct) % 16 == 0` and `> len(pt)` -> a padded block mode (ECB or CBC).
- Only ECB is deterministic across encryptions of the same plaintext.

## Which mode am I looking at

```text
# 1. length
len(ct) % 16 == 0 and no IV field          -> ECB (or CBC with a fixed/implicit IV)
len(ct) % 16 == 0 and a 16-byte prefix     -> CBC, first block is the IV
len(ct) == len(pt)                         -> CTR / OFB / CFB / ChaCha20 / RC4 / OTP
len(ct) == len(pt) + 16                    -> GCM / OCB / SIV / CCM (tag appended)
len(ct) == len(pt) + 12 + 16               -> nonce || ct || tag  (very common wire format)
len(ct) == 8 * n                           -> DES / 3DES / Blowfish, block size 8

# 2. determinism
encrypt(X) twice, same output              -> ECB, or a fixed IV/nonce  (jackpot)
encrypt(X) twice, different output         -> random IV/nonce somewhere

# 3. structure
send b"A"*64, look for repeated 16-byte blocks in the output -> ECB
xor two ciphertexts of known-different plaintexts; mostly printable -> keystream reuse
flip one ciphertext byte, see how much plaintext breaks:
    1 byte  broken                          -> CTR / OFB (stream)
    16 bytes broken + 1 byte changed        -> CBC (the classic signature)
    16 bytes broken, nothing else           -> ECB
    everything rejected                     -> AEAD

# 4. the headers people forget
"Salted__" (0x53616C7465645F5F) first 8 bytes -> openssl enc with a passphrase,
                                                 next 8 bytes are the salt
0x00000001 at the end of a 16-byte nonce field -> GCM J0
```

## openssl

```sh
# --- raw key/IV, no key derivation: what you want for CTF ---
# ECB takes no -iv. -nopad when the plaintext is already block aligned.
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -nopad -in pt.bin -out ct.bin
openssl enc -aes-128-ecb -d -K 000102030405060708090a0b0c0d0e0f -nopad -in ct.bin

# CBC with an explicit IV (hex, no 0x prefix)
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff \
            -iv 0f0e0d0c0b0a09080706050403020100 -in pt.bin -out ct.bin
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff \
            -iv 0f0e0d0c0b0a09080706050403020100 -in ct.bin

# CTR: -iv is the full 16-byte initial counter block (nonce || counter), 32 hex chars
openssl enc -aes-128-ctr -K 00112233445566778899aabbccddeeff \
            -iv 00000000000000000000000000000001 -in pt.bin -out ct.bin
# CTR is its own inverse, so the same command decrypts
openssl enc -aes-128-ctr -K 00112233445566778899aabbccddeeff \
            -iv 00000000000000000000000000000001 -in ct.bin -out pt2.bin

# base64 in/out, useful when the challenge hands you base64
openssl enc -aes-256-cbc -a -K $(openssl rand -hex 32) -iv $(openssl rand -hex 16) -in pt.txt

# --- passphrase mode: this is where "Salted__" comes from ---
# ALWAYS pass -pbkdf2 on modern openssl; the legacy EVP_BytesToKey is MD5-based.
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -pass pass:hunter2 -in pt -out ct
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -d -pass pass:hunter2 -in ct
# legacy files (no -pbkdf2 when they were made):
openssl enc -aes-256-cbc -md md5 -d -pass pass:hunter2 -in ct
# see the derived key/iv without encrypting anything:
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -S 0011223344556677 -pass pass:hunter2 -P

# --- hashes and MACs ---
openssl dgst -sha256 file
openssl dgst -sha256 -hmac "secretkey" file
openssl dgst -sha1 -binary file | xxd -p
openssl mac -macopt digest:SHA256 -macopt hexkey:00ff HMAC < file      # openssl 3.x

# --- randomness and encoding ---
openssl rand -hex 16
openssl rand -base64 32
openssl base64 -d < b64.txt > raw.bin
xxd -r -p < hex.txt > raw.bin          # hex -> raw
xxd -p -c 999 raw.bin                  # raw -> one line of hex

# --- list what this build supports ---
openssl enc -ciphers
openssl list -cipher-algorithms | grep -i gcm
```

## pycryptodome: every mode

```python
#!/usr/bin/env python3
"""Encrypt-then-decrypt round trip in every symmetric mode pycryptodome offers.

Copy the four lines you need. Run the file to confirm your install supports them all.
"""

import os
from Crypto.Cipher import AES, ARC4, Blowfish, ChaCha20, ChaCha20_Poly1305, DES, DES3
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad

PT = b"attack at dawn, bring the flag"
AAD = b"header-v1"
KEY16, KEY24, KEY32, KEY64 = (os.urandom(n) for n in (16, 24, 32, 64))


def ecb():
    ct = AES.new(KEY16, AES.MODE_ECB).encrypt(pad(PT, 16))
    return unpad(AES.new(KEY16, AES.MODE_ECB).decrypt(ct), 16)


def cbc():
    iv = os.urandom(16)
    ct = AES.new(KEY16, AES.MODE_CBC, iv).encrypt(pad(PT, 16))
    return unpad(AES.new(KEY16, AES.MODE_CBC, iv).decrypt(ct), 16)


def cfb():
    iv = os.urandom(16)                       # segment_size=8 gives 1-byte CFB
    ct = AES.new(KEY16, AES.MODE_CFB, iv, segment_size=128).encrypt(PT)
    return AES.new(KEY16, AES.MODE_CFB, iv, segment_size=128).decrypt(ct)


def ofb():
    iv = os.urandom(16)
    ct = AES.new(KEY16, AES.MODE_OFB, iv).encrypt(PT)
    return AES.new(KEY16, AES.MODE_OFB, iv).decrypt(ct)


def ctr_nonce():
    nonce = os.urandom(8)                     # 8-byte nonce + 8-byte counter
    ct = AES.new(KEY16, AES.MODE_CTR, nonce=nonce).encrypt(PT)
    return AES.new(KEY16, AES.MODE_CTR, nonce=nonce).decrypt(ct)


def ctr_counter():
    # Full 128-bit counter, no nonce -- matches `openssl enc -aes-128-ctr -iv <16 bytes>`
    ctr = Counter.new(128, initial_value=1)
    ct = AES.new(KEY16, AES.MODE_CTR, counter=ctr).encrypt(PT)
    return AES.new(KEY16, AES.MODE_CTR,
                   counter=Counter.new(128, initial_value=1)).decrypt(ct)


def gcm():
    nonce = os.urandom(12)                    # 96 bits is the fast path
    enc = AES.new(KEY16, AES.MODE_GCM, nonce=nonce)
    enc.update(AAD)
    ct, tag = enc.encrypt_and_digest(PT)
    dec = AES.new(KEY16, AES.MODE_GCM, nonce=nonce)
    dec.update(AAD)
    return dec.decrypt_and_verify(ct, tag)    # raises ValueError on a bad tag


def ccm():
    nonce = os.urandom(11)                    # 7..13 bytes
    enc = AES.new(KEY16, AES.MODE_CCM, nonce=nonce)
    enc.update(AAD)
    ct, tag = enc.encrypt_and_digest(PT)
    dec = AES.new(KEY16, AES.MODE_CCM, nonce=nonce)
    dec.update(AAD)
    return dec.decrypt_and_verify(ct, tag)


def siv():
    # Nonce-misuse resistant. Key must be 32/48/64 bytes (double length).
    nonce = os.urandom(16)
    enc = AES.new(KEY64, AES.MODE_SIV, nonce=nonce)
    enc.update(AAD)
    ct, tag = enc.encrypt_and_digest(PT)
    dec = AES.new(KEY64, AES.MODE_SIV, nonce=nonce)
    dec.update(AAD)
    return dec.decrypt_and_verify(ct, tag)


def ocb():
    nonce = os.urandom(12)
    enc = AES.new(KEY16, AES.MODE_OCB, nonce=nonce)
    ct, tag = enc.encrypt_and_digest(PT)
    dec = AES.new(KEY16, AES.MODE_OCB, nonce=nonce)
    return dec.decrypt_and_verify(ct, tag)


def chacha():
    nonce = os.urandom(8)                     # 8, 12 or 24 (XChaCha20) bytes
    ct = ChaCha20.new(key=KEY32, nonce=nonce).encrypt(PT)
    return ChaCha20.new(key=KEY32, nonce=nonce).decrypt(ct)


def chacha_poly():
    nonce = os.urandom(12)
    enc = ChaCha20_Poly1305.new(key=KEY32, nonce=nonce)
    enc.update(AAD)
    ct, tag = enc.encrypt_and_digest(PT)
    dec = ChaCha20_Poly1305.new(key=KEY32, nonce=nonce)
    dec.update(AAD)
    return dec.decrypt_and_verify(ct, tag)


def des_cbc():
    iv = os.urandom(8)                        # block size 8, key 8 bytes
    key = os.urandom(8)
    ct = DES.new(key, DES.MODE_CBC, iv).encrypt(pad(PT, 8))
    return unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(ct), 8)


def des3_cbc():
    while True:
        try:
            key = DES3.adjust_key_parity(os.urandom(24))
            break
        except ValueError:                    # degenerate 3DES key, try again
            continue
    iv = os.urandom(8)
    ct = DES3.new(key, DES3.MODE_CBC, iv).encrypt(pad(PT, 8))
    return unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ct), 8)


def blowfish_cbc():
    key = os.urandom(16)                      # 4..56 bytes, block size 8
    iv = os.urandom(8)
    ct = Blowfish.new(key, Blowfish.MODE_CBC, iv).encrypt(pad(PT, 8))
    return unpad(Blowfish.new(key, Blowfish.MODE_CBC, iv).decrypt(ct), 8)


def rc4():
    key = os.urandom(16)                      # no IV, no nonce -- see stream-rc4-attacks
    ct = ARC4.new(key).encrypt(PT)
    return ARC4.new(key).decrypt(ct)


if __name__ == "__main__":
    for fn in (ecb, cbc, cfb, ofb, ctr_nonce, ctr_counter, gcm, ccm, siv, ocb,
               chacha, chacha_poly, des_cbc, des3_cbc, blowfish_cbc, rc4):
        assert fn() == PT, fn.__name__
        print(f"[+] {fn.__name__:14s} round trip ok")
    print("\nall modes ok")
```

## Padding

```python
#!/usr/bin/env python3
"""Every padding scheme you will meet, by hand and via pycryptodome."""

from Crypto.Util.Padding import pad, unpad

BS = 16


def pkcs7_pad(data: bytes, bs: int = BS) -> bytes:
    """n bytes of value n. n is never 0, so aligned data gets a whole extra block."""
    n = bs - len(data) % bs
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, bs: int = BS) -> bytes:
    if not data or len(data) % bs:
        raise ValueError("bad length")
    n = data[-1]
    if not 1 <= n <= bs or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def pkcs7_is_valid(data: bytes, bs: int = BS) -> bool:
    """Exactly the check a padding oracle answers for you."""
    try:
        pkcs7_unpad(data, bs)
        return True
    except ValueError:
        return False


def x923_pad(data: bytes, bs: int = BS) -> bytes:
    """ANSI X.923: zeros then the length."""
    n = bs - len(data) % bs
    return data + b"\x00" * (n - 1) + bytes([n])


def x923_unpad(data: bytes, bs: int = BS) -> bytes:
    n = data[-1]
    if not 1 <= n <= bs or data[-n:-1] != b"\x00" * (n - 1):
        raise ValueError("bad padding")
    return data[:-n]


def iso7816_pad(data: bytes, bs: int = BS) -> bytes:
    """ISO/IEC 7816-4: 0x80 then zeros."""
    return data + b"\x80" + b"\x00" * ((-len(data) - 1) % bs)


def iso7816_unpad(data: bytes) -> bytes:
    i = data.rfind(b"\x80")
    if i < 0 or any(data[i + 1:]):
        raise ValueError("bad padding")
    return data[:i]


def zero_pad(data: bytes, bs: int = BS) -> bytes:
    """Ambiguous: cannot represent a plaintext that ends in NUL."""
    return data + b"\x00" * ((-len(data)) % bs)


def zero_unpad(data: bytes) -> bytes:
    return data.rstrip(b"\x00")


if __name__ == "__main__":
    for msg in (b"", b"a", b"A" * 15, b"A" * 16, b"A" * 17):
        assert pkcs7_unpad(pkcs7_pad(msg)) == msg
        assert pkcs7_pad(msg) == pad(msg, BS)                  # matches pycryptodome
        assert unpad(pkcs7_pad(msg), BS) == msg
        assert x923_unpad(x923_pad(msg)) == msg
        assert x923_pad(msg) == pad(msg, BS, style="x923")
        assert iso7816_unpad(iso7816_pad(msg)) == msg
        assert iso7816_pad(msg) == pad(msg, BS, style="iso7816")
        assert zero_unpad(zero_pad(msg)) == msg.rstrip(b"\x00")
    assert not pkcs7_is_valid(b"A" * 15 + b"\x11")
    assert not pkcs7_is_valid(b"A" * 14 + b"\x02\x03")
    assert pkcs7_is_valid(b"A" * 14 + b"\x02\x02")
    assert pkcs7_is_valid(bytes([16]) * 16)
    print("[+] all padding schemes round trip and reject bad input")
```

## Quick snippets

```python
#!/usr/bin/env python3
"""The ten helpers you retype in every crypto challenge."""

import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad

BS = 16


def xor(*args: bytes) -> bytes:
    """xor any number of buffers, truncated to the shortest."""
    out = args[0]
    for a in args[1:]:
        out = bytes(x ^ y for x, y in zip(out, a))
    return out


def blocks(data: bytes, bs: int = BS) -> list[bytes]:
    return [data[i:i + bs] for i in range(0, len(data), bs)]


def show_blocks(data: bytes, bs: int = BS) -> str:
    return "\n".join(f"{i:3d} {b.hex():32s} {b!r}" for i, b in enumerate(blocks(data, bs)))


def duplicate_blocks(data: bytes, bs: int = BS) -> list[bytes]:
    """Repeated blocks: the ECB fingerprint."""
    bl = blocks(data, bs)
    return [b for b in set(bl) if bl.count(b) > 1]


def looks_like_base64(s: bytes) -> bool:
    return len(s) % 4 == 0 and all(
        c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in s)


def decode_any(s: str) -> bytes:
    """Try hex, then base64, then raw."""
    t = s.strip()
    try:
        return bytes.fromhex(t)
    except ValueError:
        pass
    try:
        return base64.b64decode(t, validate=True)
    except Exception:
        return t.encode()


if __name__ == "__main__":
    key = os.urandom(16)
    ct = AES.new(key, AES.MODE_ECB).encrypt(pad(b"YELLOW SUBMARINE" * 3, BS))
    print(show_blocks(ct))
    assert len(duplicate_blocks(ct)) == 1
    assert xor(b"\x01\x02", b"\x03\x03", b"\x00\x01") == b"\x02\x00"
    assert long_to_bytes(bytes_to_long(b"hello")) == b"hello"
    assert decode_any("48656c6c6f") == b"Hello"
    assert decode_any("SGVsbG8=") == b"Hello"
    assert looks_like_base64(b"SGVsbG8=")
    print("[+] helpers ok")
```

## Given oracle X, read technique Y

| what you have | technique |
|---|---|
| ECB, you control a prefix, a secret is appended | `aes-ecb-byte-at-a-time` |
| ECB, structured plaintext you partly control | `aes-ecb-cut-and-paste` |
| CBC, no MAC, you know a plaintext block | `aes-cbc-bit-flipping` |
| CBC, valid/invalid padding distinguishable | `aes-cbc-padding-oracle` |
| CBC, the server echoes the plaintext on error | `aes-cbc-iv-recovery` |
| CBC, `AES.new(key, MODE_CBC, key)` | `aes-cbc-iv-recovery` |
| CTR/OFB/ChaCha20, nonce repeats | `aes-ctr-nonce-reuse` |
| CTR with an `edit(ct, offset, text)` API | `aes-ctr-nonce-reuse` |
| GCM, nonce repeats | `aes-gcm-nonce-reuse-forbidden` |
| CBC-MAC with IV=0 and variable lengths | `block-cbc-mac-forgery` |
| `sha256(secret + data)` used as a MAC | `hash-length-extension` |
| MAC compared with `==` and you can time it | `hash-hmac-timing-attack` |
| RC4 with one key for many messages | `stream-rc4-attacks` |
| A keystream from a shift register | `stream-lfsr-berlekamp-massey` |
| Two encryptions with two small keys | `block-meet-in-the-middle` |
| A custom SPN with 3-6 rounds and an oracle | `block-differential-linear` |
| A custom byte-mangler and a known plaintext | `block-toy-spn-z3` |

## Sizes and constants

```text
AES         block 16   keys 16 / 24 / 32       rounds 10 / 12 / 14
DES         block  8   key   8 (56 effective)
3DES        block  8   keys 16 / 24 (112 / 168 nominal, ~112 real)
Blowfish    block  8   keys 4..56
ChaCha20    stream     key  32   nonce 8 / 12 / 24 (XChaCha20)
RC4         stream     key  5..256, no nonce at all
GCM         nonce 12 recommended, tag 16 (truncation to 8/12 allowed, weakens it)
CCM         nonce 7..13, tag 4..16
SIV         key 32/48/64 (double length), synthetic IV 16
Poly1305    tag 16, one-time key 32
CBC/CFB/OFB IV = block size, must be unpredictable for CBC
CTR         nonce || counter = block size; pycryptodome default is 8 || 8
```

## Gotchas

```text
- ECB takes no IV. If the API demands one, it is being ignored -- still ECB.
- CBC needs an UNPREDICTABLE IV, not just a unique one (that is the BEAST lesson).
- CTR nonce || counter layouts differ between libraries; an off-by-one block is the
  usual symptom of getting it wrong.
- GCM with a nonce that is not 12 bytes runs the nonce through GHASH first. Do not
  assume J0 = nonce || 00000001 unless the nonce is exactly 12 bytes.
- decrypt_and_verify() raises ValueError on a bad tag: catch it, do not let it end
  your exploit loop.
- pycryptodome cipher objects are STATEFUL. Create a new one for every operation.
- `pad()` always adds bytes, even when the input is already aligned.
- 3DES rejects degenerate keys (K1 == K2). Retry with fresh randomness.
- openssl `-K`/`-iv` take HEX with no 0x; `-k`/`-pass` take a passphrase and derive.
- Without -pbkdf2, openssl's legacy KDF is one MD5 iteration. Old CTF files need
  `-md md5`.
- A 16-byte prefix that changes every time is almost certainly the IV, not ciphertext.
```

## Tools

```sh
# CyberChef: AES Encrypt/Decrypt, XOR, XOR Brute Force, Detect File Type,
#            Magic (auto-detect), Padding operations. Runs offline from a local copy.
# featherduster: interactive analysis, detects ECB and many-time pads automatically.
# xortool: xortool -c 20 file            # repeating-key xor key length
# padbuster: padbuster <url> <ct> 16 -cookies "s=<ct>"   # CBC padding oracle
# hashcat / john: see hash-cracking-cheatsheet
python3 -c "from Crypto.Cipher import AES; print(AES.block_size, AES.key_size)"
```
