---
title: "AES Toolkit - ECB Byte-at-a-Time, CBC Padding Oracle, CBC-R, Bit-Flipping, CTR Keystream"
category: crypto
subcategory: aes
type: script
tags: [aes, toolkit, ecb, cbc, ctr, padding-oracle, cbc-r, poodle, bit-flipping, byte-at-a-time, chosen-ciphertext, oracle, keystream-reuse, many-time-pad, nonce, iv, xor, pkcs7, pycryptodome, cryptopals]
summary: "One self-contained module: ECB secret-suffix solver, pluggable CBC padding-oracle decrypt and forge, CBC bit-flipper, CTR keystream recovery, plus detection helpers."
tools: [pycryptodome, pwntools]
related: [aes-ecb-byte-at-a-time, aes-cbc-padding-oracle, aes-cbc-bit-flipping, aes-ctr-nonce-reuse, xor-toolkit]
---

## Usage

Save as `aes_toolkit.py`. Run it directly to execute the self-test, which builds every
oracle locally with a random key and asserts each attack recovers the secret:

```sh
pip install pycryptodome
python3 aes_toolkit.py
```

Import it against a remote target by wrapping the service in a one-argument callable:

```text
from aes_toolkit import ecb_byte_at_a_time, padding_oracle_decrypt, padding_oracle_encrypt
import requests

S = requests.Session()
URL = "http://target:1337"

def enc_oracle(data: bytes) -> bytes:                 # ECB secret-suffix oracle
    return bytes.fromhex(S.post(URL + "/enc", data=data.hex()).text)

def pad_oracle(ct: bytes) -> bool:                    # CBC padding oracle
    return "padding" not in S.post(URL + "/dec", data=ct.hex()).text

secret = ecb_byte_at_a_time(enc_oracle)
plain = padding_oracle_decrypt(bytes.fromhex(cookie), pad_oracle)
forged = padding_oracle_encrypt(b"role=admin", pad_oracle)
```

## What it does

| function | needs | gives |
|---|---|---|
| `detect_block_size(oracle)` | length-observable oracle | 8 or 16 |
| `detect_ecb(oracle)` | chosen plaintext | True if ECB |
| `find_prefix_len(oracle)` | chosen plaintext, ECB | length of the fixed prefix |
| `ecb_byte_at_a_time(oracle)` | `ECB(prefix || you || secret)` | the whole secret |
| `recover_intermediate(oracle, block)` | padding oracle | `D_k(block)` |
| `padding_oracle_decrypt(ct, oracle)` | padding oracle | plaintext, no key |
| `padding_oracle_encrypt(pt, oracle)` | padding oracle | `iv || ct` decrypting to `pt` |
| `cbc_bitflip(ct, i, known, want)` | any CBC ciphertext | block `i` rewritten |
| `cbc_bitflip_iv(iv, known, want)` | attacker-supplied IV | block 0 rewritten, free |
| `ctr_keystream_from_known(ct, pt)` | one known plaintext | keystream |
| `ctr_recover_many_time_pad(cts)` | many same-nonce ciphertexts | keystream (statistical) |

## Code

```python
#!/usr/bin/env python3
"""aes_toolkit -- practical AES attack primitives for CTF.

Every attack takes a plain Python callable as its oracle, so the same code drives a
local function, an HTTP endpoint or a pwntools socket. Run this file to self-test.
"""

from __future__ import annotations

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BS = 16


# ============================================================ tiny helpers
def xor(a: bytes, b: bytes) -> bytes:
    """Byte-wise xor, truncated to the shorter input."""
    return bytes(x ^ y for x, y in zip(a, b))


def blocks(data: bytes, bs: int = BS) -> list[bytes]:
    """Split into bs-sized blocks; the last one may be short."""
    return [data[i:i + bs] for i in range(0, len(data), bs)]


def pkcs7_pad(data: bytes, bs: int = BS) -> bytes:
    n = bs - (len(data) % bs)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, bs: int = BS) -> bytes:
    if not data or len(data) % bs:
        raise ValueError("bad length")
    n = data[-1]
    if not 1 <= n <= bs or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def hexdump_blocks(data: bytes, bs: int = BS) -> str:
    return "\n".join(f"{i:3d}: {b.hex()}" for i, b in enumerate(blocks(data, bs)))


# ============================================================ mode detection
def detect_block_size(oracle) -> int:
    """Grow the input until the ciphertext length jumps. The jump is the block size."""
    base = len(oracle(b""))
    for n in range(1, 129):
        size = len(oracle(b"A" * n))
        if size != base:
            return size - base
    raise RuntimeError("block size not found (stream cipher?)")


def detect_ecb(oracle, bs: int = BS) -> bool:
    """Identical plaintext blocks give identical ciphertext blocks only in ECB."""
    ct = oracle(b"A" * (bs * 4))
    bl = blocks(ct, bs)
    return len(bl) != len(set(bl))


def has_duplicate_blocks(ct: bytes, bs: int = BS) -> bool:
    """Passive ECB fingerprint: does this ciphertext repeat a block?"""
    bl = blocks(ct, bs)
    return len(bl) != len(set(bl))


# ============================================================ ECB attacks
def find_prefix_len(oracle, bs: int = BS) -> int:
    """Length of the fixed unknown prefix in ECB(prefix || attacker || secret)."""
    c0, c1 = oracle(b""), oracle(b"\x01")
    idx = min(len(c0), len(c1)) // bs
    for i in range(0, min(len(c0), len(c1)), bs):
        if c0[i:i + bs] != c1[i:i + bs]:
            idx = i // bs
            break
    for n in range(bs + 1):
        a = oracle(b"A" * n + b"\x00")
        b = oracle(b"A" * n + b"\x01")
        if a[:(idx + 1) * bs] == b[:(idx + 1) * bs]:
            return (idx + 1) * bs - n
    raise RuntimeError("prefix length not found")


def find_secret_len(oracle, prefix_len: int, align: int, bs: int = BS) -> int:
    base = len(oracle(b"A" * align))
    for n in range(1, bs + 1):
        if len(oracle(b"A" * (align + n))) > base:
            return base - prefix_len - align - n
    raise RuntimeError("secret length not found")


def ecb_byte_at_a_time(oracle, bs: int | None = None, alphabet=None) -> bytes:
    """Recover the secret from ECB(prefix || attacker_data || secret).

    `oracle(data) -> ciphertext`. Handles a fixed random prefix automatically.
    `alphabet` narrows the 256-byte search; None means try printable first.
    """
    bs = bs or detect_block_size(oracle)
    if not detect_ecb(oracle, bs):
        raise RuntimeError("oracle does not look like ECB")
    prefix_len = find_prefix_len(oracle, bs)
    align = (-prefix_len) % bs
    start = (prefix_len + align) // bs
    secret_len = find_secret_len(oracle, prefix_len, align, bs)

    if alphabet is None:
        printable = list(range(0x20, 0x7F)) + [0x0A, 0x0D, 0x09]
        alphabet = printable + [b for b in range(256) if b not in printable]

    known = b""
    for k in range(secret_len):
        fill = (-(k + 1)) % bs
        tb = start + (fill + k) // bs
        target = oracle(b"A" * (align + fill))[tb * bs:(tb + 1) * bs]
        for guess in alphabet:
            probe = oracle(b"A" * (align + fill) + known + bytes([guess]))
            if probe[tb * bs:(tb + 1) * bs] == target:
                known += bytes([guess])
                break
        else:
            break
    return known


def ecb_cut_and_paste(ct: bytes, order: list[int], bs: int = BS) -> bytes:
    """Reassemble ciphertext blocks in an arbitrary order (ECB has no chaining)."""
    bl = blocks(ct, bs)
    return b"".join(bl[i] for i in order)


# ============================================================ CBC attacks
def recover_intermediate(oracle, block: bytes, bs: int = BS) -> bytes:
    """Recover I = D_k(block) from a valid/invalid-padding oracle.

    `oracle(ct) -> bool` takes a full `iv || body` ciphertext.
    """
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
                # Disambiguate 0x01 from an accidental 0x02 0x02 / 0x03 03 03 ...
                probe = bytearray(forged)
                probe[pos - 1] ^= 0xFF
                if not oracle(bytes(probe) + block):
                    continue
            found = guess
            break
        if found is None:
            raise RuntimeError(f"padding oracle stalled at pad value {padval}")
        inter[pos] = found ^ padval
    return bytes(inter)


def padding_oracle_decrypt(ct: bytes, oracle, bs: int = BS,
                           strip: bool = True) -> bytes:
    """Decrypt `iv || body` with only a padding oracle. No key required."""
    bl = blocks(ct, bs)
    if len(bl) < 2:
        raise ValueError("need iv + at least one block")
    out = b"".join(xor(recover_intermediate(oracle, bl[i], bs), bl[i - 1])
                   for i in range(1, len(bl)))
    return pkcs7_unpad(out, bs) if strip else out


def padding_oracle_encrypt(target: bytes, oracle, bs: int = BS) -> bytes:
    """CBC-R: forge `iv || body` that decrypts to `target`, without the key."""
    chunks = blocks(pkcs7_pad(target, bs), bs)
    cur = os.urandom(bs)
    out = [cur]
    for chunk in reversed(chunks):
        cur = xor(recover_intermediate(oracle, cur, bs), chunk)
        out.insert(0, cur)
    return b"".join(out)


def cbc_bitflip(ct: bytes, block_index: int, known: bytes, desired: bytes,
                bs: int = BS) -> bytes:
    """Rewrite plaintext block `block_index` (1-based) by editing block index-1.

    Destroys plaintext block `block_index - 1`. Use `cbc_bitflip_iv` for block 0.
    """
    if block_index < 1:
        raise ValueError("block 0 needs the IV; use cbc_bitflip_iv")
    if len(known) != len(desired):
        raise ValueError("known and desired must be the same length")
    out = bytearray(ct)
    off = (block_index - 1) * bs
    for j, d in enumerate(xor(known, desired)):
        out[off + j] ^= d
    return bytes(out)


def cbc_bitflip_iv(iv: bytes, known: bytes, desired: bytes) -> bytes:
    """Rewrite plaintext block 0 through the IV, with no collateral damage."""
    if len(known) != len(desired):
        raise ValueError("known and desired must be the same length")
    return xor(iv, xor(known, desired).ljust(len(iv), b"\x00"))


# ============================================================ CTR / stream
def ctr_keystream_from_known(ct: bytes, known_pt: bytes, offset: int = 0) -> bytes:
    """keystream[offset:] = ciphertext xor known plaintext."""
    return xor(ct[offset:offset + len(known_pt)], known_pt)


def ctr_decrypt_with_keystream(ct: bytes, keystream: bytes) -> bytes:
    return xor(ct, keystream[:len(ct)])


def ctr_edit_oracle_keystream(edit, ct: bytes) -> bytes:
    """`edit(ct, offset, newtext)` re-encrypting under the same nonce IS a dump."""
    return edit(ct, 0, b"\x00" * len(ct))


_LETTERS = set(range(0x41, 0x5B)) | set(range(0x61, 0x7B))


def ctr_recover_many_time_pad(cts: list[bytes]) -> bytes:
    """Statistical keystream recovery from several same-nonce ciphertexts.

    Each column is a single-byte-xor problem across messages; score candidates with
    an English character model. Needs ~8 ciphertexts to be reliable.
    """
    score = {0x20: 3.0}
    weights = [2.6, 2.5, 2.4, 2.3, 2.3, 2.2, 2.2, 2.1, 2.0, 1.9, 1.8, 1.6, 1.5,
               1.4, 1.3, 1.3, 1.2, 1.1, 1.0, 0.9, 0.7, 0.5, 0.3, 0.2, 0.1, 0.05]
    for ch, w in zip("etaoinshrdlcumwfgypbvkjxqz", weights):
        score[ord(ch)] = w
        score[ord(ch.upper())] = w - 1.2
    for ch in ".,'\"!?;:-()_{}/0123456789":
        score[ord(ch)] = 0.3

    longest = max(len(c) for c in cts)
    ks = bytearray(longest)
    for pos in range(longest):
        column = [c[pos] for c in cts if len(c) > pos]
        best, best_score = 0, float("-inf")
        for k in range(256):
            s = sum(score.get(b ^ k, -6.0) for b in column)
            if s > best_score:
                best, best_score = k, s
        ks[pos] = best
    return bytes(ks)


# ============================================================ local oracles
def _make_ecb_oracle(secret: bytes, prefix_len: int | None = None):
    key = os.urandom(16)
    n = os.urandom(1)[0] % 40 if prefix_len is None else prefix_len
    prefix = os.urandom(n)

    def oracle(data: bytes) -> bytes:
        return AES.new(key, AES.MODE_ECB).encrypt(pad(prefix + data + secret, BS))

    return oracle, len(prefix)


def _make_padding_oracle(secret: bytes):
    key = os.urandom(16)
    state = {"queries": 0}

    def token() -> bytes:
        iv = os.urandom(BS)
        return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(secret, BS))

    def oracle(ct: bytes) -> bool:
        state["queries"] += 1
        pt = AES.new(key, AES.MODE_CBC, ct[:BS]).decrypt(ct[BS:])
        try:
            unpad(pt, BS)
            return True
        except ValueError:
            return False

    def consume(ct: bytes) -> bytes:
        return unpad(AES.new(key, AES.MODE_CBC, ct[:BS]).decrypt(ct[BS:]), BS)

    return token, oracle, consume, state


# ============================================================== self-test
if __name__ == "__main__":
    print("== helpers ==")
    assert pkcs7_unpad(pkcs7_pad(b"abc")) == b"abc"
    assert pkcs7_unpad(pkcs7_pad(b"A" * 16)) == b"A" * 16
    for bad in (b"", b"A" * 15, b"A" * 15 + b"\x11", b"A" * 14 + b"\x02\x03"):
        try:
            pkcs7_unpad(bad)
            raise SystemExit(f"should have rejected {bad!r}")
        except ValueError:
            pass
    assert xor(b"\x00\xff", b"\xff\xff") == b"\xff\x00"
    print("[+] PASS padding + xor helpers")

    print("\n== ECB byte-at-a-time ==")
    SECRET = b"flag{ecb_byte_at_a_time_is_free}\nand more secret text here"
    for plen in (0, 1, 15, 16, 31, None):
        oracle, real = _make_ecb_oracle(SECRET, plen)
        assert detect_block_size(oracle) == 16
        assert detect_ecb(oracle)
        assert find_prefix_len(oracle) == real
        got = ecb_byte_at_a_time(oracle)
        assert got == SECRET, (got, SECRET)
    print(f"[+] PASS recovered {len(SECRET)} bytes for prefix lengths 0,1,15,16,31,random")

    print("\n== ECB cut and paste ==")
    key = os.urandom(16)
    msg = pad(b"AAAAAAAAAAAAAAAA" b"BBBBBBBBBBBBBBBB" b"CCCCCCCCCCCCCCCC", BS)
    ct = AES.new(key, AES.MODE_ECB).encrypt(msg)
    swapped = AES.new(key, AES.MODE_ECB).decrypt(ecb_cut_and_paste(ct, [2, 1, 0, 3]))
    assert swapped[:48] == b"C" * 16 + b"B" * 16 + b"A" * 16
    assert has_duplicate_blocks(AES.new(key, AES.MODE_ECB).encrypt(b"Z" * 32))
    print("[+] PASS block reordering and duplicate detection")

    print("\n== CBC padding oracle ==")
    PLAIN = b"user=guest;role=user;flag=flag{cbc_padding_oracle_decrypts_all}"
    token, pad_oracle, consume, state = _make_padding_oracle(PLAIN)
    ct = token()
    assert pad_oracle(ct)
    broken = bytearray(ct)
    broken[-BS - 1] ^= 0xFF
    assert not pad_oracle(bytes(broken))
    state["queries"] = 0
    got = padding_oracle_decrypt(ct, pad_oracle)
    assert got == PLAIN, got
    print(f"[+] PASS decrypted {len(PLAIN)} bytes in {state['queries']} oracle queries")

    print("\n== CBC-R forgery ==")
    for target in (b"user=admin;role=admin", b"A" * 32, b"", b"x"):
        state["queries"] = 0
        forged = padding_oracle_encrypt(target, pad_oracle)
        assert pad_oracle(forged)
        assert consume(forged) == target, target
    print("[+] PASS forged ciphertexts for 4 targets, including empty and aligned")

    print("\n== CBC bit-flipping ==")
    key, iv = os.urandom(16), os.urandom(16)
    pt = pad(b"comment=hello!!!" b"AAAAAAAAAAAAAAAA" b"AAAAAAAAAAAAAAAA", BS)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pt)
    forged = cbc_bitflip(ct, 2, b"A" * 16, b";admin=true;AAAA")
    out = AES.new(key, AES.MODE_CBC, iv).decrypt(forged)
    assert b";admin=true;" in out, out
    assert out[:16] == pt[:16], "blocks before the sacrifice are untouched"
    assert out[48:] == pt[48:], "blocks after the target are untouched"
    print("[+] PASS bit-flip rewrote block 2, damaged only block 1")

    iv2 = cbc_bitflip_iv(iv, b"comment=hello!!!", b"user=admin;id=01")
    out = AES.new(key, AES.MODE_CBC, iv2).decrypt(ct)
    assert out[:16] == b"user=admin;id=01"
    assert out[16:] == pt[16:], "the IV route costs nothing"
    print("[+] PASS iv bit-flip rewrote block 0 for free")

    print("\n== CTR keystream ==")
    key, nonce = os.urandom(16), os.urandom(8)
    msgs = [
        b"Never encrypt two messages under one counter mode nonce, please.",
        b"The flag for this one is flag{ctr_keystream_reuse_breaks_it_all}.",
        b"Counter mode turns a block cipher into a very fast stream cipher.",
        b"An attacker who knows one message learns the keystream and wins.",
        b"Frequency analysis of each column recovers the rest without help.",
        b"Every serious protocol derives a fresh nonce for every message OK.",
        b"Repeating a nonce is the single most common mistake in this area.",
        b"Another ordinary English sentence so the statistics have a chance.",
        b"Column scoring needs about eight ciphertexts to be reliable here.",
        b"And one more line of plain prose to push the sample size higher.",
        b"Please do not reply to this address because nobody ever reads it.",
        b"Attached you will find the minutes of the last committee meeting.",
        b"Our servers will be unavailable on Sunday morning for some hours.",
        b"Thank you for your patience while we migrate the old databases ok.",
        b"A stream cipher is only as strong as the uniqueness of its nonce.",
        b"The quick brown fox jumps over the lazy dog while nobody watches.",
        b"Sales figures for the quarter are attached to the previous email.",
        b"Meeting moved to eleven o'clock in the small room near the stairs.",
    ]
    cts = [AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(m) for m in msgs]

    # Take the keystream from the LONGEST known message so it covers every other one.
    longest = max(range(len(msgs)), key=lambda i: len(msgs[i]))
    ks = ctr_keystream_from_known(cts[longest], msgs[longest])
    for m, c in zip(msgs, cts):
        assert ctr_decrypt_with_keystream(c, ks) == m
    print(f"[+] PASS one known message decrypted all {len(msgs)}")

    def edit(ct_: bytes, offset: int, newtext: bytes) -> bytes:
        buf = bytearray(AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct_))
        buf[offset:offset + len(newtext)] = newtext
        return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(bytes(buf))

    dumped = ctr_edit_oracle_keystream(edit, cts[1])
    assert ctr_decrypt_with_keystream(cts[1], dumped) == msgs[1]
    print("[+] PASS edit oracle dumped the keystream")

    guess = ctr_recover_many_time_pad(cts)
    common = min(len(m) for m in msgs)
    acc = sum(1 for i in range(common) if guess[i] == ks[i]) / common
    print(f"[+] many-time-pad keystream accuracy: {acc:.0%}")
    assert acc >= 0.90, acc
    recovered = ctr_decrypt_with_keystream(cts[1], guess)
    assert b"flag{ctr_keystream_reuse_breaks_it_all}" in recovered, recovered
    print("[+] PASS statistical many-time-pad recovery:", recovered[:45])

    print("\nall checks passed")
```

## Notes

- **Every oracle is a callable.** `ecb_byte_at_a_time` wants `bytes -> bytes`;
  `padding_oracle_decrypt` and `padding_oracle_encrypt` want `bytes -> bool` over a
  full `iv || body`. Wrap the remote service once and all four attacks work.
- **Query cost.** `ecb_byte_at_a_time` is `<= 256` queries per secret byte (far fewer
  with the printable-first alphabet). `padding_oracle_*` is `<= 4096` per block,
  ~2000 typical. Blocks are independent, so parallelise across them.
- **The 0x01 ambiguity** is handled in `recover_intermediate`; do not remove that
  second probe or roughly one block in sixteen comes back wrong.
- **`padding_oracle_encrypt` pads for you.** Pass the raw plaintext you want the
  server to see, not a pre-padded one.
- **`cbc_bitflip` destroys the preceding block.** Choose a target whose predecessor
  lands in a field the parser ignores, or fix it afterwards with CBC-R.
- **CTR helpers work for OFB and ChaCha20 unchanged** - anything that xors a keystream.
- **8-byte blocks.** Pass `bs=8` for DES/3DES/Blowfish; `detect_block_size` will tell
  you.
- See `aes-ecb-byte-at-a-time`, `aes-cbc-padding-oracle`, `aes-cbc-bit-flipping` and
  `aes-ctr-nonce-reuse` for the theory behind each function, and `xor-toolkit` for the
  pure-xor side.
