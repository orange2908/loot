---
title: "Hash Length Extension - MD5, SHA-1, SHA-256 (Merkle-Damgard)"
category: crypto
subcategory: hash
type: technique
tags: [hash, length-extension, merkle-damgard, md5, sha1, sha256, sha512, glue-padding, secret-prefix-mac, mac-forgery, hashpump, hashpumpy, hash-extender, hmac, keyed-hash, cryptopals, blake2, sha3, padding]
difficulty: medium
summary: "If a MAC is H(secret || data) with a Merkle-Damgard hash, the digest IS the internal state, so you can append data and compute the new MAC without the secret."
when_to_use:
  - "A signature is `md5(secret + data)`, `sha1(secret + data)` or `sha256(secret + data)`"
  - "You have the digest and the data, and want to append to the data"
  - "The message looks like `user=guest&role=user&sig=<hex>` with a secret-prefix MAC"
  - "The parser keeps the LAST occurrence of a duplicated key, so appending wins"
  - "You do not know the secret but can guess or brute-force its length"
tools: [hashpumpy, hash_extender, python]
source:
  name: "Cryptopals Set 4"
  url: "https://cryptopals.com/sets/4"
related: [block-cbc-mac-forgery, hash-collisions-magic, hash-hmac-timing-attack, aes-cbc-bit-flipping]
---

## TL;DR

MD5, SHA-1, SHA-256 and SHA-512 are Merkle-Damgard: they pad the message, chop it into
blocks, and iterate a compression function over an internal state. The final state *is*
the digest - no finalisation step hides it. So `H(secret || data)` hands you the exact
state the hash was in after `secret || data || glue_padding`, and you can keep hashing
from there. You forge `H(secret || data || glue || anything)` knowing only the digest,
the data, and `len(secret)`.

## Recognise it

- `sig = hashlib.sha256(SECRET + data).hexdigest()` in source, with `SECRET` unknown.
- A URL like `?user=guest&role=user&sig=abcdef...` where the sig is 32/40/64 hex chars.
- `\x80` and a length field appearing in a decoded blob - that is glue padding from a
  previous, successful attack.
- The server re-parses the message after verifying, and later keys override earlier
  ones (`urllib.parse.parse_qs` keeps all, `dict(...)` keeps the last).
- The secret length is stated in the challenge, or is guessable (16, 32, "the flag").

## Theory

Merkle-Damgard padding for MD5 / SHA-1 / SHA-256 on a message of `L` bytes:

```
msg || 0x80 || 0x00 * k || len_in_bits (8 bytes)
```

where `k = (55 - L) mod 64`, so the total is a multiple of 64. The length field is
**big-endian** for SHA-1/SHA-256/SHA-512 and **little-endian** for MD5 - that single
byte-order difference is the only thing that changes between them.

The hash is

$$h_0 = IV,\qquad h_{i+1} = f(h_i, B_{i+1}),\qquad H(m) = h_n$$

and `H(m)` is `h_n` verbatim: 8 big-endian `uint32` for SHA-256, 5 for SHA-1, 4
little-endian `uint32` for MD5.

Given `t = H(secret || data)` with `len(secret) = s`:

1. Load `t` back into the state registers. You are now "inside" the hash, positioned
   after `s + len(data) + len(glue)` bytes.
2. `glue = md_padding(s + len(data))` - the padding the original hash appended.
3. Feed `suffix` and the *new* final padding, computed for total length
   `s + len(data) + len(glue) + len(suffix)`.
4. The output equals `H(secret || data || glue || suffix)`.

You hand the server `data || glue || suffix` and the forged digest. The glue is raw
bytes including `\x80` and NULs - URL-encode it (`%80%00...`) if it travels in a query
string.

**Not vulnerable:** HMAC (the nested construction hides the state), SHA-3 / Keccak
(sponge, the state is larger than the output), BLAKE2/BLAKE3, SHA-512/224 and
SHA-512/256 (truncated output, so the digest is not the whole state), and the
`H(data || secret)` order (you cannot append past the secret).

## Attack

1. Identify the hash by digest length: 32 hex = MD5, 40 = SHA-1, 64 = SHA-256.
2. Guess `len(secret)`. If unknown, loop 1..64 and submit each forgery; one will be
   accepted. Locally, loop and compare against the real digest.
3. For each candidate length, compute `glue` and the extended digest.
4. Send `data || glue || suffix` with the forged signature.
5. Choose `suffix` so the parser prefers it: `&admin=true`, `&role=admin`, a second
   JSON key, or a trailing command.

## Code

```python
#!/usr/bin/env python3
"""Merkle-Damgard length extension for MD5, SHA-1 and SHA-256.

Pure Python compression functions with a settable internal state, so no external
tool (hashpumpy, hash_extender) is required. Self-test forges a signature against a
locally built secret-prefix MAC and brute-forces the unknown secret length.
"""

import hashlib
import hmac
import math
import struct

MASK32 = 0xFFFFFFFF


# --------------------------------------------------------------- constants
def _primes(n: int) -> list[int]:
    out, c = [], 2
    while len(out) < n:
        if all(c % p for p in out):
            out.append(c)
        c += 1
    return out


def _icbrt(n: int) -> int:
    lo, hi = 0, 1 << ((n.bit_length() + 2) // 3 + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


_P = _primes(64)
# SHA-256: fractional parts of the square roots / cube roots of the first primes.
SHA256_IV = [math.isqrt(p << 64) & MASK32 for p in _P[:8]]
SHA256_K = [_icbrt(p << 96) & MASK32 for p in _P]

MD5_K = [int(abs(math.sin(i + 1)) * (1 << 32)) & MASK32 for i in range(64)]
MD5_S = ([7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4
         + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4)
MD5_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


# ------------------------------------------------- compression functions
def sha256_compress(state: list[int], block: bytes) -> list[int]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & MASK32 & g)
        t1 = (h + s1 + ch + SHA256_K[i] + w[i]) & MASK32
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & MASK32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK32, c, b, a, (t1 + t2) & MASK32
    return [(x + y) & MASK32 for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def sha1_compress(state: list[int], block: bytes) -> list[int]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f, k = (b & c) | (~b & MASK32 & d), 0x5A827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        a, b, c, d, e = ((_rotl(a, 5) + f + e + k + w[i]) & MASK32,
                         a, _rotl(b, 30), c, d)
    return [(x + y) & MASK32 for x, y in zip(state, [a, b, c, d, e])]


def md5_compress(state: list[int], block: bytes) -> list[int]:
    m = struct.unpack("<16I", block)
    a, b, c, d = state
    for i in range(64):
        if i < 16:
            f, g = (b & c) | (~b & MASK32 & d), i
        elif i < 32:
            f, g = (d & b) | (~d & MASK32 & c), (5 * i + 1) % 16
        elif i < 48:
            f, g = b ^ c ^ d, (3 * i + 5) % 16
        else:
            f, g = c ^ (b | (~d & MASK32)), (7 * i) % 16
        tmp = d
        d = c
        c = b
        b = (b + _rotl((a + f + MD5_K[i] + m[g]) & MASK32, MD5_S[i])) & MASK32
        a = tmp
    return [(x + y) & MASK32 for x, y in zip(state, [a, b, c, d])]


ALGOS = {
    "sha256": (sha256_compress, SHA256_IV, ">8I", "big"),
    "sha1":   (sha1_compress,   SHA1_IV,   ">5I", "big"),
    "md5":    (md5_compress,    MD5_IV,    "<4I", "little"),
}


# ---------------------------------------------------- generic MD plumbing
def md_padding(msg_len: int, endian: str) -> bytes:
    """The bytes a Merkle-Damgard hash appends to a message of `msg_len` bytes."""
    return (b"\x80" + b"\x00" * ((55 - msg_len) % 64)
            + (msg_len * 8).to_bytes(8, endian))


def md_hash(algo: str, data: bytes) -> bytes:
    compress, iv, fmt, endian = ALGOS[algo]
    state = list(iv)
    padded = data + md_padding(len(data), endian)
    for i in range(0, len(padded), 64):
        state = compress(state, padded[i:i + 64])
    return struct.pack(fmt, *state)


def length_extend(algo: str, digest: bytes, orig_len: int,
                  suffix: bytes) -> tuple[bytes, bytes]:
    """Return (glue_padding, forged_digest) for H(secret||data||glue||suffix).

    `orig_len` is len(secret) + len(data): the length the original hash saw.
    """
    compress, _iv, fmt, endian = ALGOS[algo]
    state = list(struct.unpack(fmt, digest))
    glue = md_padding(orig_len, endian)
    total = orig_len + len(glue) + len(suffix)
    stream = suffix + md_padding(total, endian)
    for i in range(0, len(stream), 64):
        state = compress(state, stream[i:i + 64])
    return glue, struct.pack(fmt, *state)


# --------------------------------------------------------- vulnerable app
class SignedCookieApp:
    """sig = H(secret || data) -- a secret-prefix MAC, the textbook mistake."""

    def __init__(self, secret: bytes, algo: str = "sha256") -> None:
        self.secret = secret
        self.algo = algo

    def sign(self, data: bytes) -> bytes:
        return getattr(hashlib, self.algo)(self.secret + data).digest()

    def check(self, data: bytes, sig: bytes) -> bool:
        return hmac.compare_digest(self.sign(data), sig)

    def authorise(self, data: bytes, sig: bytes) -> dict[bytes, bytes]:
        if not self.check(data, sig):
            raise ValueError("bad signature")
        out: dict[bytes, bytes] = {}
        for kv in data.split(b"&"):           # last key wins -- helps the attacker
            k, _, v = kv.partition(b"=")
            out[k] = v
        return out


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    # --- our compression functions agree with hashlib ----------------------
    for algo in ("md5", "sha1", "sha256"):
        for msg in (b"", b"a", b"abc", b"x" * 55, b"x" * 56, b"x" * 64, b"y" * 1000):
            assert md_hash(algo, msg) == getattr(hashlib, algo)(msg).digest(), (algo, msg)
    print("[+] PASS pure-Python md5/sha1/sha256 match hashlib")

    SECRET = b"s3cr3t-of-unknown-length!"
    DATA = b"user=guest&role=user&expires=99999"
    SUFFIX = b"&role=admin"

    for algo in ("md5", "sha1", "sha256"):
        app = SignedCookieApp(SECRET, algo)
        sig = app.sign(DATA)
        assert app.authorise(DATA, sig)[b"role"] == b"user"

        # --- brute-force the unknown secret length -------------------------
        found = None
        for guess in range(1, 65):
            glue, forged_sig = length_extend(algo, sig, guess + len(DATA), SUFFIX)
            payload = DATA + glue + SUFFIX
            if app.check(payload, forged_sig):
                found = (guess, payload, forged_sig)
                break
        assert found is not None, algo
        guess, payload, forged_sig = found
        assert guess == len(SECRET), (guess, len(SECRET))

        claims = app.authorise(payload, forged_sig)
        assert claims[b"role"] == b"admin", claims
        print(f"[+] PASS {algo}: secret length {guess}, role -> {claims[b'role'].decode()}")

    # --- what the forged payload looks like on the wire --------------------
    app = SignedCookieApp(SECRET, "sha256")
    sig = app.sign(DATA)
    glue, forged = length_extend("sha256", sig, len(SECRET) + len(DATA), SUFFIX)
    payload = DATA + glue + SUFFIX
    print("[+] payload  :", payload)
    print("[+] url-safe :", "".join(f"%{b:02x}" if b < 0x20 or b > 0x7E else chr(b)
                                    for b in payload))
    print("[+] signature:", forged.hex())
    assert hashlib.sha256(SECRET + payload).hexdigest() == forged.hex()
    print("[+] PASS forged digest equals the real hash of the forged message")

    # --- HMAC is immune ----------------------------------------------------
    hsig = hmac.new(SECRET, DATA, hashlib.sha256).digest()
    _, hforged = length_extend("sha256", hsig, len(SECRET) + len(DATA), SUFFIX)
    assert not hmac.compare_digest(
        hmac.new(SECRET, DATA + glue + SUFFIX, hashlib.sha256).digest(), hforged)
    print("[+] PASS HMAC resists length extension")

    print("\nall checks passed")
```

## Variants & pitfalls

- **Unknown secret length.** Loop 1..64 (or 1..128) and submit every forgery. Each
  candidate gives a *different* glue, so you get one request per guess. `hashpumpy`
  does this in a loop for you.
- **The glue is binary.** URL-encode it, or base64 the whole blob. If the transport
  strips NULs or is ASCII-only, the attack dies - look for a hex/base64 field instead.
- **Big vs little endian length.** MD5 writes the bit length little-endian; SHA-1,
  SHA-256 and SHA-512 write it big-endian. Getting this wrong is the usual reason a
  hand-rolled extender fails.
- **SHA-512** uses 128-byte blocks, a 16-byte length field and 64-bit words
  (`k = (111 - L) mod 128`). Same attack, different arithmetic.
- **SHA-512/224 and SHA-512/256 are safe** because the output is a truncation of the
  state. So is SHA-384 (truncated SHA-512). SHA-224 truncates SHA-256 and is also
  safe in this sense, though only 32 bits are withheld.
- **`H(data || secret)` is not extendable**, but it is vulnerable to collision attacks
  on `data` - see `hash-collisions-magic`.
- **The parser must prefer your suffix.** Test which occurrence of a duplicated key
  wins: PHP `parse_str` and Python `dict(...)` keep the last, `parse_qs` keeps all,
  some JSON parsers keep the first.
- **Sometimes you also control `data`.** Then you can choose where the glue lands, for
  example inside a comment field, so the message still looks clean.

## Tools

- `hashpumpy` (Python binding for HashPump):
  `hashpumpy.hashpump(sig_hex, data, append, key_length) -> (new_sig, new_data)`.
- `hash_extender` (C tool by Ron Bowes):
  `hash_extender -d <data> -s <sig> -a <append> -l <keylen> -f sha256`.
- Pure Python (above) when you cannot install anything.

## References

- Cryptopals Set 4, challenges 29 and 30 ("Break a SHA-1 / MD4 keyed MAC using length
  extension"): <https://cryptopals.com/sets/4>
- RFC 6234 (SHA), RFC 1321 (MD5) and RFC 2104 (HMAC) define the padding rules used
  above.
