---
title: "RSA - Bleichenbacher e=3 PKCS#1 v1.5 Signature Forgery"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, signature-forgery, bleichenbacher-2006, e-3, pkcs1, pkcs1-v15, emsa-pkcs1, cube-root, nth-root, asn1, digestinfo, lazy-parser, trailing-garbage, sha256, forgery, no-private-key, verifier-bug, nth-root-forgery]
difficulty: medium
summary: "e=3 plus a verifier that does not check the padding length: craft a cube that starts with 00 01 FF..FF 00 ASN.1 hash and ignore the trailing garbage - a signature with no private key."
when_to_use:
  - "e == 3 (or 17) and the challenge asks you to sign something you should not be able to sign"
  - "The verifier regex-matches or 'finds' the ASN.1 DigestInfo instead of comparing the whole block"
  - "Verification code does int -> bytes, strips 0xFF padding, then compares only the hash"
  - "No private key is available, but the public key is"
  - "The modulus is large (2048/3072/4096) relative to the hash - more room for garbage"
tools: [python3, openssl, gmpy2]
cves: [CVE-2006-4340]
source:
  name: "RFC 8017 (EMSA-PKCS1-v1_5)"
  url: "https://www.rfc-editor.org/rfc/rfc8017"
related: [rsa-small-e, rsa-bleichenbacher-pkcs1, rsa-blinding-decrypt-oracle]
---

## TL;DR

A correct PKCS#1 v1.5 signature check *re-encodes* the expected block and compares all `k`
bytes. A lazy one parses left to right: skip `00 01`, skip `FF`s, expect `00`, read the
ASN.1 DigestInfo, compare the hash - and never checks that nothing follows.
With `e = 3` you can pick the block yourself: put the required prefix at the top, fill the
rest with whatever the cube root needs, and take an integer cube root. The signature
verifies without knowing `d`.

## Recognise it

- Public exponent is `3` (the classic) or another tiny `e`.
- The verifier is hand-rolled: `if b"\x00\x01" == blob[:2]` ... `blob.find(b"\x00", 2)` ...
  `hashlib.sha256(msg).digest() in blob`.
- Anything using `blob.index(ASN1_PREFIX)` or a regex like `\x00\x01\xff+\x00`.
- The challenge gives you only `(n, e)` and a "sign this to get the flag" endpoint.
- Real-world echoes: NSS 2006, several JOSE/JWT libraries, python-rsa.

## Theory

An EMSA-PKCS1-v1_5 block for a `k`-byte modulus is

```
00 01 FF FF ... FF 00 || DigestInfo(hash)
```

with enough `FF`s to fill exactly `k` bytes. A lazy verifier only requires the block to
*begin* with `00 01 FF+ 00 DigestInfo`, and ignores the suffix. So the attacker needs an
integer `s` with

$$s^3 = \underbrace{\texttt{0001FF..FF00}\,\|\,\text{ASN.1}\,\|\,H}_{\text{fixed high part}} \; \| \; \underbrace{\text{anything}}_{\text{low } g \text{ bits}}$$

Take `T` = the fixed part shifted left by `g` bits (the garbage room). Any cube in
`[T, T + 2^g)` works, so `s = ceil(T^(1/3))` succeeds as long as the gap between
consecutive cubes near `T` is smaller than `2^g`:
`(s+1)^3 - s^3 ~ 3 s^2 ~ 3 * 2^(2*8k/3)`, so we need `g > 2*8k/3` roughly - i.e. the fixed
prefix must fit in the top third of the block. With SHA-256 (51 bytes of prefix+hash) this
is comfortable for 3072-bit and 4096-bit moduli, tight for 2048, and needs the
"garbage in the middle" variant (Kuehn/Finney) for 1024-bit.

Also `s^3 < n` must hold - the whole point is that the modular reduction never happens.

## Attack

1. Get `n`, `e = 3`, and the exact ASN.1 DigestInfo prefix for the hash the verifier uses.
2. Build `suffix = 00 || ASN1 || H(msg)`.
3. Build `T = (0x0001 || FF*f || suffix) << garbage_bits` so that the total is `8k` bits.
4. `s = ceil(iroot(T, 3))`; verify `s^3 >= T` and `s^3 < T + 2^garbage_bits`.
5. Send `s` as the signature.
6. If the verifier also checks the total length of the FF run, use the middle-garbage
   variant or a different `e`.

**ASN.1 DigestInfo prefixes (hex, from RFC 8017):**

```
MD5     3020300c06082a864886f70d020505000410
SHA-1   3021300906052b0e03021a05000414
SHA-224 302d300d06096086480165030402040500041c
SHA-256 3031300d060960864801650304020105000420
SHA-384 3041300d060960864801650304020205000430
SHA-512 3051300d060960864801650304020305000440
```

## Code

```python
#!/usr/bin/env python3
"""Bleichenbacher 2006 e=3 PKCS#1 v1.5 signature forgery + a vulnerable verifier.

    python3 rsa_forge_e3.py       # self-test: forge, then verify with a lazy parser

Note: the forgery itself needs only (n, e). The self-test builds a real modulus
so the 'sig**3 < n' condition is checked honestly.
"""
from __future__ import annotations

import hashlib
import re

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:  # pure-python fallback (slow for 1536-bit primes, but correct)
    import random as _r

    def bytes_to_long(b: bytes) -> int:
        return int.from_bytes(b, "big")

    def long_to_bytes(x: int) -> bytes:
        return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")

    def _is_prime(n: int) -> bool:
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def getPrime(bits: int) -> int:
        while True:
            c = _r.getrandbits(bits) | (1 << (bits - 1)) | 1
            if _is_prime(c):
                return c


ASN1 = {
    "md5": bytes.fromhex("3020300c06082a864886f70d020505000410"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def iroot(x: int, n: int) -> tuple[int, bool]:
    if x <= 0:
        return 0, x == 0
    r = 1 << ((x.bit_length() + n - 1) // n)
    while True:
        nr = ((n - 1) * r + x // r ** (n - 1)) // n
        if nr >= r:
            break
        r = nr
    return r, r ** n == x


def forge_signature(msg: bytes, k: int, e: int = 3, hashname: str = "sha256",
                    ff_bytes: int = 8) -> int:
    """Forge a signature that a left-to-right PKCS#1 v1.5 parser accepts.

    k        modulus size in BYTES
    ff_bytes how many 0xFF padding bytes to emit (a lazy verifier only needs >= 1,
             many require >= 8 to mimic the real format)
    """
    h = hashlib.new(hashname, msg).digest()
    suffix = b"\x00" + ASN1[hashname] + h            # the 00 separator + DigestInfo
    fixed_len = 2 + ff_bytes + len(suffix)           # 00 01 FF.. 00 ASN1 H
    if fixed_len >= k:
        raise ValueError("modulus too small for this hash")
    garbage_bits = 8 * (k - fixed_len)

    head = (0x0001 << (8 * (k - 2)))
    head |= ((1 << (8 * ff_bytes)) - 1) << (8 * (k - 2 - ff_bytes))
    target = head | (bytes_to_long(suffix) << garbage_bits)

    s, exact = iroot(target, e)
    if not exact:
        s += 1                                       # round UP into the window
    assert s ** e >= target, "cube root rounding went the wrong way"
    if s ** e >= target + (1 << garbage_bits):
        raise ValueError("no cube in the garbage window: modulus too small, "
                         "use the middle-garbage variant or more garbage room")
    return s


def vulnerable_verify(sig: int, msg: bytes, n: int, e: int = 3,
                      hashname: str = "sha256") -> bool:
    """A typical buggy verifier: parses left to right, ignores trailing bytes."""
    k = (n.bit_length() + 7) // 8
    blob = pow(sig, e, n).to_bytes(k, "big")
    if blob[0] != 0x00 or blob[1] != 0x01:
        return False
    i = 2
    while i < k and blob[i] == 0xFF:
        i += 1
    if i == 2 or i >= k or blob[i] != 0x00:          # needs at least one FF
        return False
    i += 1
    prefix = ASN1[hashname]
    if blob[i:i + len(prefix)] != prefix:
        return False
    i += len(prefix)
    digest = hashlib.new(hashname, msg).digest()
    return blob[i:i + len(digest)] == digest          # <-- BUG: nothing checks the tail


def regex_verify(sig: int, msg: bytes, n: int, e: int = 3) -> bool:
    """An even lazier real-world pattern: a regex over the decoded block."""
    k = (n.bit_length() + 7) // 8
    blob = pow(sig, e, n).to_bytes(k, "big")
    want = re.escape(b"\x00" + ASN1["sha256"] + hashlib.sha256(msg).digest())
    return re.match(b"\x00\x01\xff+" + want, blob) is not None


def correct_verify(sig: int, msg: bytes, n: int, e: int = 3,
                   hashname: str = "sha256") -> bool:
    """The right way: rebuild the whole block and compare every byte."""
    k = (n.bit_length() + 7) // 8
    blob = pow(sig, e, n).to_bytes(k, "big")
    digest = hashlib.new(hashname, msg).digest()
    di = ASN1[hashname] + digest
    expected = b"\x00\x01" + b"\xff" * (k - 3 - len(di)) + b"\x00" + di
    return blob == expected


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    random.seed(5)

    # 3072-bit modulus: plenty of garbage room for SHA-256
    while True:
        p, q = getPrime(1536), getPrime(1536)
        n = p * q
        if n.bit_length() == 3072:
            break
    k = 3072 // 8
    e = 3
    msg = b"transfer 1000000 to attacker"

    sig = forge_signature(msg, k, e=e, hashname="sha256", ff_bytes=8)
    assert sig ** e < n, "forged block must not wrap mod n"
    assert vulnerable_verify(sig, msg, n, e), "lazy verifier should accept the forgery"
    assert regex_verify(sig, msg, n, e), "regex verifier should accept the forgery"
    assert not correct_verify(sig, msg, n, e), "a correct verifier must reject it"
    print(f"[+] forged a {sig.bit_length()}-bit signature for {msg!r} with no private key")
    print(f"    lazy verifier : accepted")
    print(f"    strict verifier: rejected (as it should)")

    # a different message must not verify with the same signature
    assert not vulnerable_verify(sig, b"transfer 1 to attacker", n, e)
    print("[+] the forgery is message-specific, as expected")

    # sha1 variant
    sig1 = forge_signature(msg, k, e=e, hashname="sha1", ff_bytes=8)
    assert vulnerable_verify(sig1, msg, n, e, hashname="sha1")
    print("[+] sha1 variant ok")

    # a genuine signature must still pass the strict verifier
    d = pow(e, -1, (p - 1) * (q - 1))
    di = ASN1["sha256"] + hashlib.sha256(msg).digest()
    block = b"\x00\x01" + b"\xff" * (k - 3 - len(di)) + b"\x00" + di
    real = pow(bytes_to_long(block), d, n)
    assert correct_verify(real, msg, n, e)
    print("[+] genuine signature still verifies strictly")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    _selftest()
```

## Variants & pitfalls

- **`e = 3` is not required**, just convenient. Any small `e` works if the modulus is big
  enough relative to `e * (prefix + hash)`.
- **Small modulus (1024-bit, SHA-256)**: the naive "garbage at the end" needs the fixed part
  to sit in the top third. If it does not fit, use the Kuehn/Finney "garbage in the middle"
  construction: choose the block as `2^x - C` forms whose cube root is exact by design.
- **Exact vs rounded root**: always round *up* and then check that `s^e` is still below
  `T + 2^garbage_bits`.
- **The `0xFF` count**: some verifiers demand at least 8 padding bytes; set `ff_bytes >= 8`.
- **NULL parameters in the ASN.1**: some libraries accept both the `05 00` NULL and its
  absence, giving two prefix variants to try.
- **`sig >= n`**: if the forged `s` is bigger than `n`, the reduction ruins everything. Use a
  bigger modulus or fewer FF bytes.
- **This is not a decryption attack.** It forges signatures only. For decryption with a
  padding oracle see `rsa-bleichenbacher-pkcs1`.
- **PSS is immune.** So is any verifier that re-encodes and memcmps the full block.

## Tools

```bash
# see the raw block a real signature decodes to (great for reversing the verifier)
openssl rsautl -verify -in sig.bin -pubin -inkey pub.pem -raw -hexdump

# dump a public key's n and e
openssl rsa -pubin -in pub.pem -text -noout

# recompute the DigestInfo for a file
openssl dgst -sha256 -binary msg.txt | xxd -p
```

## References

- D. Bleichenbacher, rump session CRYPTO 2006 (the "e=3 signature forgery")
- H. Finney / U. Kuehn, follow-up variants with garbage in the middle
- RFC 8017 EMSA-PKCS1-v1_5: https://www.rfc-editor.org/rfc/rfc8017
