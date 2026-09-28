---
title: "RSA - Blinding / Homomorphic Malleability vs a Decryption Oracle Blacklist"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, blinding, rsa-blinding, malleability, homomorphic, multiplicative, decrypt-oracle, decryption-oracle, blacklist, chosen-ciphertext, cca, signature-blinding, forgery, unpadded, textbook-rsa, modular-inverse, oracle-bypass]
difficulty: easy
summary: "A decrypt oracle that refuses the target ciphertext is useless: send c*r^e, divide the answer by r - textbook RSA is multiplicatively homomorphic."
when_to_use:
  - "A service decrypts anything EXCEPT the one ciphertext you care about"
  - "A signing service signs anything except the message that gives you the flag"
  - "The oracle rejects your input after a blacklist/equality check"
  - "The service decrypts but only returns part of the plaintext (still blind, then shift)"
  - "You want to forge a signature for m = m1*m2 from signatures of m1 and m2"
tools: [python3, pwntools]
source:
  name: "CTF Wiki - RSA chosen ciphertext attacks"
  url: "https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/"
related: [rsa-lsb-parity-oracle, rsa-bleichenbacher-pkcs1, rsa-signature-forgery-e3]
---

## TL;DR

Textbook RSA satisfies `enc(a)*enc(b) = enc(a*b)`. Pick a random `r`, send
`c' = c * r^e mod n`, the oracle returns `m' = m * r mod n`, and you recover
`m = m' * r^(-1) mod n`. The blacklist never sees the ciphertext it was meant to block.
Same trick blinds a signing oracle: `s = sign(m * r^e) * r^(-1)`.

## Recognise it

- `if ciphertext == FLAG_CT: return "nope"` in the service source.
- "I will decrypt anything except that one" / "you already used this ciphertext".
- A signature service that refuses the exact message `give me the flag`.
- Any RSA endpoint with no padding (or padding that is not checked after decryption).
- The oracle answers with the full plaintext (otherwise combine with the parity/LSB search).

## Theory

For unpadded RSA, $\mathrm{dec}(c_1 c_2) = \mathrm{dec}(c_1)\,\mathrm{dec}(c_2) \bmod n$.
Choose $r$ with $\gcd(r, n) = 1$ and compute

$$c' = c \cdot r^{e} \bmod n \;\Rightarrow\; \mathrm{dec}(c') = m r \bmod n
\;\Rightarrow\; m = \mathrm{dec}(c') \cdot r^{-1} \bmod n$$

`c'` is uniformly random-looking, so no blacklist of specific values can stop it.

**Signature blinding** is the same identity in reverse:
$\mathrm{sign}(m r^{e}) = (m r^{e})^{d} = m^{d} r$, so
$s = \mathrm{sign}(m r^{e}) \cdot r^{-1}$ is a valid signature on `m` that the signer never
produced. (This is also the *defensive* use of blinding, against timing attacks - same maths,
opposite intent.)

**Multiplicative forgery**: `sign(m1) * sign(m2) = sign(m1*m2 mod n)`. If the service signs
`2` and `3`, you get a signature for `6` for free. Handy when the target message factors
into allowed pieces.

If `gcd(r, n) != 1` you factored `n`; that never happens by accident but always check.

## Attack

1. Get `n` and `e` (public key, or from two signatures, or from the service).
2. Pick a random `r` in `[2, n)`; `assert gcd(r, n) == 1`.
3. Send `c * pow(r, e, n) % n`.
4. Take the answer `m'`, compute `m = m' * pow(r, -1, n) % n`.
5. `long_to_bytes(m)`.
6. If the oracle returns bytes, convert with `bytes_to_long` first; watch for leading
   zero bytes being stripped.

## Code

```python
#!/usr/bin/env python3
"""RSA blinding against a blacklisting decrypt/sign oracle.

    python3 rsa_blinding.py        # self-test with a simulated, blacklisting service
"""
from __future__ import annotations

import random
from math import gcd

try:
    from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
except ImportError:
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
            c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if _is_prime(c):
                return c


class Blacklisted(Exception):
    pass


class DecryptService:
    """A typical CTF service: decrypts anything except the flag ciphertext."""

    def __init__(self, p: int, q: int, e: int, banned: set[int]):
        self.n, self.e = p * q, e
        self.d = pow(e, -1, (p - 1) * (q - 1))
        self.banned = set(banned)
        self.calls = 0

    def decrypt(self, c: int) -> int:
        self.calls += 1
        if c % self.n in self.banned:
            raise Blacklisted("nice try")
        return pow(c, self.d, self.n)


class SignService:
    """Signs anything except one specific message."""

    def __init__(self, p: int, q: int, e: int, banned_msgs: set[int]):
        self.n, self.e = p * q, e
        self.d = pow(e, -1, (p - 1) * (q - 1))
        self.banned = set(banned_msgs)
        self.calls = 0

    def sign(self, m: int) -> int:
        self.calls += 1
        if m % self.n in self.banned:
            raise Blacklisted("that one is off limits")
        return pow(m, self.d, self.n)


# --------------------------------------------------------------------------- #
def blind_decrypt(n: int, e: int, c: int, oracle, rng=random) -> int:
    """Recover m from c using a decryption oracle that refuses c itself."""
    while True:
        r = rng.randrange(2, n)
        g = gcd(r, n)
        if g == 1:
            break
        raise RuntimeError(f"gcd(r, n) = {g} -> you just factored n, use that instead")
    blinded = c * pow(r, e, n) % n
    m_blinded = oracle(blinded)
    return m_blinded * pow(r, -1, n) % n


def blind_sign(n: int, e: int, m: int, oracle, rng=random) -> int:
    """Get a signature on m from a signer that refuses m itself."""
    while True:
        r = rng.randrange(2, n)
        if gcd(r, n) == 1:
            break
    s_blinded = oracle(m * pow(r, e, n) % n)
    return s_blinded * pow(r, -1, n) % n


def multiplicative_forgery(n: int, sigs: list[int]) -> int:
    """sign(a)*sign(b) = sign(a*b): combine signatures of factors."""
    out = 1
    for s in sigs:
        out = out * s % n
    return out


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    random.seed(31337)

    p, q = getPrime(512), getPrime(512)
    e = 65537
    n = p * q
    flag = b"CTF{blinding_defeats_every_blacklist}"
    m = bytes_to_long(flag)
    c = pow(m, e, n)

    # --- decryption oracle with the flag ciphertext blacklisted ------------- #
    svc = DecryptService(p, q, e, banned={c})
    try:
        svc.decrypt(c)
        raise AssertionError("the service should have refused")
    except Blacklisted:
        pass
    rec = blind_decrypt(n, e, c, svc.decrypt)
    assert rec == m
    assert long_to_bytes(rec) == flag
    print(f"[+] blinded decryption in {svc.calls} oracle call(s):",
          long_to_bytes(rec).decode())

    # --- signing oracle with the target message blacklisted ----------------- #
    target = bytes_to_long(b"give me the flag")
    ssvc = SignService(p, q, e, banned_msgs={target})
    try:
        ssvc.sign(target)
        raise AssertionError("the signer should have refused")
    except Blacklisted:
        pass
    sig = blind_sign(n, e, target, ssvc.sign)
    assert pow(sig, e, n) == target % n
    print("[+] blinded signature verifies against the public key")

    # --- multiplicative forgery: sign(6) from sign(2) and sign(3) ----------- #
    ssvc2 = SignService(p, q, e, banned_msgs={6})
    s2, s3 = ssvc2.sign(2), ssvc2.sign(3)
    s6 = multiplicative_forgery(n, [s2, s3])
    assert pow(s6, e, n) == 6
    print("[+] sign(2) * sign(3) is a valid signature for 6")

    # --- a blinded ciphertext is never equal to the banned one -------------- #
    hits = 0
    for _ in range(200):
        r = random.randrange(2, n)
        if c * pow(r, e, n) % n == c:
            hits += 1
    assert hits == 0
    print("[+] 200 blinded ciphertexts, none matched the blacklist entry")

    # --- combining with a partial oracle: blind, then shift ----------------- #
    # service returns only the LOW 64 bits of the plaintext
    def partial_oracle(ct: int) -> int:
        return pow(ct, svc.d, n) & ((1 << 64) - 1)

    # choose r = inverse(2^64) so that m*r shifts the unknown into view
    shift = pow(pow(2, 64, n), -1, n)
    low = partial_oracle(c)                    # m mod 2^64
    ct2 = c * pow(shift, e, n) % n
    low2 = partial_oracle(ct2)                 # (m / 2^64 mod n) mod 2^64
    assert low == m % (1 << 64)
    assert low2 == (m * shift % n) % (1 << 64)
    print("[+] partial-output oracle can be shifted with a chosen blinding factor")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    _selftest()
```

## Variants & pitfalls

- **Padding breaks the homomorphism.** If the service OAEP-decrypts and validates, the
  blinded plaintext will not unpad and you get an error - that is a padding oracle
  situation (`rsa-bleichenbacher-pkcs1`), not a blinding one.
- **Leading zeros.** If the oracle returns *bytes*, `m*r mod n` may start with a zero byte
  that the service strips. Work with integers, and reconstruct with `int.from_bytes`.
- **The oracle may blacklist by hash of the input** - still fine, `c*r^e` hashes differently.
- **Rate limits**: blinding needs exactly one query. If the service allows one query total,
  this is the attack it expects.
- **`r = 2` is enough** in a pinch (`m*2 mod n`), but a random `r` looks less suspicious and
  avoids "small multiplier" filters.
- **gcd(r, n) != 1** means `r` shares a factor with `n`: you factored the modulus.
- **Combine freely**: blind first, then run the LSB/parity search on the blinded value, then
  unblind at the end.
- The same malleability is why unpadded RSA must never be used for real encryption.

## Tools

```bash
# pwntools skeleton for a blinding oracle
python3 - <<'PY'
from pwn import remote
from Crypto.Util.number import long_to_bytes
import random
n, e, c = 0, 65537, 0            # fill in
io = remote("host", 1337)
r = random.randrange(2, n)
io.sendlineafter(b"ct: ", str(c * pow(r, e, n) % n).encode())
mb = int(io.recvline().strip())
print(long_to_bytes(mb * pow(r, -1, n) % n))
PY
```

## References

- CTF Wiki, chosen-ciphertext attacks on RSA:
  https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/
- D. Chaum, "Blind Signatures for Untraceable Payments" (CRYPTO 1982) - the same identity,
  used constructively
