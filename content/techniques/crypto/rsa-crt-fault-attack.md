---
title: "RSA - CRT Fault Attack (Bellcore)"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, crt, crt-rsa, fault-attack, bellcore, boneh-demillo-lipton, glitch, faulty-signature, gcd, dp, dq, qinv, garner, signature, smartcard, rowhammer, differential-fault-analysis, dfa]
difficulty: medium
summary: "One faulty CRT-RSA signature plus the message gives gcd(s^e - m, n) = p; with a correct signature too, gcd(s - s', n) = q."
when_to_use:
  - "A signing service occasionally returns a wrong signature (glitch, voltage, 'lucky' flag)"
  - "The challenge gives you one valid and one invalid signature of the same message"
  - "Source computes sp = pow(m, dp, p) and sq = pow(m, dq, q) and never verifies the result"
  - "A hardware/embedded challenge mentions fault injection, glitching, or Rowhammer"
  - "You can ask for the same signature twice and the answers differ"
tools: [python3, openssl, gmpy2]
related: [rsa-known-phi-known-d, rsa-signature-forgery-e3, rsa-blinding-decrypt-oracle]
---

## TL;DR

CRT-RSA signs with `s_p = m^dp mod p`, `s_q = m^dq mod q`, then recombines. If exactly one
half is computed wrongly, the result `s'` is correct mod `p` and wrong mod `q`. Then
`s'^e - m` is divisible by `p` but not by `q`, so

```
p = gcd(s'^e - m mod n, n)
```

One faulty signature is enough. If you have a correct `s` as well, `gcd(s - s', n) = q` -
even simpler, and it works with randomized padding too.

## Recognise it

- Signing code has `dp`, `dq`, `qinv`, `Garner`, or `crt` in it and no verification step.
- A service returns different signatures for the same message, or a "sometimes corrupted"
  signature.
- A challenge hands you `(m, s_good, s_bad)` or `(m, s_bad)`.
- Hardware CTF: glitch the target during the signature, keep every output, then run the gcd
  over all of them.
- OpenSSL / library CVEs about "missing CRT verification" (this is why libraries verify the
  signature before returning it).

## Theory

Standard CRT recombination (Garner):

$$s = s_q + q \cdot \left[ (s_p - s_q) q^{-1} \bmod p \right], \quad
s_p = m^{d_p} \bmod p,\ s_q = m^{d_q} \bmod q$$

Suppose the computation of $s_q$ is faulted to $\hat s_q \ne s_q$. Then the returned
$\hat s$ satisfies

$$\hat s \equiv s \pmod p, \qquad \hat s \not\equiv s \pmod q$$

Raising to the public exponent, $\hat s^e \equiv m \pmod p$ but $\hat s^e \not\equiv m
\pmod q$. Hence $p \mid (\hat s^e - m)$ and $q \nmid (\hat s^e - m)$:

$$p = \gcd(\hat s^{e} - m \bmod n,\; n)$$

With a correct signature in hand, $s - \hat s \equiv 0 \pmod p$ and $\ne 0 \pmod q$ gives
$p = \gcd(s - \hat s, n)$ without needing to know the padded message at all.

The message you feed the gcd must be the **padded** one that was actually signed. For
PKCS#1 v1.5 that is deterministic and reconstructable; for PSS it is not, which is why the
two-signature variant matters.

## Attack

1. Collect `(message, faulty_signature)` - and a correct signature if you can.
2. Rebuild the exact integer that was signed (raw `m`, or the full EMSA-PKCS1-v1_5 block).
3. `p = gcd(pow(s_bad, e, n) - m_padded, n)`; if that is 1, try `gcd(s_good - s_bad, n)`.
4. `q = n // p`, `d = pow(e, -1, (p-1)*(q-1))`.
5. Sign/decrypt anything.

## Code

```python
#!/usr/bin/env python3
"""Bellcore CRT fault attack, with a faulty signer to test against.

    python3 rsa_crt_fault.py            # self-test
    python3 rsa_crt_fault.py N E M SBAD [SGOOD]
"""
from __future__ import annotations

import hashlib
import random
import sys
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


ASN1_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def pkcs1_v15_sign_block(msg: bytes, k: int) -> int:
    """The integer that a PKCS#1 v1.5 signer actually raises to d."""
    di = ASN1_SHA256 + hashlib.sha256(msg).digest()
    block = b"\x00\x01" + b"\xff" * (k - 3 - len(di)) + b"\x00" + di
    return bytes_to_long(block)


# ------------------------------- the target -------------------------------- #
class CrtSigner:
    """A CRT-RSA signer that can be faulted, like a glitched smartcard."""

    def __init__(self, p: int, q: int, e: int = 65537):
        self.p, self.q, self.e = p, q, e
        self.n = p * q
        self.dp = pow(e, -1, p - 1)
        self.dq = pow(e, -1, q - 1)
        self.qinv = pow(q, -1, p)

    def sign(self, m: int, fault: bool = False, rng=random) -> int:
        sp = pow(m, self.dp, self.p)
        sq = pow(m, self.dq, self.q)
        if fault:                       # a single bit flip in the mod-q half
            sq ^= 1 << rng.randrange(self.q.bit_length())
            sq %= self.q
        h = (self.qinv * (sp - sq)) % self.p
        return (sq + h * self.q) % self.n


# ------------------------------- the attack -------------------------------- #
def factor_from_faulty_signature(n: int, e: int, m_padded: int, s_bad: int):
    """One faulty signature + the exact signed integer -> p."""
    g = gcd((pow(s_bad, e, n) - m_padded) % n, n)
    if 1 < g < n:
        return g, n // g
    return None


def factor_from_two_signatures(n: int, s_good: int, s_bad: int):
    """A correct and a faulty signature of the SAME message -> p. Padding-agnostic."""
    g = gcd((s_good - s_bad) % n, n)
    if 1 < g < n:
        return g, n // g
    return None


def break_it(n: int, e: int, m_padded: int | None, s_bad: int,
             s_good: int | None = None):
    res = None
    if m_padded is not None:
        res = factor_from_faulty_signature(n, e, m_padded, s_bad)
    if res is None and s_good is not None:
        res = factor_from_two_signatures(n, s_good, s_bad)
    if res is None:
        return None
    p, q = res
    d = pow(e, -1, (p - 1) * (q - 1))
    return {"p": p, "q": q, "d": d}


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    random.seed(1009)

    p, q = getPrime(512), getPrime(512)
    e = 65537
    signer = CrtSigner(p, q, e)
    n = signer.n
    k = (n.bit_length() + 7) // 8

    # --- raw (textbook) signature, one fault -------------------------------- #
    m = bytes_to_long(b"sign me")
    s_ok = signer.sign(m)
    s_bad = signer.sign(m, fault=True)
    assert pow(s_ok, e, n) == m
    assert pow(s_bad, e, n) != m
    res = factor_from_faulty_signature(n, e, m, s_bad)
    assert res is not None and set(res) == {p, q}, "single-fault attack failed"
    print("[+] one faulty raw signature -> factored n")

    # --- two signatures, padding irrelevant --------------------------------- #
    res = factor_from_two_signatures(n, s_ok, s_bad)
    assert res is not None and set(res) == {p, q}
    print("[+] good + faulty signature -> factored n (padding-agnostic)")

    # --- realistic PKCS#1 v1.5 signature ------------------------------------ #
    msg = b"transfer 1 BTC to alice"
    m_pad = pkcs1_v15_sign_block(msg, k)
    s_bad = signer.sign(m_pad, fault=True)
    out = break_it(n, e, m_pad, s_bad)
    assert out is not None and {out["p"], out["q"]} == {p, q}
    print("[+] pkcs1 v1.5 faulty signature -> factored n")

    # forge a correct signature with the recovered key
    forged = pow(m_pad, out["d"], n)
    assert pow(forged, e, n) == m_pad
    print("[+] recovered d and produced a valid signature")

    # --- a non-faulty signature must NOT leak anything ---------------------- #
    assert factor_from_faulty_signature(n, e, m_pad, pow(m_pad, out["d"], n)) is None
    print("[+] correct signatures leak nothing, as expected")

    # --- 20 glitches, count how many are exploitable ------------------------ #
    hits = 0
    for _ in range(20):
        sb = signer.sign(m_pad, fault=True)
        if factor_from_faulty_signature(n, e, m_pad, sb):
            hits += 1
    print(f"[+] {hits}/20 random single-bit faults were exploitable")
    assert hits >= 18

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) >= 5:
        N, E, M, SBAD = (int(x, 0) for x in sys.argv[1:5])
        SGOOD = int(sys.argv[5], 0) if len(sys.argv) > 5 else None
        print(break_it(N, E, M, SBAD, SGOOD))
    else:
        _selftest()
```

## Variants & pitfalls

- **Use the padded integer**, not the raw message hash. If the signature scheme is
  PKCS#1 v1.5 you can rebuild it exactly; if it is PSS (randomized) you must use the
  two-signature variant.
- **Both halves faulted** -> `gcd` returns 1. Collect more faults.
- **The fault must be in exactly one CRT branch.** A fault in the final recombination or in
  `m` itself does not factor anything.
- **gcd returns n**: the "faulty" signature was actually correct, or the fault hit `m`.
- **Decryption instead of signing**: identical maths. A CRT-RSA *decryption* that leaks a
  faulty plaintext leaks the factorisation the same way.
- **Countermeasure you may have to bypass**: verify `s^e == m` before returning. If the
  service verifies, look for a timing or error-message side channel instead.
- **Collect everything.** In hardware CTFs, save every glitched output with its message;
  run the gcd over the whole set afterwards.

## Tools

```bash
# check whether a signature is valid at all (raw mode shows the block)
openssl rsautl -verify -in sig.bin -pubin -inkey pub.pem -raw -hexdump

# one-liner once you have m, s_bad, n, e
python3 -c 'from math import gcd;print(gcd(pow(<SBAD>,<E>,<N>)-<M>,<N>))'
```

## References

- Boneh, DeMillo, Lipton, "On the Importance of Checking Cryptographic Protocols for
  Faults" (EUROCRYPT 1997) - the Bellcore attack
- A. Lenstra, "Memo on RSA signature generation in the presence of faults" (1996)
- RFC 8017 section 5.1.2 (RSASP1 with CRT): https://www.rfc-editor.org/rfc/rfc8017
