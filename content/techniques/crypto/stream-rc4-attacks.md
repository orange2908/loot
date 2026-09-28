---
title: "RC4 - Keystream Reuse, Output Biases and the FMS Related-Key Attack"
category: crypto
subcategory: stream-cipher
type: technique
tags: [rc4, arc4, stream-cipher, ksa, prga, keystream-reuse, mantin-shamir, second-byte-bias, broadcast-attack, fluhrer-mantin-shamir, fms, wep, weak-iv, related-key, invariance-weakness, xor, nonce, biases, aircrack-ng, pycryptodome]
difficulty: medium
summary: "RC4 has no nonce, so one key means one keystream; its second output byte is zero twice as often as it should be, and IV||key concatenation leaks the key outright."
when_to_use:
  - "A service encrypts several messages with RC4 under one key (no IV/nonce at all)"
  - "The key is built as `IV || secret` or `secret || IV` and you see many IVs"
  - "You have the same plaintext encrypted under many random keys (broadcast)"
  - "The challenge mentions WEP, `arc4`, `ARC4.new(key)`, or `RC4-drop`"
  - "You know part of one plaintext and need the rest of every message"
tools: [pycryptodome, aircrack-ng, cyberchef]
related: [xor-repeating-key, xor-known-plaintext, aes-ctr-nonce-reuse, stream-lfsr-berlekamp-massey]
---

## TL;DR

RC4 turns a key into a keystream and xors. There is no nonce in the algorithm, so
implementations bolt one on by concatenating it with the key - which is exactly what
broke WEP. Three separate attack families:

1. **Keystream reuse.** Same key, two messages: `C1 xor C2 = P1 xor P2`.
2. **Output biases.** `P(Z_2 = 0) ~ 2/256`, double what it should be (Mantin-Shamir).
   Given the same plaintext under many random keys, the second plaintext byte falls
   out of a frequency count.
3. **Related keys.** With `K = IV || secret` and chosen weak IVs `(A+3, 255, X)`, each
   IV leaks a guess at one secret key byte with probability ~5%; vote and you recover
   the key (Fluhrer-Mantin-Shamir, the WEP attack).

## Recognise it

- `from Crypto.Cipher import ARC4; ARC4.new(key)` with a constant key.
- A `rc4(key, data)` helper in the challenge source, key hardcoded or derived from a
  password with no salt.
- Ciphertext length equals plaintext length; no IV field on the wire.
- An IV field that is prepended to the key rather than mixed in properly.
- Many ciphertexts of the same message under different keys ("broadcast").
- `RC4-drop[n]` in the description - someone knew about the biases and dropped output.

## Theory

**KSA** (key scheduling):

```
S = [0..255]; j = 0
for i in 0..255:  j = (j + S[i] + K[i mod len(K)]) % 256; swap(S[i], S[j])
```

**PRGA** (output):

```
i = j = 0
loop: i = (i+1)%256; j = (j+S[i])%256; swap(S[i],S[j]); output S[(S[i]+S[j])%256]
```

**Keystream reuse.** RC4's output depends only on `K`. No nonce, no counter, no
position input. Encrypting two messages under one key is a two-time pad - solve it
with the techniques in `xor-repeating-key`.

**Mantin-Shamir second-byte bias.** If `S[2] = 0` after the KSA (probability `1/256`)
then the second output byte is `0` as well, on top of the uniform `1/256`. Net:

$$P(Z_2 = 0) \approx \frac{2}{256}$$

That is a distinguisher, and in the *broadcast* setting (same plaintext, many random
keys) it is a plaintext recovery: `C_2 = P_2 xor Z_2`, so the most frequent value of
`C_2` across many ciphertexts is `P_2`. Later work (Fluhrer-McGrew, AlFardan et al.)
extended this to biases across the first 256 bytes, which is what made the 2013
RC4-in-TLS attacks practical.

**Fluhrer-Mantin-Shamir.** With `K = IV || secret` and `IV` transmitted in clear
(WEP's design), pick `IV = (A+3, 255, X)`:

- Run the KSA for its first `A+3` steps. Those steps only touch key bytes you already
  know (the 3 IV bytes plus the `A` secret bytes recovered so far), so you can compute
  the state `S` and index `j` at that point.
- These IVs satisfy the *resolved* condition, which means the first output byte `Z_1`
  is, with probability about `e^{-3} ~ 5%`, the value that sat at index
  `S[1] + S[S[1]]` before the rest of the KSA scrambled it.
- Therefore

$$K[A+3] \;=\; S^{-1}[Z_1] - j - S[A+3] \pmod{256}$$

  is right ~5% of the time and uniformly wrong the rest of the time. Collect a few
  thousand `X` values, vote, and the true byte wins by ~3:1. Then move to `A+1`.

Klein's attack and PTW improved this to work with *any* IV, which is why `aircrack-ng`
cracks WEP-104 in minutes with 40k-85k packets.

**Invariance weakness / weak keys.** Certain key classes make part of the permutation
survive the KSA, leaking key bits directly. Rare in CTF but the reason RC4 with a
short key is worse than its key length suggests.

## Attack

1. Confirm there is no nonce. If two ciphertexts of known-different plaintexts xor to
   something printable, you have keystream reuse - go to `xor-repeating-key`.
2. If you have one known plaintext, `KS = C xor P` and every other message is free.
3. If you have the same plaintext under many keys, count byte values at each position;
   position 2 falls immediately, positions 1..256 with more samples.
4. If the key is `IV || secret`, harvest `(IV, first ciphertext byte)` pairs. Subtract
   the known first plaintext byte (in WEP it is the constant `0xAA` SNAP header) to
   get `Z_1`, filter for weak IVs, and vote byte by byte.
5. `RC4-drop[768]` or more kills the bias attacks but not keystream reuse.

## Code

```python
#!/usr/bin/env python3
"""RC4: implementation, keystream reuse, the Mantin-Shamir second-byte bias, a
broadcast plaintext recovery, and the FMS related-key attack on IV||key.

Self-contained; every attack is asserted. Runs in a few seconds.
"""

import os
import random
from collections import Counter

N = 256


# ------------------------------------------------------------------ RC4
def ksa(key: bytes, steps: int = N) -> tuple[list[int], int]:
    """Key scheduling. Returns (S, j) after `steps` iterations."""
    s = list(range(N))
    j = 0
    for i in range(steps):
        j = (j + s[i] + key[i % len(key)]) % N
        s[i], s[j] = s[j], s[i]
    return s, j


def rc4_keystream(key: bytes, n: int) -> bytes:
    s, _ = ksa(key)
    i = j = 0
    out = bytearray()
    for _ in range(n):
        i = (i + 1) % N
        j = (j + s[i]) % N
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) % N])
    return bytes(out)


def rc4(key: bytes, data: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, rc4_keystream(key, len(data))))


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------- 1. keystream reuse
def keystream_from_known(ct: bytes, known_pt: bytes) -> bytes:
    return xor(ct[:len(known_pt)], known_pt)


# ------------------------------------------- 2. Mantin-Shamir / broadcast
def second_byte_distribution(samples: int, key_len: int = 16) -> Counter:
    """Distribution of the SECOND keystream byte over random keys."""
    c: Counter = Counter()
    for _ in range(samples):
        c[rc4_keystream(os.urandom(key_len), 2)[1]] += 1
    return c


def broadcast_recover_byte(ciphertexts: list[bytes], pos: int = 1) -> int:
    """Same plaintext, many random keys: the modal ciphertext byte is the plaintext."""
    return Counter(c[pos] for c in ciphertexts).most_common(1)[0][0]


# ----------------------------------------------------- 3. FMS on IV||key
def fms_recover(collect, secret_len: int, n_iv: int = 6000) -> bytes:
    """Recover `secret` from RC4 keys of the form IV||secret.

    `collect(iv) -> first keystream byte` is the oracle: in WEP this is
    `first_ciphertext_byte xor 0xAA` (the constant SNAP header).
    """
    known: list[int] = []
    for a in range(secret_len):
        votes = [0] * N
        for _ in range(n_iv):
            iv = bytes([a + 3, N - 1, random.randrange(N)])
            # The first a+3 KSA steps only touch bytes we already know.
            s, j = ksa(iv + bytes(known) + b"\x00" * N, a + 3)
            if not (s[1] < a + 3 and (s[1] + s[s[1]]) % N == a + 3):
                continue                       # not a resolved IV
            z1 = collect(iv)
            sinv = [0] * N
            for idx, v in enumerate(s):
                sinv[v] = idx
            votes[(sinv[z1] - j - s[a + 3]) % N] += 1
        known.append(max(range(N), key=lambda v: votes[v]))
    return bytes(known)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    # --- published RC4 test vectors ---------------------------------------
    assert rc4(b"Key", b"Plaintext").hex().upper() == "BBF316E8D940AF0AD3"
    assert rc4(b"Wiki", b"pedia").hex().upper() == "1021BF0420"
    assert rc4(b"Secret", b"Attack at dawn").hex().upper() == \
        "45A01F645FC35B383552544B9BF5"
    assert rc4(b"Key", rc4(b"Key", b"Plaintext")) == b"Plaintext"
    print("[+] PASS RC4 matches the standard test vectors")

    # --- 1. keystream reuse ------------------------------------------------
    key = os.urandom(16)
    m1 = b"GET /admin HTTP/1.1\r\nCookie: session=guest; theme=dark; lang=en\r\n\r\n"
    m2 = b"GET /flag  HTTP/1.1\r\nCookie: flag{rc4_has_no_nonce_at_all}\r\n"
    c1, c2 = rc4(key, m1), rc4(key, m2)
    assert xor(c1, c2) == xor(m1, m2)
    ks = keystream_from_known(c1, m1)
    recovered = xor(c2, ks)
    print("[+] recovered:", recovered)
    assert b"flag{rc4_has_no_nonce_at_all}" in recovered
    print("[+] PASS keystream reuse (one known plaintext breaks every message)")

    # --- 2. the second-byte bias -------------------------------------------
    SAMPLES = 40000
    dist = second_byte_distribution(SAMPLES)
    p_zero = dist[0] / SAMPLES
    print(f"[+] P(Z2 == 0) = {p_zero:.5f}   uniform would be {1/256:.5f}")
    assert p_zero > 1.5 / 256, p_zero
    print("[+] PASS Mantin-Shamir bias is measurably ~2/256")

    # --- 2b. broadcast plaintext recovery ----------------------------------
    PLAIN = b"\x00SECRET-BROADCAST-MESSAGE"
    cts = [rc4(os.urandom(16), PLAIN) for _ in range(SAMPLES)]
    got = broadcast_recover_byte(cts, pos=1)
    print(f"[+] recovered plaintext byte 1 = {got!r}, true = {PLAIN[1]!r}")
    assert got == PLAIN[1]
    print("[+] PASS broadcast attack recovers byte 1 with no key at all")

    # --- 3. FMS related-key attack on IV||secret ---------------------------
    random.seed()
    SECRET = bytes(random.randrange(N) for _ in range(5))   # WEP-40 style

    def wep_oracle(iv: bytes) -> int:
        """A WEP station: encrypts a packet whose first plaintext byte is 0xAA."""
        packet = bytes([0xAA]) + os.urandom(32)
        ct = rc4(iv + SECRET, packet)
        return ct[0] ^ 0xAA                    # = first keystream byte

    found = fms_recover(wep_oracle, len(SECRET))
    print("[+] FMS recovered:", found.hex(), " true:", SECRET.hex())
    assert found == SECRET, (found.hex(), SECRET.hex())
    print("[+] PASS FMS recovered the whole secret key from weak IVs")

    # ...and the key decrypts real traffic
    iv = os.urandom(3)
    msg = b"flag{fluhrer_mantin_shamir_killed_wep}"
    assert rc4(iv + found, rc4(iv + SECRET, msg)) == msg
    print("[+] PASS recovered key decrypts traffic under any IV")

    print("\nall checks passed")
```

## Variants & pitfalls

- **`RC4-drop[n]`** discards the first `n` output bytes (768 or 3072 are common).
  That kills the second-byte bias and FMS, but keystream reuse is untouched.
- **The bias attacks need *many* samples.** 50k here for a clean signal on byte 2. For
  the later-position biases (Fluhrer-McGrew) you need `2^24`+ ciphertexts, which is a
  paper result, not a CTF move.
- **`ARC4.new` in pycryptodome** takes `drop=` as a keyword; check whether the
  challenge used it before assuming the biases are live.
- **`K = secret || IV`** (IV appended, not prepended) is not vulnerable to FMS, but it
  is still vulnerable to Klein/PTW-style correlations and to keystream reuse if the
  IV repeats.
- **IV repetition.** WEP's 24-bit IV repeats after ~16.7M packets, or far sooner with
  a bad PRNG. Two packets with the same IV is an instant two-time pad.
- **Short keys.** RC4 with a 5-byte key is 40 bits; just brute-force it if you have a
  known-plaintext check. `2^40` is hours on a GPU, minutes with a few known bytes
  narrowing the search.
- **RC4 is removed from TLS** (RFC 7465) precisely because of these biases. Any
  challenge that says "modern protocol uses RC4" is telling you the intended path.
- **Do not confuse the KSA `j` with the PRGA `j`.** They are different variables; the
  PRGA restarts with `i = j = 0`.

## Tools

- `pycryptodome` - `from Crypto.Cipher import ARC4; ARC4.new(key, drop=0)`.
- `aircrack-ng` - production FMS/Klein/PTW implementation against WEP captures.
- CyberChef - "RC4" and "RC4 Drop" operations for quick manual decryption.

## References

- Fluhrer, Mantin, Shamir, "Weaknesses in the Key Scheduling Algorithm of RC4"
  (SAC 2001) - the weak-IV attack implemented above.
- Mantin, Shamir, "A Practical Attack on Broadcast RC4" (FSE 2001) - the second-byte
  bias.
- RFC 7465 prohibits RC4 cipher suites in TLS.
