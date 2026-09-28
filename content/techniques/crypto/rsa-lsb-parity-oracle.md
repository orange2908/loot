---
title: "RSA - LSB / Parity Oracle Decryption"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, lsb-oracle, parity-oracle, least-significant-bit, lsb, binary-search, homomorphic, malleability, chosen-ciphertext, cca, oracle, decryption-oracle, half-oracle, byte-oracle, fractions, netcat-service, pwntools]
difficulty: medium
summary: "A server that leaks one bit (m mod 2, or 'is m > n/2') for chosen ciphertexts reveals the whole plaintext in log2(n) queries by binary search."
when_to_use:
  - "A service decrypts anything you send and returns only the parity / last bit / 'even or odd'"
  - "The oracle answers 'is the plaintext bigger than n/2' or returns m mod 2^k"
  - "You can send ~1024-2048 chosen ciphertexts and get one bit back each time"
  - "Unpadded (textbook) RSA decryption on the server side"
  - "The service returns the last digit, the colour of a lamp, or any 1-bit function of m"
tools: [python3, pwntools, fractions]
source:
  name: "CTF Wiki - RSA parity oracle"
  url: "https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/"
related: [rsa-blinding-decrypt-oracle, rsa-bleichenbacher-pkcs1, rsa-crt-fault-attack]
---

## TL;DR

Textbook RSA is homomorphic: `enc(2m) = c * 2^e mod n`. Asking the oracle for the parity of
`2^i * m mod n` tells you whether the repeated doubling wrapped around `n`, which is exactly
one bit of a binary search on `m`. After `log2(n)` queries (1024 for a 1024-bit modulus) the
interval has collapsed to a single integer. Use `fractions.Fraction` for the bounds,
never floats.

## Recognise it

- `nc host port` gives you "send me a ciphertext, I will tell you if the plaintext is even".
- The server code does `return pow(c, d, n) % 2` or `... & 1` or `... % 2 == 0`.
- A "lamp/coin/parity" theme, or the server returns `True/False` per query.
- Variant: the oracle says whether `m > n/2` (a "half oracle") - identical binary search,
  one shift in the logic.
- Variant: the server returns `m % 256` (a byte oracle) - 8 bits per query, 8x fewer rounds.

## Theory

Let $c_i = c \cdot 2^{ie} \bmod n$, so $\mathrm{dec}(c_i) = 2^i m \bmod n$.

$2m \bmod n$ is even iff $2m < n$ (no wraparound), because $2m$ is even and subtracting the
odd $n$ makes it odd. So:

- parity of $\mathrm{dec}(2c)$ is **even** $\Rightarrow m < n/2$
- parity is **odd** $\Rightarrow m \ge n/2$

Iterating, after $i$ steps the plaintext is known to lie in an interval of width $n/2^i$.
Maintain exact rational bounds $\text{lo}, \text{hi}$ and halve:

$$\text{mid} = \frac{\text{lo}+\text{hi}}{2}, \quad
\text{odd} \Rightarrow \text{lo} \leftarrow \text{mid}, \quad
\text{even} \Rightarrow \text{hi} \leftarrow \text{mid}$$

After $\lceil \log_2 n \rceil$ iterations, `int(hi)` (sometimes `int(hi) - 1` or
`int(lo) + 1`) is the plaintext. Always verify by re-encrypting.

## Attack

1. Confirm the oracle really returns `dec(c) & 1` (send `enc(2)` and `enc(3)` if you have
   the public key - `2` is even, `3` is odd).
2. `lo, hi = Fraction(0), Fraction(n)`.
3. For `i` in `range(n.bit_length())`: query `c * pow(2, e*(i+1), n) % n`,
   halve the interval accordingly.
4. Take `m = int(hi)`; check `pow(m, e, n) == c`; if not, scan `m-2 .. m+2`.
5. `long_to_bytes(m)`.

## Code

```python
#!/usr/bin/env python3
"""RSA LSB / parity oracle attack, with a local simulated oracle for self-test.

    python3 rsa_lsb_oracle.py             # self-test against a simulated oracle
    (plug `remote_oracle` into `lsb_oracle_attack` for a real netcat service)
"""
from __future__ import annotations

from fractions import Fraction

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


def lsb_oracle_attack(n: int, e: int, c: int, oracle, verbose: bool = True) -> int:
    """oracle(ciphertext) -> 0/1, the least significant bit of the plaintext."""
    lo, hi = Fraction(0), Fraction(n)
    mult = 1
    for i in range(n.bit_length()):
        mult = mult * pow(2, e, n) % n           # 2^((i+1)e) mod n
        bit = oracle(c * mult % n)
        mid = (lo + hi) / 2
        if bit:
            lo = mid                              # wrapped: m is in the upper half
        else:
            hi = mid
        if verbose and i % 128 == 0:
            print(f"    [{i:4d}/{n.bit_length()}] interval width "
                  f"~2^{int(hi - lo).bit_length()}")
    # the answer is one of the few integers left in [lo, hi]
    for cand in range(int(lo) - 2, int(hi) + 3):
        if cand >= 0 and pow(cand, e, n) == c % n:
            return cand
    return int(hi)


def half_oracle_attack(n: int, e: int, c: int, oracle) -> int:
    """Variant where oracle(ct) -> 1 iff dec(ct) > n/2 (a 'is it big' oracle).

    Same binary search, the bit has the opposite meaning.
    """
    lo, hi = Fraction(0), Fraction(n)
    mult = 1
    for _ in range(n.bit_length()):
        # NOTE: unlike the parity oracle, the FIRST query uses the untouched c:
        # bit i of the binary expansion of m/n is 'is 2^i*m mod n > n/2'.
        big = oracle(c * mult % n)
        mid = (lo + hi) / 2
        if big:
            lo = mid
        else:
            hi = mid
        mult = mult * pow(2, e, n) % n
    for cand in range(int(lo) - 2, int(hi) + 3):
        if cand >= 0 and pow(cand, e, n) == c % n:
            return cand
    return int(hi)


def byte_oracle_attack(n: int, e: int, c: int, oracle) -> int:
    """Oracle returns dec(ct) mod 256: 8 bits per query instead of 1.

    Let K_i = floor(256^i * m / n).  Querying dec(c * 256^((i+1)e)) gives
        u = 256^(i+1) m - K_{i+1} n ,  and  u mod 256 = (-K_{i+1} * n) mod 256
    because 256^(i+1) m is divisible by 256.  n is odd, so
        K_{i+1} mod 256 = -u * n^(-1) mod 256
    and K_{i+1} mod 256 is exactly which of the 256 sub-intervals m falls into.
    """
    inv_n = pow(n % 256, -1, 256)
    lo, hi = Fraction(0), Fraction(n)
    mult = 1
    k = pow(256, e, n)
    for _ in range((n.bit_length() + 7) // 8 + 1):
        mult = mult * k % n
        low_byte = oracle(c * mult % n)
        t = (-low_byte * inv_n) % 256
        width = (hi - lo) / 256
        lo, hi = lo + t * width, lo + (t + 1) * width
    for cand in range(int(lo) - 2, int(hi) + 3):
        if cand >= 0 and pow(cand, e, n) == c % n:
            return cand
    return int(hi)


# ------------------------- talking to a real service ------------------------ #
def remote_oracle_template(host: str, port: int):
    """Sketch for a pwntools-backed oracle. Adapt the prompts to the challenge.

    from pwn import remote
    io = remote(host, port)
    def oracle(ct: int) -> int:
        io.sendlineafter(b'ciphertext: ', str(ct).encode())
        return int(io.recvline().strip())
    return oracle
    """
    raise NotImplementedError("copy the docstring body and adapt it to the service")


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    import time
    random.seed(11)

    p, q = getPrime(256), getPrime(256)
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    flag = b"CTF{one_bit_per_query_is_enough}"
    m = bytes_to_long(flag)
    assert m < n
    c = pow(m, e, n)

    calls = {"n": 0}

    def parity_oracle(ct: int) -> int:
        calls["n"] += 1
        return pow(ct, d, n) & 1

    t0 = time.time()
    rec = lsb_oracle_attack(n, e, c, parity_oracle, verbose=False)
    assert rec == m, "LSB oracle attack failed"
    print(f"[+] parity oracle: recovered {len(flag)} bytes in {calls['n']} queries, "
          f"{time.time()-t0:.2f}s")
    print("    flag:", long_to_bytes(rec).decode())

    # half oracle ("is the plaintext > n/2")
    calls["n"] = 0

    def half_oracle(ct: int) -> int:
        calls["n"] += 1
        return int(pow(ct, d, n) > n // 2)

    rec = half_oracle_attack(n, e, c, half_oracle)
    assert rec == m, "half oracle attack failed"
    print(f"[+] half oracle: ok in {calls['n']} queries")

    # byte oracle
    calls["n"] = 0

    def byte_oracle(ct: int) -> int:
        calls["n"] += 1
        return pow(ct, d, n) % 256

    rec = byte_oracle_attack(n, e, c, byte_oracle)
    assert rec == m, "byte oracle attack failed"
    print(f"[+] byte oracle: ok in {calls['n']} queries (8 bits per query)")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    _selftest()
```

## Variants & pitfalls

- **Floats destroy this attack.** `lo = (lo+hi)/2` in float loses precision after 53 bits.
  Use `Fraction`, or integer bounds with the classic `lo = (lo+hi)//2` + off-by-one sweep.
- **Off-by-one at the end**: always verify with `pow(m, e, n) == c` and scan a few
  neighbours. Rounding makes the last 1-2 bits unreliable.
- **Oracle returns "even/odd" as text**: normalise to 0/1 before feeding the search.
- **The oracle refuses the original ciphertext** (a blacklist): multiply by `r^e` first, see
  `rsa-blinding-decrypt-oracle`. The parity attack already sends modified ciphertexts, so
  this is rarely a problem.
- **Padded decryption** (PKCS#1 v1.5 / OAEP) is not a parity oracle; if the server only says
  "valid padding / invalid padding", you want Bleichenbacher instead.
- **Query budget.** The attack needs exactly `log2(n)` queries. If the service limits you to
  100, look for a byte oracle or a different bug.
- **Slow networks**: batch with pwntools, keep the connection open, and log every answer so
  a disconnect does not cost you the run.
- The same doubling trick with `m mod 2` also works modulo a *prime* oracle, and the
  identical binary search underpins many "decryption oracle leaks one bit" challenges in
  other cryptosystems (Paillier, ElGamal).

## Tools

```bash
# quick interactive probe of a parity service
python3 -c '
from pwn import remote
io = remote("host", 1337)
io.sendlineafter(b"> ", b"1")   # enc(1) should decrypt to 1 -> odd
print(io.recvline())'
```

## References

- CTF Wiki, RSA oracle attacks: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/
- Original idea: Goldwasser-Micali-Tong hardcore-bit results; the CTF form is folklore.
