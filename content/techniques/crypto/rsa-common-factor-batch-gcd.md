---
title: "RSA - Shared Prime / Batch GCD Across Many Moduli"
category: crypto
subcategory: rsa
type: technique
tags: [rsa, batch-gcd, common-factor, shared-prime, gcd, greatest-common-divisor, product-tree, remainder-tree, mining-your-ps-and-qs, weak-randomness, factordb, many-keys, pairwise-gcd, keyfile-dump, rsactftool]
difficulty: easy
summary: "Two RSA moduli generated with bad entropy share a prime -> gcd(n1, n2) factors both instantly; batch GCD does it for millions of keys."
when_to_use:
  - "You are handed more than one modulus (a keys.txt, a certificate dump, many pubkeys)"
  - "A service issues a fresh RSA key per connection from a weak PRNG"
  - "n is 2048 bits so nothing else is feasible, but there are 50 of them"
  - "Challenge title mentions 'entropy', 'embedded device', 'ps and qs', 'batch'"
  - "One modulus alone is unbreakable but the challenge gives you a whole set"
tools: [python3, gmpy2, factordb, rsactftool, openssl]
related: [rsa-weak-keygen-roca-e-gcd-phi, rsa-fermat-close-primes]
---

## TL;DR

RSA security needs `p` and `q` to be *secret*, but also *unique*. Devices that generate keys
with a low-entropy PRNG re-use primes across keys. If two moduli share a prime,
`gcd(n1, n2)` is that prime and both keys die in microseconds. With `k` moduli, the naive
approach is `k^2/2` gcds; the product/remainder tree ("batch GCD") does it in
`O(k log^2 k)` and scales to millions of TLS keys.

## Recognise it

- The handout is a *list*: `moduli.txt`, `keys/*.pem`, a PCAP full of certificates.
- A netcat service gives you a new `n` every connection.
- `n` is large (2048+) and there is no other structural weakness.
- The flag text or challenge name references "Mining your Ps and Qs", entropy, routers,
  IoT, embedded, "factory keys".
- Two of the moduli have the same top bits? Irrelevant - just run the gcd.

## Theory

For each pair $i \ne j$, $\gcd(n_i, n_j) \in \{1, p\}$. If it is $p \ne 1$ then
$q_i = n_i / p$ and $q_j = n_j / p$, so both private keys follow immediately:
$\varphi = (p-1)(q-1)$, $d = e^{-1} \bmod \varphi$.

Batch GCD (Bernstein): build the product tree $P = \prod n_i$, then compute the remainder
tree of $P$ modulo each $n_i^2$. The classical result is

$$\gcd\left(n_i, \frac{P \bmod n_i^2}{n_i}\right) = \gcd\left(n_i, \prod_{j \ne i} n_j\right)$$

which is $p$ exactly when $n_i$ shares a prime with some other modulus. The $n_i^2$ trick
is what makes the division exact.

Careful: if a modulus appears **twice** in the list, its gcd with the product is `n` itself,
not a prime. De-duplicate first.

## Attack

1. Collect every modulus you can (parse PEMs/DERs/certs with `openssl` if needed).
2. De-duplicate.
3. Run pairwise gcd for small lists (< ~2000 moduli), batch gcd otherwise.
4. For each hit: `p = gcd`, `q = n // p`, `d = pow(e, -1, (p-1)*(q-1))`, decrypt.
5. Also gcd every modulus against any *other* big integers lying around in the challenge
   (a "signature", a "hash", the flag file) - authors hide primes in odd places.

## Code

```python
#!/usr/bin/env python3
"""Shared-prime detection: pairwise GCD and Bernstein batch GCD.

    python3 rsa_batch_gcd.py                # self-test
    python3 rsa_batch_gcd.py moduli.txt     # one decimal-or-hex modulus per line
"""
from __future__ import annotations

import sys
from math import gcd

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


# --------------------------------------------------------------------------- #
# 1. naive pairwise - fine up to a couple of thousand moduli
# --------------------------------------------------------------------------- #
def pairwise_gcd(moduli: list[int]) -> list[tuple[int, int, int]]:
    """Return [(i, j, shared_prime), ...] for every colliding pair."""
    hits = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if g != 1:
                hits.append((i, j, g))
    return hits


# --------------------------------------------------------------------------- #
# 2. batch GCD (product tree + remainder tree) - O(k log^2 k)
# --------------------------------------------------------------------------- #
def product_tree(ns: list[int]) -> list[list[int]]:
    """levels[0] == ns, last level == [prod(ns)]."""
    levels = [list(ns)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([cur[i] * cur[i + 1] if i + 1 < len(cur) else cur[i]
                       for i in range(0, len(cur), 2)])
    return levels


def batch_gcd(ns: list[int]) -> list[int]:
    """For each n_i return gcd(n_i, prod of all the others).

    Result is 1 for a safe modulus, a prime for a modulus sharing a factor, and
    n_i itself if that exact modulus appears twice in the list.
    """
    if len(ns) == 1:
        return [1]
    levels = product_tree(ns)
    rem = levels[-1]
    for i in range(len(levels) - 2, -1, -1):
        cur = levels[i]
        rem = [rem[j // 2] % (cur[j] ** 2) for j in range(len(cur))]
    return [gcd(rem[i] // ns[i], ns[i]) for i in range(len(ns))]


def crack_from_shared_prime(n: int, p: int, e: int = 65537) -> dict:
    """Build the full private key once a factor is known."""
    assert n % p == 0, "p does not divide n"
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return {"p": p, "q": q, "phi": phi, "d": d, "e": e, "n": n}


def decrypt(c: int, key: dict) -> bytes:
    return long_to_bytes(pow(c, key["d"], key["n"]))


def load_moduli(path: str) -> list[int]:
    out = []
    for line in open(path):
        line = line.strip().replace("_", "")
        if not line or line.startswith("#"):
            continue
        out.append(int(line, 0) if line.lower().startswith("0x") else int(line))
    return out


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    import random
    import time
    random.seed(4242)

    # 24 moduli, two of which share a prime with each other
    shared = getPrime(256)
    moduli, primes = [], []
    for _ in range(24):
        a, b = getPrime(256), getPrime(256)
        moduli.append(a * b)
        primes.append((a, b))
    moduli[7] = shared * getPrime(256)
    moduli[19] = shared * getPrime(256)

    t0 = time.time()
    res = batch_gcd(moduli)
    dt = time.time() - t0
    hits = [i for i, g in enumerate(res) if g != 1]
    assert hits == [7, 19], f"batch gcd found {hits}"
    assert res[7] == shared and res[19] == shared
    print(f"[+] batch gcd found colliding moduli {hits} in {dt*1000:.1f} ms")

    # cross-check against the naive version
    pw = pairwise_gcd(moduli)
    assert len(pw) == 1 and pw[0][:2] == (7, 19) and pw[0][2] == shared
    print("[+] pairwise gcd agrees")

    # full key recovery + decryption
    e = 65537
    flag = b"CTF{two_devices_one_prime}"
    key = crack_from_shared_prime(moduli[7], res[7], e)
    c = pow(bytes_to_long(flag), e, moduli[7])
    assert decrypt(c, key) == flag
    print("[+] decrypted:", decrypt(c, key).decode())

    # duplicate-modulus edge case
    dup = moduli[:4] + [moduli[0]]
    r = batch_gcd(dup)
    assert r[0] == moduli[0] and r[4] == moduli[0], "duplicate handling"
    print("[+] duplicate modulus correctly reported as n itself")

    print("[*] all self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        ns = load_moduli(sys.argv[1])
        print(f"[i] loaded {len(ns)} moduli")
        for i, g in enumerate(batch_gcd(ns)):
            if g == 1:
                continue
            if g == ns[i]:
                print(f"[!] modulus {i} is duplicated in the list")
            else:
                print(f"[+] modulus {i}: p = {g}")
                print(f"    q = {ns[i] // g}")
    else:
        _selftest()
```

## Variants & pitfalls

- **De-duplicate first.** Repeated moduli make `batch_gcd` return `n` instead of a prime.
- **Memory.** The product of a million 2048-bit moduli is a 2 Gbit integer. Chunk the list
  (e.g. 10k at a time) or use `gmpy2.mpz`, which is 10-50x faster than Python ints here.
- **Also gcd across challenges.** If the CTF gives several RSA tasks, try gcd of every
  modulus in the whole event; authors reuse generator scripts.
- **Not just pairs.** A prime may be shared by three or more moduli; `batch_gcd` flags all of
  them, then you re-run on the survivors.
- **Trailing junk in the file.** `int(line)` chokes on `n = 0x...`; strip labels first.
- If the moduli do *not* share primes, check for: close primes (`rsa-fermat-close-primes`),
  ROCA structure (`rsa-weak-keygen-roca-e-gcd-phi`), or smooth `p-1` (`rsa-pollard-p-minus-1`).
- **factordb** may already know the factorisation of a CTF modulus. Always ask it first.

## Tools

```bash
# pull the modulus out of every public key / certificate in a directory
for f in keys/*.pem; do openssl rsa -pubin -in "$f" -text -noout | \
    tr -d ' \n:' | sed -n 's/.*Modulus(\?[0-9]*bit)\?:\(.*\)Exponent.*/\1/p'; done

# cleaner: one modulus per line, decimal, via python
python3 -c '
import sys,glob
from Crypto.PublicKey import RSA
for f in glob.glob("keys/*.pem"):
    print(RSA.import_key(open(f).read()).n)'

# gcd of just two moduli
python3 -c 'from math import gcd;print(gcd(<N1>, <N2>))'

# RsaCtfTool across a directory of keys
python3 RsaCtfTool.py --publickey "keys/*.pem" --private --attack common_factors
```

## References

- Heninger, Durumeric, Wustrow, Halderman, "Mining Your Ps and Qs: Detection of Widespread
  Weak Keys in Network Devices" (USENIX Security 2012)
- D. J. Bernstein, "How to find smooth parts of integers" (batch gcd / product trees)
- factordb: http://factordb.com/
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
