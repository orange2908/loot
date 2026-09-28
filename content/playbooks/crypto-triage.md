---
title: "Playbook - Crypto Challenge Triage"
category: crypto
subcategory: triage
type: playbook
tags: [crypto-triage, what-attack, where-to-start, stuck, rsa, aes, ecb, cbc, xor, lcg, prng, ecc, dlog, lattice, padding-oracle, hash-length-extension, cipher-identification, oracle, nc-service, sagemath]
summary: "Sort any crypto challenge into an attack family by what you were given: parameters, a service, a ciphertext blob, or source code."
when_to_use:
  - "You opened a crypto challenge and do not know which attack family it belongs to"
  - "You have n/e/c and need to know if it is factorable"
  - "You have `nc host port` that does something cryptographic"
  - "You have an opaque ciphertext and no key"
related: [rsa-decision-tree, remote-service, cipher-identification, math-constants-and-identities, source-code-given]
---

## TL;DR

Crypto challenges split by **what you were handed**. Find your row, go to that section.

| You were given | Section |
|---|---|
| `n`, `e`, `c` (and maybe more) | [1. RSA](#1-you-have-rsa-parameters) |
| A `nc host port` that encrypts/decrypts on demand | [2. Oracle](#2-you-have-an-interactive-oracle) |
| A blob of letters/numbers and nothing else | [3. Blob](#3-you-have-a-ciphertext-blob-only) |
| Python/Sage source implementing a scheme | [4. Source](#4-you-have-source-code) |
| A curve, a point `G`, a point `P = kG` | [5. ECC/DLOG](#5-you-have-ecc-or-a-discrete-log) |
| A hash, or `sha256(secret + data)` | [6. Hashes](#6-you-have-hashes) |
| A stream of outputs from a "random" generator | [7. PRNG](#7-you-have-prng-output) |
| AES with a mode name visible | [8. Symmetric](#8-you-have-a-symmetric-cipher) |

---

## 0. Always do this first (2 minutes)

```sh
# 1. does the 'ciphertext' just decode to something already?
python3 -c "
import base64, binascii
d = open('ct.txt','rb').read().strip()
for name, fn in (('hex', binascii.unhexlify), ('b64', base64.b64decode), ('b32', base64.b32decode)):
    try:
        print(name, fn(d)[:80])
    except Exception:
        pass"
# 2. if the 'ciphertext' is a big integer, check its size in bits - it tells you the modulus size
python3 -c "c=0xDEADBEEF; print(c.bit_length())"
# 3. is the plaintext short enough to be unpadded? is c a perfect e-th root?
python3 -c "
from gmpy2 import iroot
c=<c>; e=3
r,ok=iroot(c,e); print(ok, bytes.fromhex(hex(int(r))[2:]) if ok else '')"
# 4. try the dumb things: is n on factordb? is the key 'password'?
curl -s 'http://factordb.com/api?query=<n>' | head -c 400
```

Also: **read the flag format**. If the flag is 30 bytes and the modulus is 1024 bits, the message is tiny -> small-message attacks apply.

---

## 1. You have RSA parameters

Go straight to the lookup table: `ctfbrain search rsa-decision-tree`.

Quick pre-filter:

```sh
# throw everything at RsaCtfTool first; it covers ~20 classic attacks in one shot
RsaCtfTool --publickey key.pub --uncipherfile cipher.bin --attack all
# or with raw numbers
RsaCtfTool -n <n> -e <e> --uncipher <c> --attack all
```

| Observation | Attack |
|---|---|
| `e` is 3 or 5 and the message is short | small-e root / cube root |
| Two ciphertexts, same `n`, different `e` | common modulus |
| Two moduli share a factor | `gcd(n1,n2)` |
| `d` is small (large `e`, `e` ~ `n`) | Wiener / Boneh-Durfee |
| `n` is a perfect power or `p == q` | `iroot(n, k)` |
| `p` and `q` are close | Fermat factorisation |
| `p-1` is smooth | Pollard p-1 |
| `p+1` is smooth | Williams p+1 |
| Part of `p` known | Coppersmith |
| `c` and `c'` related by a known polynomial | Franklin-Reiter / related message |
| LSB/parity oracle available | LSB oracle -> section 2 |
| PKCS#1 v1.5 padding error distinguishable | Bleichenbacher -> section 2 |
| `n` under ~350 bits | just factor it (`factordb`, `yafu`, `cado-nfs`) |

---

## 2. You have an interactive oracle

Fingerprint the service first: `ctfbrain search remote-service`.

Then classify by **what it lets you do**:

| The service lets you... | Attack | Search |
|---|---|---|
| Submit ciphertext, learn valid/invalid padding | CBC padding oracle (decrypt + forge) | `ctfbrain search padding-oracle` |
| Submit ciphertext, learn the plaintext's LSB/parity | RSA LSB oracle (binary search the plaintext) | `ctfbrain search rsa-lsb-oracle` |
| Decrypt anything except the target | RSA blinding: send `c * r^e`, divide by `r` | `ctfbrain search rsa-blinding-chosen-ciphertext` |
| Encrypt `prefix \|\| secret` under ECB | ECB byte-at-a-time decryption | `ctfbrain search ecb-byte-at-a-time` |
| Encrypt chosen plaintext under CBC with a fixed IV | CBC bit-flipping / IV recovery | `ctfbrain search cbc-bit-flipping` |
| Encrypt with a nonce it reuses | CTR/GCM nonce reuse -> XOR of plaintexts; GCM -> forge auth key | `ctfbrain search nonce-reuse gcm-forbidden-attack` |
| Sign anything but the target (RSA/DSA/ECDSA) | existential forgery / blinding | `ctfbrain search signature-forgery` |
| Time-differs on compare | timing attack on HMAC compare | `ctfbrain search timing-attack` |
| Give you `sha256(secret \|\| m)` for chosen `m` | length extension | `ctfbrain search hash-length-extension hashpump` |
| Respond differently per error | error/"crypto oracle" -> enumerate the error strings, that IS the leak | `ctfbrain search oracle-attacks` |
| Give you two signatures with the same `k` | ECDSA/DSA nonce reuse -> recover `d` | `ctfbrain search ecdsa-nonce-reuse` |
| Give many signatures with biased nonces | HNP / lattice | `ctfbrain search hidden-number-problem lll` |

**Oracle scaffold** (start every interactive crypto challenge with this):
```python
#!/usr/bin/env python3
from pwn import remote, context
import sys
context.log_level = "info"
HOST, PORT = (sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else ("localhost", 1337)

def conn():
    return remote(HOST, PORT)

def oracle(io, payload: bytes) -> bytes:
    io.sendlineafter(b"> ", payload.hex().encode())
    return bytes.fromhex(io.recvline().strip().decode())

if __name__ == "__main__":
    io = conn()
    print(io.recvrepeat(1.0).decode(errors="replace"))
    io.interactive()
```

---

## 3. You have a ciphertext blob only

```sh
# character-set fingerprint decides everything here
python3 -c "
s=open('ct.txt').read().strip()
import collections
print('len',len(s),'alphabet',''.join(sorted(set(s)))[:80])
print('freq',collections.Counter(s.lower()).most_common(8))"
```

| Alphabet | Likely | Command |
|---|---|---|
| `A-Z` only, spaces preserved | Caesar/Vigenere/substitution | `ctfbrain search cipher-identification` |
| `A-Z` + digits, length multiple of 8 | base32 | `base32 -d` |
| `A-Za-z0-9+/=` | base64 | `base64 -d` |
| `0-9a-f` | hex | `xxd -r -p` |
| Bitcoin alphabet (no `0OIl`) | base58 | `ctfbrain search encoding-detection` |
| `.`/`-`/space | Morse | `ctfbrain search morse` |
| Only 5 distinct chars | Baconian / base5 | `ctfbrain search bacon-cipher` |
| High entropy bytes | modern cipher | you need more than the blob; re-read the prompt for the key/scheme |
| Numbers separated by commas, each < 256 | ordinals / a substitution on bytes | XOR / Caesar on bytes |
| Numbers larger than 2^64 | RSA/DLOG values | go to section 1 or section 5 |

Then: `ctfbrain search cipher-identification` for the full classical-cipher decision flow.

Automated first pass:
```sh
# try every classical scheme + encoding chain automatically
python3 -m ciphey -t "$(cat ct.txt)" 2>/dev/null || echo "install: pipx install ciphey"
# or paste into CyberChef's Magic operation (offline build)
```

---

## 4. You have source code

Read it in this order:
1. **What is the flag flow?** Grep the flag variable backwards to see exactly which function protects it.
2. **What is the secret?** A key, a nonce, a seed, an exponent. How is it generated?
3. **What does the attacker control?** Anything you send is chosen-plaintext/ciphertext.
4. **What leaks?** Every `print`, every distinct error branch, every timing difference.

```sh
grep -nE 'random|seed|urandom|getrandbits|randint|time\(\)|nonce|iv|key *=' chal.py
grep -nE 'AES|DES|RC4|ChaCha|ECB|CBC|CTR|GCM|OFB|CFB' chal.py
grep -nE 'pow\(|getPrime|isPrime|inverse|gmpy|% *n|\*\* *e' chal.py
grep -nE 'md5|sha1|sha256|hmac|==|compare_digest' chal.py
```

Red flags and what they mean:

| Code | Vulnerability |
|---|---|
| `random.seed(int(time.time()))` | seed brute force over a few thousand values |
| `random.getrandbits(32)` many times | Mersenne Twister state recovery (624 outputs) |
| `AES.new(key, AES.MODE_ECB)` | ECB: equal blocks, cut-and-paste, byte-at-a-time |
| `iv = key` or a constant IV | IV recovery / bit-flipping |
| `nonce = os.urandom(8)` reused per session | stream reuse |
| `pow(m, 3, n)` | small exponent |
| `p = getPrime(512); q = nextprime(p)` | Fermat |
| `d = inverse(e, phi)` with `e` huge | Wiener |
| `if hmac == user_hmac` (non-constant-time) | timing |
| `hashlib.sha256(SECRET + data)` used as a MAC | length extension |
| `k = random.randint(1, n)` derived from something guessable in ECDSA | nonce recovery |
| Custom "encryption" with `^`, shifts, S-boxes | write the inverse; or algebraic/differential attack |
| `Zmod(p)` with smooth `p-1` | Pohlig-Hellman |

`ctfbrain search source-code-given`

---

## 5. You have ECC or a discrete log

```sh
# first: is the group small or smooth? that decides everything
sage -c "p=<p>; print(factor(p-1))"
```

| Condition | Attack | Complexity |
|---|---|---|
| Group order factors into small primes | Pohlig-Hellman | sum of `sqrt(p_i)` |
| Order ~ up to 2^60 | BSGS / Pollard rho | `O(sqrt(n))` |
| `#E == p` (anomalous curve) | Smart's attack, linear time | `O(1)`-ish |
| Small embedding degree `k` | MOV/Frey-Ruck to `GF(p^k)` | index calculus |
| Singular curve (discriminant 0) | map to additive/multiplicative group | trivial |
| Nonce bias in ECDSA | lattice / HNP | LLL |
| Two signatures share `k` | direct algebra for `d` | `O(1)` |
| Invalid-curve point accepted | small-subgroup + CRT | easy |
| `p` prime, plain DLOG, `p` < 2^100 | Sage `discrete_log` | varies |

```python
# Sage: the generic call that handles Pohlig-Hellman for you
# sage: discrete_log(P, G, operation='+')       # elliptic curve
# sage: discrete_log(Mod(h,p), Mod(g,p))        # multiplicative
```
`ctfbrain search ecc-attacks pohlig-hellman smart-attack`

---

## 6. You have hashes

| Situation | Do |
|---|---|
| Unknown hash string | `hashid 'HASH'` / `hash-identifier`; then `ctfbrain search hashcat john` |
| MD5/SHA1 collision needed | `ctfbrain search hash-collision hashclash` ; for MD5 use UniColl/fastcoll |
| `sha256(secret \|\| msg)` MAC | length extension: `ctfbrain search hash-length-extension` |
| Hash of something short/structured | brute force with a mask: `hashcat -a 3 -m 0 hash '?l?l?l?l?d?d'` |
| Need to find a partial-collision / PoW | `ctfbrain search proof-of-work` |
| Custom hash in source | look for a small state, invertible rounds, or no avalanche -> meet-in-the-middle |
| `crypt()`/bcrypt/argon | `john --format=...`; check `ctfbrain search john hashcat` for the mode number |

---

## 7. You have PRNG output

| Generator | Recovery |
|---|---|
| Python `random` (Mersenne Twister) | 624 consecutive 32-bit outputs -> full state. `ctfbrain search mersenne-twister randcrack` |
| LCG `x = a*x + c mod m`, all params known | trivially invertible |
| LCG, params unknown | recover `m`, then `a`, `c` from a handful of outputs via gcd of differences |
| Truncated LCG | LLL lattice |
| `rand()` in C (glibc) | glibc additive-feedback, reproducible from seed; brute-force seed |
| Seeded with time | brute force +/- a few hours of unix timestamps |
| LFSR | Berlekamp-Massey with 2n bits |
| `xorshift`/`xoroshiro` | symbolic solve with z3 |
| Java `Random` | 48-bit LCG, 2 outputs -> seed |

```python
# Mersenne Twister state recovery
from randcrack import RandCrack
rc = RandCrack()
for v in outputs[:624]:
    rc.submit(v)
print(rc.predict_getrandbits(32))
```

---

## 8. You have a symmetric cipher

| Mode | Attack |
|---|---|
| ECB | identical plaintext blocks -> identical ciphertext blocks; byte-at-a-time; block shuffling/cut-and-paste |
| CBC | padding oracle; bit-flipping in the previous block; IV = key leak; predictable-IV chosen-plaintext (BEAST-style) |
| CTR / OFB / CFB8 | keystream reuse on nonce reuse -> `c1 ^ c2 = p1 ^ p2`, crib drag |
| GCM | nonce reuse -> recover `H`, forge any tag (forbidden attack); short tags -> forgery |
| CFB | similar to CBC for flipping |
| XTS | block-level, sector tweak; rare in CTF |
| Stream (RC4) | biased keystream, related-key, keystream reuse |
| DES/3DES | 56-bit key is brute-forceable on GPU; meet-in-the-middle on 2DES |
| Any, with a "reduced rounds" note | differential / linear / integral cryptanalysis. `ctfbrain search differential-cryptanalysis` |

Detect ECB instantly:
```python
def is_ecb(ct: bytes, bs: int = 16) -> bool:
    blocks = [ct[i:i+bs] for i in range(0, len(ct), bs)]
    return len(blocks) != len(set(blocks))
```

---

## Still stuck?

- Re-read the source for the **one line that is unusual**. CTF crypto is always one deliberate deviation from the standard.
- Check parameter sizes: a 512-bit `n`, a 64-bit key, a 32-bit seed, 16-bit primes are all screaming "brute force me".
- `ctfbrain search stuck`
