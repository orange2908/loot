---
title: "Feistel Barrier - TSG CTF 2024"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["rsa-crypto", "crypto", "rsa", "ecc", "lll", "sage", "discrete-log", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "I played with team blue-lotus and solved all cryptos challenges except Who is the Outlier"
source:
  name: "CTFtime writeup #39713"
  url: "https://ctftime.org/writeup/39713"
original_source: "https://github.com/unprintable123/CTF-Writeups/tree/main/ctfs/tsgctf-2024"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "Feistel Barrier"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** Feistel Barrier
- **Author team:** blue-lotus
- **CTFtime tags:** rsa-crypto, crypto, rsa
- **CTFtime:** <https://ctftime.org/writeup/39713>
- **Original writeup:** <https://github.com/unprintable123/CTF-Writeups/tree/main/ctfs/tsgctf-2024>

---
# TSG CTF 2024

I played with team blue-lotus and solved all cryptos challenges except `Who is the Outlier`

## Mystery of Scattered Key

Reconstruct `p` and `q` from the least significant bits by mod `65536^i`. Code is in `mystery_of_scattered_key/challenge.py`

## Feistel Barrier

Send `n+chal` and we can decrypt `chal`. I played it in sage interactive mode thus no code.

## CONPASS

The signature doesn't use hash function, so we can forge the signature by making `{"time":0, "something":"..."} mod n=s^e`. Since all non-printable chars are filtered, only `"` will break the json, LLL is not necessary. Code is in `CONPASS/solve.py`.

## Easy? ECDLP

[Smart Attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/smart_attack.py)

## Easy?? ECDLP

The challenge asks to do discrete log on elliptic curve over $Q_p$. Similar to $Z_{P^n}$, I guess the order of the curve is $kp^7$, where $k$ is the order of the curve over something like $Z_p$. So I use some small primes to find the $k$ and surpringly find that $k\in\{p-1,p,p+1\}$ (I don't know why). And the idea of Smart Attack is to lift $F_p$ to $Q_p$, it is reasonable to guess Smart Attack works here for the $p^7$ part. So I find a prime such that $p+1$ and $p-1$ are smooth.

In fact, even the $p^7$ part is enough to pass the challenge because the secret is $2^{1600}$, but $p$ is only required to larger than $2^{200}$.

The code is in `easy_ecdlp2/problem.sage`
