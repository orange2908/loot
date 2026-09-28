---
title: "Gaa (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "factorization", "rsa", "lsb", "gaa", "crypto"]
summary: "gaa - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/gaa.py"
license: "MIT"
---

## What it does

`attacks/factorization/gaa.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/gaa.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/gaa.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/gaa.py
python3 vendor/crypto-attacks/attacks/factorization/gaa.py
```

## Code

```python
from math import ceil

from sage.all import ZZ
from sage.all import sqrt


def factorize(N, rp, rq):
    """
    Recovers the prime factors from a modulus using the Ghafar-Ariffin-Asbullah attack.
    More information: Ghafar AHA. et al., "A New LSB Attack on Special-Structured RSA Primes"
    :param N: the modulus
    :param rp: the value rp
    :param rq: the value rq
    :return: a tuple containing the prime factors
    """
    i = ceil(sqrt(rp * rq))
    x = ZZ["x"].gen()
    while True:
        sigma = (round(int(sqrt(N))) - i) ** 2
        z = (N - (rp * rq)) % sigma
        f = x ** 2 - z * x + sigma * rp * rq
        for x0 in f.roots(multiplicities=False):
            if x0 % rp == 0:
                p = int((x0 // rp) + rq)
                assert N % p == 0
                return p, N // p
            if x0 % rq == 0:
                p = int((x0 // rq) + rp)
                assert N % p == 0
                return p, N // p

        i += 1

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
