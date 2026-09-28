---
title: "Known D (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "gcd", "known", "known-d", "crypto"]
summary: "known d - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/known_d.py"
license: "MIT"
---

## What it does

`attacks/rsa/known_d.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/known_d.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/known_d.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/known_d.py
python3 vendor/crypto-attacks/attacks/rsa/known_d.py
```

## Code

```python
from math import gcd
from random import randrange


def attack(N, e, d):
    """
    Recovers the prime factors from a modulus if the public exponent and private exponent are known.
    :param N: the modulus
    :param e: the public exponent
    :param d: the private exponent
    :return: a tuple containing the prime factors
    """
    k = e * d - 1
    t = 0
    while k % (2 ** t) == 0:
        t += 1

    while True:
        g = randrange(1, N)
        for s in range(1, t + 1):
            x = pow(g, k // (2 ** s), N)
            p = gcd(x - 1, N)
            if 1 < p < N and N % p == 0:
                return p, N // p

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
