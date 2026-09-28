---
title: "Lsb Oracle (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "lsb", "oracle", "lsb-oracle", "crypto"]
summary: "lsb oracle - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/lsb_oracle.py"
license: "MIT"
---

## What it does

`attacks/rsa/lsb_oracle.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/lsb_oracle.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/lsb_oracle.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/lsb_oracle.py
python3 vendor/crypto-attacks/attacks/rsa/lsb_oracle.py
```

## Code

```python
from sage.all import ZZ


def attack(N, e, c, oracle):
    """
    Recovers the plaintext from the ciphertext using the LSB oracle (parity oracle) attack.
    :param N: the modulus
    :param e: the public exponent
    :param c: the encrypted message
    :param oracle: a function which returns the last bit of a plaintext for a given ciphertext
    :return: the plaintext
    """
    left = ZZ(0)
    right = ZZ(N)
    while right - left > 1:
        c = (c * pow(2, e, N)) % N
        if oracle(c) == 0:
            right = (right + left) / 2
        else:
            left = (right + left) / 2

    return int(right)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
