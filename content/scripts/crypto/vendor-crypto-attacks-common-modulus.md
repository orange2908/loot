---
title: "Common Modulus (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "common-modulus", "gcd", "common", "modulus", "crypto"]
summary: "common modulus - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/common_modulus.py"
license: "MIT"
---

## What it does

`attacks/rsa/common_modulus.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/common_modulus.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/common_modulus.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/common_modulus.py
python3 vendor/crypto-attacks/attacks/rsa/common_modulus.py
```

## Code

```python
from sage.all import ZZ
from sage.all import xgcd


def attack(n, e1, c1, e2, c2):
    """
    Recovers the plaintext from two ciphertexts, encrypted using the same modulus and different public exponents.
    :param n: the common modulus
    :param e1: the first public exponent
    :param c1: the ciphertext of the first encryption
    :param e2: the second public exponent
    :param c2: the ciphertext of the second encryption
    :return: the plaintext
    """
    g, u, v = xgcd(e1, e2)
    p1 = pow(c1, u, n) if u > 0 else pow(pow(c1, -1, n), -u, n)
    p2 = pow(c2, v, n) if v > 0 else pow(pow(c2, -1, n), -v, n)
    return int(ZZ(int(p1 * p2) % n).nth_root(g))

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
