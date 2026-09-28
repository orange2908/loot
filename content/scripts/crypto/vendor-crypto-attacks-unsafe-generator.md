---
title: "Unsafe Generator (crypto-attacks)"
category: "crypto"
subcategory: "asymmetric"
type: "script"
tags: ["crypto-attacks", "elgamal-encryption", "sage", "elgamal", "quadratic-residue", "unsafe-generator", "crypto"]
summary: "unsafe generator - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/elgamal_encryption/unsafe_generator.py"
license: "MIT"
---

## What it does

`attacks/elgamal_encryption/unsafe_generator.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/elgamal_encryption/unsafe_generator.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/elgamal_encryption/unsafe_generator.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/elgamal_encryption/unsafe_generator.py
python3 vendor/crypto-attacks/attacks/elgamal_encryption/unsafe_generator.py
```

## Code

```python
from sage.all import legendre_symbol


def attack(p, h, c1, c2):
    """
    Returns the Legendre symbol of the message encrypted using an unsafe generator.
    :param p: the prime used in the ElGamal scheme
    :param h: the public key
    :param c1: the ciphertext
    :param c2: the ciphertext
    :return: the Legendre symbol
    """
    return int(legendre_symbol(c2, p) // max(legendre_symbol(h, p), legendre_symbol(c1, p)))

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
