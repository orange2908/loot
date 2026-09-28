---
title: "Low Exponent (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "low-exponent", "low", "exponent", "crypto"]
summary: "low exponent - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/low_exponent.py"
license: "MIT"
---

## What it does

`attacks/rsa/low_exponent.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/low_exponent.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/low_exponent.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/low_exponent.py
python3 vendor/crypto-attacks/attacks/rsa/low_exponent.py
```

## Code

```python
from sage.all import ZZ


def attack(e, c):
    """
    Recovers the plaintext from a ciphertext, encrypted using a very small public exponent (e.g. e = 3).
    :param e: the public exponent
    :param c: the ciphertext
    :return: the plaintext
    """
    return int(ZZ(c).nth_root(e))

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
