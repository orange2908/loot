---
title: "Stereotyped Message (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "rsa", "coppersmith", "sage", "stereotyped", "message", "stereotyped-message", "crypto"]
summary: "stereotyped message - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/stereotyped_message.py"
license: "MIT"
---

## What it does

`attacks/rsa/stereotyped_message.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/rsa/stereotyped_message.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/rsa/stereotyped_message.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/rsa/stereotyped_message.py
python3 vendor/crypto-attacks/attacks/rsa/stereotyped_message.py
```

## Code

```python
import logging
import os
import sys

from sage.all import Zmod

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import howgrave_graham


def attack(N, e, c, partial_m, m=1, t=0):
    """
    Recovers the plaintext from the ciphertext if some bits of the plaintext are known, using Coppersmith's method.
    :param N: the modulus
    :param e: the public exponent (should be "small": 3, 5, or 7 work best)
    :param c: the encrypted message
    :param partial_m: the partial plaintext message (PartialInteger)
    :param m: the m value to use for the small roots method (default: 1)
    :param t: the t value to use for the small roots method (default: 0)
    :return: the plaintext
    """
    x = Zmod(N)["x"].gen()
    f = (partial_m.sub([x])) ** e - c
    X = partial_m.get_unknown_bounds()
    logging.info(f"Trying {m = }, {t = }...")
    for x0, in howgrave_graham.modular_univariate(f, N, m, t, X):
        if x0 != 0:
            return int(partial_m.sub([x0]))

    return None

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
