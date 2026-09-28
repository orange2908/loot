---
title: "Ecdsa Nonce Reuse (crypto-attacks)"
category: "crypto"
subcategory: "ecc"
type: "script"
tags: ["crypto-attacks", "ecc", "ecdsa", "nonce-reuse", "nonce", "reuse", "ecdsa-nonce-reuse", "crypto"]
summary: "ecdsa nonce reuse - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ecc/ecdsa_nonce_reuse.py"
license: "MIT"
---

## What it does

`attacks/ecc/ecdsa_nonce_reuse.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/ecc/ecdsa_nonce_reuse.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ecc/ecdsa_nonce_reuse.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/ecc/ecdsa_nonce_reuse.py
python3 vendor/crypto-attacks/attacks/ecc/ecdsa_nonce_reuse.py
```

## Code

```python
import os
import sys

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared import solve_congruence


def attack(n, m1, r1, s1, m2, r2, s2):
    """
    Recovers the nonce and private key from two messages signed using the same nonce.
    :param n: the order of the elliptic curve
    :param m1: the first message
    :param r1: the signature of the first message
    :param s1: the signature of the first message
    :param m2: the second message
    :param r2: the signature of the second message
    :param s2: the signature of the second message
    :return: generates tuples containing the possible nonce and private key
    """
    for k in solve_congruence(int(s1 - s2), int(m1 - m2), int(n)):
        for x in solve_congruence(int(r1), int(k * s1 - m1), int(n)):
            yield int(k), int(x)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
