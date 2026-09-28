---
title: "Padding Oracle (crypto-attacks)"
category: "crypto"
subcategory: "aes"
type: "script"
tags: ["crypto-attacks", "ige", "padding-oracle", "xor", "padding", "oracle", "crypto"]
summary: "padding oracle - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ige/padding_oracle.py"
license: "MIT"
---

## What it does

`attacks/ige/padding_oracle.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/ige/padding_oracle.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ige/padding_oracle.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/ige/padding_oracle.py
python3 vendor/crypto-attacks/attacks/ige/padding_oracle.py
```

## Code

```python
import logging

from Crypto.Util.strxor import strxor


def _attack_block(padding_oracle, p0, c0, c):
    logging.info(f"Attacking block {c.hex()}...")
    r = bytes()
    for i in reversed(range(16)):
        s = bytes([16 - i] * (16 - i))
        for b in range(256):
            c0_ = bytes(i) + strxor(s, bytes([b]) + r)
            if padding_oracle(p0, c0_, c):
                r = bytes([b]) + r
                break
        else:
            raise ValueError(f"Unable to find decryption for {s}, {p0}, {c0}, and {c}")

    return strxor(c0, r)


def attack(padding_oracle, p0, c0, c):
    """
    Recovers the plaintext using the padding oracle attack.
    :param padding_oracle: the padding oracle, returns True if the padding is correct, False otherwise
    :param p0: the initial plaintext block
    :param c0: the initial ciphertext block
    :param c: the ciphertext
    :return: the (padded) plaintext
    """
    p = _attack_block(padding_oracle, p0, c0, c[0:16])
    for i in range(16, len(c), 16):
        p += _attack_block(padding_oracle, p[i - 16:i], c[i - 16:i], c[i:i + 16])

    return p

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
