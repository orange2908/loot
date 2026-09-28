---
title: "Bit Flipping (crypto-attacks)"
category: "crypto"
subcategory: "ctr"
type: "script"
tags: ["crypto-attacks", "ctr", "bit-flipping", "bit-flip", "bit", "flipping", "crypto"]
summary: "bit flipping - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ctr/bit_flipping.py"
license: "MIT"
---

## What it does

`attacks/ctr/bit_flipping.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/ctr/bit_flipping.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ctr/bit_flipping.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/ctr/bit_flipping.py
python3 vendor/crypto-attacks/attacks/ctr/bit_flipping.py
```

## Code

```python
def attack(c, pos, p, p_):
    """
    Replaces the original plaintext with a new plaintext at a position in the ciphertext.
    :param c: the ciphertext
    :param pos: the position to modify at
    :param p: the original plaintext
    :param p_: the new plaintext
    :return: the modified ciphertext
    """
    c_ = bytearray(c)
    for i in range(len(p)):
        c_[pos + i] = c[pos + i] ^ p[i] ^ p_[i]

    return c_

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
