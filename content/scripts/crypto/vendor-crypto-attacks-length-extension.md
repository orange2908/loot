---
title: "Length Extension (crypto-attacks)"
category: "crypto"
subcategory: "mac"
type: "script"
tags: ["crypto-attacks", "cbc-mac", "sage", "cbc", "length-extension", "xor", "crypto"]
summary: "length extension - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/cbc_mac/length_extension.py"
license: "MIT"
---

## What it does

`attacks/cbc_mac/length_extension.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/cbc_mac/length_extension.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/cbc_mac/length_extension.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/cbc_mac/length_extension.py
python3 vendor/crypto-attacks/attacks/cbc_mac/length_extension.py
```

## Code

```python
from Crypto.Util.strxor import strxor


def attack(m1, t1, m2, t2):
    """
    Uses a length extension attack to forge a message and tag pair for CBC-MAC.
    :param m1: the first message
    :param t1: the tag of the first message
    :param m2: the second message
    :param t2: the tag of the second message
    :return: a tuple containing a valid message and tag for CBC-MAC
    """
    m3 = bytearray(m1)
    m3 += strxor(t1, m2[:16])
    for i in range(16, len(m2), 16):
        m3 += m2[i:i + 16]

    return m3, t2

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
