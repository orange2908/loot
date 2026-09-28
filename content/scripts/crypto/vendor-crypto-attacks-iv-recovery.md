---
title: "Iv Recovery (crypto-attacks)"
category: "crypto"
subcategory: "cbc"
type: "script"
tags: ["crypto-attacks", "cbc", "xor", "recovery", "iv-recovery", "crypto"]
summary: "iv recovery - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/cbc/iv_recovery.py"
license: "MIT"
---

## What it does

`attacks/cbc/iv_recovery.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/cbc/iv_recovery.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/cbc/iv_recovery.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/cbc/iv_recovery.py
python3 vendor/crypto-attacks/attacks/cbc/iv_recovery.py
```

## Code

```python
from Crypto.Util.strxor import strxor


def attack(decrypt_oracle):
    """
    Recovers the initialization vector using a chosen-ciphertext attack.
    :param decrypt_oracle: the decryption oracle to decrypt ciphertexts
    :return: the initialization vector
    """
    p = decrypt_oracle(bytes(32))
    return strxor(p[:16], p[16:])

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
