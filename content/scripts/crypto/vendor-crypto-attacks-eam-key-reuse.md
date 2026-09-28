---
title: "Eam Key Reuse (crypto-attacks)"
category: "crypto"
subcategory: "cbc-and-cbc-mac"
type: "script"
tags: ["crypto-attacks", "cbc-and-cbc-mac", "cbc", "eam", "key", "reuse", "eam-key-reuse", "crypto"]
summary: "eam key reuse - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/cbc_and_cbc_mac/eam_key_reuse.py"
license: "MIT"
---

## What it does

`attacks/cbc_and_cbc_mac/eam_key_reuse.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/cbc_and_cbc_mac/eam_key_reuse.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/cbc_and_cbc_mac/eam_key_reuse.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/cbc_and_cbc_mac/eam_key_reuse.py
python3 vendor/crypto-attacks/attacks/cbc_and_cbc_mac/eam_key_reuse.py
```

## Code

```python
def attack(decrypt_oracle, iv, c, t):
    """
    Uses a chosen-ciphertext attack to decrypt the ciphertext.
    :param decrypt_oracle: the decryption oracle
    :param iv: the initialization vector
    :param c: the ciphertext
    :param t: the tag corresponding to the ciphertext
    :return: the plaintext
    """
    c_ = iv + c
    p_ = decrypt_oracle(bytes(16), c_, c[-16:])
    return p_[16:]

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
