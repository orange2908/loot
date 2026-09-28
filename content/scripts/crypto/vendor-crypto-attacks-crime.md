---
title: "Crime (crypto-attacks)"
category: "crypto"
subcategory: "ctr"
type: "script"
tags: ["crypto-attacks", "ctr", "crime", "crypto"]
summary: "Don't try the padding byte."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ctr/crime.py"
license: "MIT"
---

## What it does

Don't try the padding byte.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/ctr/crime.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ctr/crime.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/ctr/crime.py
python3 vendor/crypto-attacks/attacks/ctr/crime.py
```

## Code

```python
def attack(encrypt_oracle, known_prefix, padding_byte):
    """
    Recovers a secret using the CRIME attack (CTR version).
    :param encrypt_oracle: the encryption oracle
    :param known_prefix: a known prefix of the secret to recover
    :param padding_byte: a byte which is never used in the plaintext
    :return: the secret
    """
    known_prefix = bytearray(known_prefix)
    padding_bytes = bytes([padding_byte])
    while True:
        for i in range(256):
            # Don't try the padding byte.
            if i == padding_byte:
                continue

            l1 = len(encrypt_oracle(padding_bytes + known_prefix + bytes([i]) + padding_bytes + padding_bytes))
            l2 = len(encrypt_oracle(padding_bytes + known_prefix + padding_bytes + bytes([i]) + padding_bytes))
            if l1 < l2:
                known_prefix.append(i)
                break
        else:
            return known_prefix

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
