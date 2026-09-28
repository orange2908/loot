---
title: "Plaintext Recovery Hardest (crypto-attacks)"
category: "crypto"
subcategory: "ecb"
type: "script"
tags: ["crypto-attacks", "ecb", "plaintext", "recovery", "hardest", "plaintext-recovery-hardest", "crypto"]
summary: "plaintext recovery hardest - vendored from jvdsn/crypto-attacks."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ecb/plaintext_recovery_hardest.py"
license: "MIT"
---

## What it does

`attacks/ecb/plaintext_recovery_hardest.py` from jvdsn/crypto-attacks: Python implementations of a large catalogue of cryptographic attacks.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/ecb/plaintext_recovery_hardest.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/ecb/plaintext_recovery_hardest.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/ecb/plaintext_recovery_hardest.py
python3 vendor/crypto-attacks/attacks/ecb/plaintext_recovery_hardest.py
```

## Code

```python
def attack(encrypt_oracle, unused_byte=0):
    """
    Recovers a secret which is appended to a plaintext and encrypted using ECB.
    In this scenario, the encryption oracle prepends a random prefix (length 0 to 16) to the plaintext.
    :param encrypt_oracle: the encryption oracle
    :param unused_byte: a byte that's never used in the secret or random prefix
    :return: the secret
    """
    paddings = [bytes([unused_byte] * i) for i in range(16)]
    prefix = bytes([unused_byte] * 32)
    secret = bytearray()
    while True:
        padding = paddings[15 - (len(secret) % 16)]
        p = bytearray(prefix + padding + secret + b"0" + padding)
        byte_index = len(prefix) + len(padding) + len(secret)
        end1 = len(prefix) + len(padding) + len(secret) + 1
        end2 = end1 + len(padding) + len(secret) + 1
        for i in range(256):
            p[byte_index] = i
            c = encrypt_oracle(p)
            while c[0:16] != c[16:32]:
                c = encrypt_oracle(p)

            if c[end1 - 16:end1] == c[end2 - 16:end2]:
                secret.append(i)
                break
        else:
            secret.pop()
            break

    return bytes(secret)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
