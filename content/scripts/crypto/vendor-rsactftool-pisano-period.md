---
title: "Pisano Period (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "pisano", "period", "pisano-period", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/pisano_period.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/pisano_period.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/pisano_period.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/pisano_period.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/pisano_period.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integer factorization with pisano period
Heavily based on original repo https://github.com/wuliangshun/IntegerFactorizationWithPisanoPeriod/
White paper: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8901977
"""

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.algos import Fibonacci
from RsaCtfTool.lib.number_theory import ilog10


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """
        Pisano(mersenne) period factorization algorithm optimal for keys sub 70 bits in less than a minute.
        The attack is very similar to londahl's
        """
        Fib = Fibonacci(progress=progress)
        B1, B2 = (
            pow(10, (ilog10(publickey.n) // 2) - 4),
            0,
        )  # Arbitrary selected bounds, bigger b2 is more faster but more failed factorizations.
        try:
            r = Fib.factorization(publickey.n, B1, B2)
        except OverflowError:
            r = None
        if r is not None:
            publickey.p, publickey.q = r
            priv_key = PrivateKey(
                int(publickey.p),
                int(publickey.q),
                int(publickey.e),
                int(publickey.n),
            )
            return priv_key, None
        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCQwDQYJKoZIhvcNAQEBBQADEwAwEAIJVqCE2raBvB+lAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
