---
title: "Highandlowbitsequal (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "highandlowbitsequal", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/highandlowbitsequal.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/highandlowbitsequal.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/highandlowbitsequal.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/highandlowbitsequal.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/highandlowbitsequal.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.algos import FactorHighAndLowBitsEqual


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run FactorHighAndLowBitsEqual attack with a timeout"""

        try:
            pq = FactorHighAndLowBitsEqual(publickey.n)
        except Exception:
            pq = None

        if pq is not None:
            publickey.p = pq[0]
            publickey.q = pq[1]

            priv_key = PrivateKey(
                n=publickey.n,
                p=int(publickey.p),
                q=int(publickey.q),
                e=int(publickey.e),
            )
            return priv_key, None

        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDQwDQYJKoZIhvcNAQEBBQADIwAwIAIZAKGAon/dEGXmAuaZ0X1IIW2sUdRAh1ew
SQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
