---
title: "Lehman (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "lehman", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/lehman.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/lehman.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/lehman.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/lehman.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/lehman.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.algos import lehman


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run lehman attack with a timeout"""
        try:
            r = lehman(publickey.n)
            if r is None:
                return None, None
            publickey.p, publickey.q = r
        except FactorizationError:
            self.logger.error("N should not be a 4k+2 number...")
            return None, None

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCG6ZYBPnfEFpkADglB1IDARrL3
Gk+Vs1CsGk1CY3KSPYpFYdlvv7AkBZWQcgGtMiXPbt7X3gLZHDhv+sKAty0Plcrn
H0Lr4NPtrqznzqMZX6MsHGCA2Q74U9Bt1Fcskrn4MQu8DGNaXiaVJRF1EDCmWQgW
VU52MDG8uzHj8RnGXwIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
