---
title: "Neca (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "neca", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/neca.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/neca.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/neca.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/neca.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/neca.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.number_theory import getpubkeysz
from RsaCtfTool.lib.is_roca_test import is_roca_vulnerable
from RsaCtfTool.lib.external import neca_factor_driver


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.logger = logging.getLogger("global_logger")
        self.required_binaries = ["neca"]

    def attack(self, publickey, cipher=[], progress=True):
        if is_roca_vulnerable(publickey.n):
            if getpubkeysz(publickey.n) <= 512:
                pq = neca_factor_driver(publickey.n, timeout=self.timeout)
                if pq is not None:
                    priv_key = PrivateKey(
                        int(pq[0]), int(pq[1]), int(publickey.e), int(publickey.n)
                    )
                    return (priv_key, None)
                else:
                    return (None, None)
            else:
                self.logger.error(
                    "[-] This key is roca but > 512 bits, try with roca attack..."
                )
                return (None, None)
        else:
            self.logger.error("[-] This key is not roca, skipping test...")
            return (None, None)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIAce1LytE5hd6Kl8yUMSo9BSfvjgW9W
3nu+QG7/FNRjB7+ot8giOYNZqid2e6Z/MrJf1QzftgJCF9qhUv2egKUCAwEAAQ==
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
