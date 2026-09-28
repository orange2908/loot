---
title: "Qicheng (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "subprocess", "qicheng", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/qicheng.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/qicheng.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/qicheng.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/qicheng.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/qicheng.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        # The CLI injects its --timeout default (60s) into this constructor.
        # 200 probabilistic ECM attempts need ~11 min; never accept less than
        # 900s so the attempt budget stays meaningful.
        super().__init__(max(timeout, 900))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/qicheng.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Qi Cheng - A New Class of Unsafe Primes"""
        try:
            sageresult = int(
                subprocess.check_output(
                    [
                        "sage",
                        f"{rootpath}/sage/qicheng.sage",
                        str(publickey.n),
                        "200",
                    ],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return (None, None)

        p = sageresult
        if not (1 < p < publickey.n) or publickey.n % p != 0:
            return (None, None)
        q = publickey.n // p
        priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
        return (priv_key, None)

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        n = int(
            "1444329727510154393553799612747635457542181563961160832013134005"
            "088873165794135221"
        )
        key_data = RSA.construct((n, 65537)).publickey().exportKey()
        for _ in range(5):
            result = self.attack(PublicKey(key_data), progress=False)
            if result != (None, None):
                return True
        return False

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
