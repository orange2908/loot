---
title: "Qs (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "sage", "subprocess", "qs", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/qs.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/qs.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/qs.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/qs.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/qs.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/qs.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """
        Use sage's internal quadratic sieve method.
        If input is less than 40 digits, i'll fallback to sage factor method.
        """
        privatekey = None
        try:
            sageresult = (
                subprocess.check_output(
                    ["sage", f"{rootpath}/sage/qs.sage", str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
                .decode("utf8")
                .rstrip()
            )
            sageresult = sageresult.split("\n")
            for line in sageresult:
                line = line.strip()
                if not line or line.startswith("// ** "):
                    continue
                fields = line.split()
                if len(fields) != 2:
                    continue
                p, q = map(int, fields)
                if p <= 1 or q <= 1 or p * q != publickey.n:
                    continue
                publickey.p, publickey.q = p, q
                privatekey = PrivateKey(
                    p=publickey.p,
                    q=publickey.q,
                    e=int(publickey.e),
                    n=int(publickey.n),
                )
            return (privatekey, None)

        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            ValueError,
        ):
            return (None, None)

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = RSA.construct((1009 * 1013, 65537)).publickey().exportKey()
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
