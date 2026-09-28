---
title: "Partial D (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "sage", "subprocess", "partial", "partial-d", "crypto"]
summary: "!/usr/bin/python3"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/partial_d.py"
license: "MIT"
---

## What it does

!/usr/bin/python3

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/partial_d.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/partial_d.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/partial_d.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/partial_d.py
```

## Code

```python
#!/usr/bin/python3

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath
from RsaCtfTool.lib.exceptions import FactorizationError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/partial_d.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run partial_d attack with a timeout"""
        if not isinstance(publickey, PrivateKey) or publickey.d is None:
            self.logger.error(
                "[!] partial_d attack is only for partial private keys not pubkeys..."
            )
            return None, None

        try:
            cmd = [
                "sage",
                f"{rootpath}/sage/partial_d.sage",
                str(publickey.n),
                str(publickey.e),
                str(publickey.d),
            ]
            result = subprocess.check_output(
                cmd,
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            p, q = (int(value) for value in result.split())
            if p * q != publickey.n:
                raise FactorizationError("Sage returned factors that do not match n")
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            FactorizationError,
            ValueError,
        ):
            self.logger.error("[!] partial_d internal error...")
            return None, None

        publickey.p = p
        publickey.q = q
        return self.create_private_key(publickey)

    def test(self):
        raise NotImplementedError

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
