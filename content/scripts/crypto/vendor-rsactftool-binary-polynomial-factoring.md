---
title: "Binary Polynomial Factoring (RsaCtfTool)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["rsactftool", "rsa", "eval", "subprocess", "binary", "polynomial", "factoring", "binary-polynomial-factoring", "crypto"]
summary: "!/usr/bin/env python3 -*- coding: utf-8 -*-"
tools: ["RsaCtfTool"]
source:
  name: "RsaCtfTool/RsaCtfTool"
  url: "https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/binary_polynomial_factoring.py"
license: "MIT"
---

## What it does

!/usr/bin/env python3 -*- coding: utf-8 -*-

## Where it lives

- Vendored locally at `vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/binary_polynomial_factoring.py`
- Upstream: <https://github.com/RsaCtfTool/RsaCtfTool/blob/8c9a9ecb85ca/src/RsaCtfTool/attacks/single_key/binary_polynomial_factoring.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/binary_polynomial_factoring.py
python3 vendor/RsaCtfTool/src/RsaCtfTool/attacks/single_key/binary_polynomial_factoring.py
```

## Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import subprocess

from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/binary_polynomial_factoring.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """binary polynomial factoring"""
        try:
            output = subprocess.check_output(
                [
                    "sage",
                    f"{rootpath}/sage/binary_polynomial_factoring.sage",
                    str(publickey.n),
                ],
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            factors = ast.literal_eval(output.strip())
            p = next(
                int(factor)
                for factor in factors
                if 1 < int(factor) < publickey.n
                and publickey.n % int(factor) == 0
            )
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            StopIteration,
            SyntaxError,
            TypeError,
            ValueError,
        ):
            return (None, None)

        q = publickey.n // p
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

```

## Attribution

- **Author:** RsaCtfTool contributors
- **Repository:** <https://github.com/RsaCtfTool/RsaCtfTool> (commit `8c9a9ecb85ca`)
- **Licence:** MIT — see `vendor/RsaCtfTool/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
