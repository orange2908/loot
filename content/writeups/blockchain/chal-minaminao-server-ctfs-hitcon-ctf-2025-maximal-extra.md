---
title: "Server - Hitcon CTF 2025"
category: "blockchain"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "server", "blockchain", "hitcon-ctf-2025"]
summary: "The infra shouldn't be vulnerable."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln/server"
license: "none stated"
ctf:
  name: "Hitcon CTF 2025"
  year: 2025
  challenge: "Server"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/hitcon-ctf-2025/maximal-extractable-vuln/server>
- **CTF:** Hitcon CTF 2025

---

The infra shouldn't be vulnerable.
It's not necessary to look at anywhere other than the contract files (`src/contracts`) to solve this challenge!

First, set the `FORKING_RPC_URL` in `compose.yaml` to your mainnet RPC endpoint (for example, Alchemy) to deploy the challenge contract on a network forked from the Ethereum mainnet.

Next, start the local challenge server:
```
docker compose up --build
```
