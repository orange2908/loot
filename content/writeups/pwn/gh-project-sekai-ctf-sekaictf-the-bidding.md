---
title: "the bidding - sekaictf 2023"
category: "pwn"
subcategory: "pwn"
type: "writeup"
tags: ["pwn", "bidding", "binary-exploitation", "the-bidding", "sekaictf", "project-sekai-ctf"]
summary: "!! siced from idekctf2023/babysolana chals !!"
source:
  name: "project-sekai-ctf/sekaictf-2023"
  url: "https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/pwn/the-bidding/solution/README.md"
ctf:
  name: "sekaictf"
  year: 2023
  challenge: "the bidding"
---

## Source

- **CTF:** sekaictf 2023
- **Challenge:** the bidding
- **Repository:** [project-sekai-ctf/sekaictf-2023](https://github.com/project-sekai-ctf/sekaictf-2023)
- **File:** <https://github.com/project-sekai-ctf/sekaictf-2023/blob/4dc0f1fb2836c64b3a502e2538ba32530996b8c9/pwn/the-bidding/solution/README.md>

---
# Setup

!! siced from idekctf2023/babysolana chals !!
!! too lazy to setup anchor myself so thx <3 !!

Use `framework/` to locally setup the challenge
Use `framework-solve/` to solve the challenge locally and remotely

Edit `framework-solve/solve/programs/solve/src/lib.rs` with your exploit


## Deployment
- Run `docker build -t solana-challenge-2 .` in the `framework` directory
- Run `docker run -d -p 1337:1337 solana-challenge-2`


## Building the solution
- Run `build_solution.sh` in the `solution` directory
- Run `target/release/solve-framework`
