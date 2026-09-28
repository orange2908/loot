---
title: "crosslinks - Hack-A-Sat-Quals 2022"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "crosslinks", "cryptography", "hack-a-sat-quals", "perfectblue", "ctf-writeups"]
summary: "In this challenge, we are given satellite observation data which includes range and range rate data."
source:
  name: "perfectblue/ctf-writeups"
  url: "https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/Hack-A-Sat-Quals-2022/crosslinks/README.md"
ctf:
  name: "Hack-A-Sat-Quals"
  year: 2022
  challenge: "crosslinks"
---

## Source

- **CTF:** Hack-A-Sat-Quals 2022
- **Challenge:** crosslinks
- **Repository:** [perfectblue/ctf-writeups](https://github.com/perfectblue/ctf-writeups)
- **File:** <https://github.com/perfectblue/ctf-writeups/blob/db9b964bf35c210567ea508383e91a9c423adaee/2022/Hack-A-Sat-Quals-2022/crosslinks/README.md>

---
# Crosslinks

## Background

In this challenge, we are given satellite observation data which includes range and range rate data. The task is to figure out which satellite is making these observations.

## Solution

To solve this, we can brute force through each satellite. For each satellite, we can compute the error of both the range and range rate data. The satellite for which the computed error is the smallest will be the answer.

To compute range, we can use the skyfield python library to get each satellie's position at a given time. Then, we simply compute the distance between the two points and take its square of the difference as error.

To compute range rate, we note that range rate is computed as the projection of the difference in velocities onto the displacement vector. The skyfield python library can get us both position and velocity data as a given time. using these values, we can compute the range rate. Again, we use least squares error as the computed error.

## Solve Script

The final script is in solve.py. Run with `python solve.py`
