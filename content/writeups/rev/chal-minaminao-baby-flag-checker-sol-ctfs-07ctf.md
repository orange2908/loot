---
title: "Baby Flag Checker Sol - 07ctf"
category: "rev"
type: "writeup"
tags: ["minaminao-my-ctf-challenges", "author-solution", "challenge-source", "symbolic-execution", "baby", "checker", "sol", "rev", "07ctf"]
summary: "A small anti-decompilation trick has been applied: PUSH2 0x000f (61000f) -> PUSH1 0x00 SLOAD (600054)."
source:
  name: "minaminao/my-ctf-challenges"
  url: "https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/07ctf/baby-flag-checker-sol"
license: "none stated"
ctf:
  name: "07ctf"
  challenge: "Baby Flag Checker Sol"
---

## Challenge

- **Author:** [minaminao](https://github.com/minaminao)
- **Source:** <https://github.com/minaminao/my-ctf-challenges/tree/c9c9ddb171c2db93b282f74ff9f38c7312668d7b/ctfs/07ctf/baby-flag-checker-sol>
- **CTF:** 07ctf

---

# BabyFlagChecker.sol

**Challenge Name**:  
BabyFlagChecker.sol

**Description**:  
wakaba 🔰


## Author's solver notes

# Brief Writeup

A small anti-decompilation trick has been applied: PUSH2 0x000f (61000f) -> PUSH1 0x00 SLOAD (600054).
So no proper decompilation result can be obtained.

From the disassembly and dynamic analysis, it's clear that the contract is only performing simple addition and multiplication, so it can be easily solved using a symbolic execution engine such as [hevm](https://github.com/argotorg/hevm).

**Flag**: `07CTF{MVdfJ892Xb}`
