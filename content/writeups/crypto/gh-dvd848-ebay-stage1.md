---
title: "Stage1 - eBay 2020"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "base64", "stage1", "cryptography", "ebay", "dvd848"]
summary: "This is an easy warm-up question."
source:
  name: "Dvd848/CTFs"
  url: "https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2020_eBay/Stage1.md"
ctf:
  name: "eBay"
  year: 2020
  challenge: "Stage1"
---

## Source

- **CTF:** eBay 2020
- **Challenge:** Stage1
- **Repository:** [Dvd848/CTFs](https://github.com/Dvd848/CTFs)
- **File:** <https://github.com/Dvd848/CTFs/blob/eaad41f2cb9679fd9be8ce6ab36018ec48008228/2020_eBay/Stage1.md>

---
# Stage 1

## Description

> Decipher this to have the key to the next stage.
> 
> `aHR0cHM6Ly9ybmQuZWJheS5jby5pbC9yaWRkbGUvbXpmYmFiZXdjZXlxeGFsdXIv`

## Solution

This is an easy warm-up question. We decode the string as base-64 and get:

```console
root@kali:/media/sf_CTFs/ebay/1# echo aHR0cHM6Ly9ybmQuZWJheS5jby5pbC9yaWRkbGUvbXpmYmFiZXdjZXlxeGFsdXIv | base64 -d
https://rnd.ebay.co.il/riddle/mzfbabewceyqxalur/
```
