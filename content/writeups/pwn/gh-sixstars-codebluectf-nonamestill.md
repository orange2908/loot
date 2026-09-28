---
title: "nonamestill - CodeBlueCTF 2017"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["pwn", "house-of-force", "nonamestill", "heap", "binary-exploitation", "codebluectf"]
summary: "Input length 0 when creating url, we can bypass the fgets, no \\0 left, thus information leak."
source:
  name: "sixstars/ctf"
  url: "https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2017/CodeBlueCTF/nonamestill/writeup.md"
ctf:
  name: "CodeBlueCTF"
  year: 2017
  challenge: "nonamestill"
---

## Source

- **CTF:** CodeBlueCTF 2017
- **Challenge:** nonamestill
- **Repository:** [sixstars/ctf](https://github.com/sixstars/ctf)
- **File:** <https://github.com/sixstars/ctf/blob/797933e5397b1e6ee7cc14982c478bec183d15bc/2017/CodeBlueCTF/nonamestill/writeup.md>

---
Input length 0 when creating url, we can bypass the `fgets`, no `\0` left, thus information leak.

Prefill an url ending with `%\n` (without `\0`), urldecode it will cause the string length reduce 1, means that we can reduce the size of next chunk.
Though size reducing could not cause overwrite directly, we can fake a large free chunk after the corrupted chunk.
So that we can got a large free chunk overlap with top chunk after freeing the corrupted chunk which would cause merging.

Now we can overwrite the size of top chunk and use `house of force`.
