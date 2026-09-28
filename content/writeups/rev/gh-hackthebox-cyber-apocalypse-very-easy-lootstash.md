---
title: "[Very Easy] LootStash - cyber apocalypse 2024"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "easy", "lootstash", "reverse-engineering", "very-easy-lootstash", "cyber-apocalypse"]
summary: "rev writeup for \"[Very Easy] LootStash\" from cyber apocalypse - techniques: easy, lootstash, reverse-engineering, very-easy-lootstash, cyber-apocalypse."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/%5BVery%20Easy%5D%20LootStash/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "[Very Easy] LootStash"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** [Very Easy] LootStash
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/%5BVery%20Easy%5D%20LootStash/README.md>

---
<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/banner.png" style="zoom: 80%;" align=center />

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">LootStash</font>

  7<sup>th</sup> 02 24 / Document No. D24.102.13

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Very Easy</font>

  Classification: Official






# Synopsis

LootStash is a Very Easy reversing challenge.

## Skills Learned
    - Using `strings`

# Solution

If we run the binary, it will print a series of dots over 5 seconds, then tell us a weapon that was retrieved from the stash.

```
Diving into the stash - let's see what we can find.
.....
You got: 'Supinity, Ferocity of Bloodlust'. Now run, before anyone tries to steal it!
```

If we run `strings` and `grep` for `HTB`, we can locate the flag in the binary.
