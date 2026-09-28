---
title: "[Very Easy] BoxCutter - cyber apocalypse 2024"
category: "rev"
subcategory: "rev"
type: "writeup"
tags: ["rev", "nmap", "easy", "boxcutter", "reverse-engineering", "very-easy-boxcutter"]
summary: "rev writeup for \"[Very Easy] BoxCutter\" from cyber apocalypse - techniques: nmap, easy, boxcutter, reverse-engineering, very-easy-boxcutter."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/%5BVery%20Easy%5D%20BoxCutter/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "[Very Easy] BoxCutter"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** [Very Easy] BoxCutter
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/%5BVery%20Easy%5D%20BoxCutter/README.md>

---
<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/banner.png" style="zoom: 80%;" align=center />

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">BoxCutter</font>

  6<sup>th</sup> 03 24 / Document No. D24.102.19

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Very Easy</font>

  Classification: Official






# Synopsis

BoxCutter is a Very Easy reversing challenge. Players will use `strace` to identify the flag.

## Skills Learned
    - Use of `strace`

# Solution

If players run the challenge, they will receive the message `[X] Error: Box Not Found`. If we run it under strace, we will see the following:

```
[ .. SNIP .. ]
munmap(0x7f2ee0bd7000, 334763)          = 0
openat(AT_FDCWD, "HTB{...}", O_RDONLY) = -1 ENOENT (No such file or directory)
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
[ .. SNIP .. ]
```

The binary is trying to open a file with the name of the flag. We have now solved the challenge.
