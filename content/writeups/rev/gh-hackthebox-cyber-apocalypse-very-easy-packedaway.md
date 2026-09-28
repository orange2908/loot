---
title: "[Very Easy] PackedAway - cyber apocalypse 2024"
category: "rev"
subcategory: "packers"
type: "writeup"
tags: ["rev", "upx", "packer", "easy", "packedaway", "packers"]
summary: "rev writeup for \"[Very Easy] PackedAway\" from cyber apocalypse - techniques: upx, packer, easy, packedaway, packers."
source:
  name: "hackthebox/cyber-apocalypse-2024"
  url: "https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/%5BVery%20Easy%5D%20PackedAway/README.md"
ctf:
  name: "cyber apocalypse"
  year: 2024
  challenge: "[Very Easy] PackedAway"
---

## Source

- **CTF:** cyber apocalypse 2024
- **Challenge:** [Very Easy] PackedAway
- **Repository:** [hackthebox/cyber-apocalypse-2024](https://github.com/hackthebox/cyber-apocalypse-2024)
- **File:** <https://github.com/hackthebox/cyber-apocalypse-2024/blob/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/%5BVery%20Easy%5D%20PackedAway/README.md>

---
<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/banner.png" style="zoom: 80%;" align=center />

<img src="https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">PackedAway</font>

  6<sup>th</sup> 03 24 / Document No. D24.102.20

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Very Easy</font>

  Classification: Official






# Synopsis

PackedAway is a Very Easy reversing challenge. Players will use `UPX` to extract the original version of an executable.

## Skills Learned
    - Unpacking `UPX` executables

# Solution

If we run the binary, it opens a UI containing a text box with 'Placeholder'. If we write a fake flag such as `HTB{xx}`, it is highlighted in red.

![textbox with fake flag highlighted in red](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/[Very%20Easy]%20PackedAway/assets/textbox.png).

If we run `strings` on the binary, there are no obvious secrets - but there are several 'UPX!' strings. If we use `upx -d` to extract the binary, we will unpack a slightly larger one. We can then run `strings` again, and find the flag in the output.

If we enter this in the textbox, it will be highlighted in green.

![textbox with blurred flag highlighted in green](https://raw.githubusercontent.com/hackthebox/cyber-apocalypse-2024/4e59eec7a4919d2a4ae4f5d98ecf8ba153ac464a/reversing/[Very%20Easy]%20PackedAway/assets/flag.png).
