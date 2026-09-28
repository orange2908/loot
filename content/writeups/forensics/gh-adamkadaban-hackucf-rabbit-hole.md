---
title: "rabbit hole - HackUCF"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "foremost", "rabbit", "hole", "disk"]
summary: "forensics writeup for \"rabbit hole\" from HackUCF - techniques: binwalk, foremost, rabbit, hole, disk."
source:
  name: "Adamkadaban/CTFs"
  url: "https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/HackUCF/forensics/rabbit-hole/README.md"
ctf:
  name: "HackUCF"
  challenge: "rabbit hole"
---

## Source

- **CTF:** HackUCF
- **Challenge:** rabbit hole
- **Repository:** [Adamkadaban/CTFs](https://github.com/Adamkadaban/CTFs)
- **File:** <https://github.com/Adamkadaban/CTFs/blob/ea683463e77d8867fb31dae4cb4fa6dd3da68852/1.CTFs/HackUCF/forensics/rabbit-hole/README.md>

---
* This took so long, I can't even be bothered to write up every single step

* First, I used `foremost` to extract some files from the image
* I might have used binwalk a couple times
* I had to fix the hex of one file once with `hexedit` to change the name from `falg.txt` to `flag.txt` a couple places 
* This was just a process of doing a lot of .zip, .gz, [.bz2](https://www.cyberciti.biz/faq/linuxunix-how-to-extract-and-decompress-a-bz2-tbz2-file/) unzipping
