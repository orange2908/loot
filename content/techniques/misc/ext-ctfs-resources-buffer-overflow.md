---
title: "Buffer Overflow (ctfs/resources)"
category: "misc"
subcategory: "buffer-overflow"
type: "technique"
tags: ["ctfs-resources", "misc", "buffer-overflow", "shellcode", "buffer", "overflow", "binary-exploitation", "binary"]
summary: "A buffer overflow occurs when a buffer (i.e., an array) is filled with more data"
source:
  name: "ctfs/resources"
  url: "https://github.com/ctfs/resources/blob/68c4287943f5714ae86fff4af714d1a493175181/topics/binary-exploitation/buffer-overflow/README.md"
license: "CC0 1.0"
difficulty: "medium"
when_to_use: ["Vulnerable Functions", "Real World Examples", "More"]
---

# Buffer Overflow
A buffer overflow occurs when a buffer (i.e., an array) is filled with more data
than it can hold. The excess bytes of data are written directly into memory,
often causing a [segfault](https://en.wikipedia.org/wiki/Segmentation_fault) and crashing the program.


Vulnerable programs can be explioted to redirect the instruction pointer to
point to malicious code or [shell
code](https://en.wikipedia.org/wiki/Shellcode).


Buffer overflows are common in compiled langauges like C and C++, where array
boundaries are not checked.

## Vulnerable Functions
The table below shows several C and C++ functions vulnerable to buffer overflows
and their safe alternative:

| Vulnerable	| Safe		|
| ------------- | ------------- |
| strcpy	| strncpy	|
| strcat	| strncat	|
| sprintf	| snprintf	|
| gets		| fgets		|


## Real World Examples
Real world examples of buffer overflow exploits:
* [Morris Worm](https://en.wikipedia.org/wiki/Morris_worm)
* [Code Red Worm](https://en.wikipedia.org/wiki/Code_Red_worm)
* [Twilight Princess Exploit](https://en.wikipedia.org/wiki/The_Legend_of_Zelda:_Twilight_Princess#Technical_issues)


## More
[CTF 101 - Binary Exploitation](https://ctf101.org/binary-exploitation/buffer-overflow/)
[Wikipedia](https://en.wikipedia.org/wiki/Buffer_overflow)

---

## Source

ctfs/resources - <https://github.com/ctfs/resources/blob/68c4287943f5714ae86fff4af714d1a493175181/topics/binary-exploitation/buffer-overflow/README.md>

Mirrored into CTF-Brain at commit `68c4287943f5`. Licence: CC0 1.0. The text is the original authors' work.
