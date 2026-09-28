---
title: "hateful - Nullcon Goa HackIM 2025 CTF"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "ret2libc", "format-string", "pie", "libc-database", "stack", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We're given the libc and linker file as well as the binary, first thing i did was to patch it using pwninit"
source:
  name: "CTFtime writeup #39909"
  url: "https://ctftime.org/writeup/39909"
original_source: "https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/writeup.md#hateful"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "hateful"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** hateful
- **Author team:** QnQSec
- **CTFtime:** <https://ctftime.org/writeup/39909>
- **Original writeup:** <https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/writeup.md#hateful>

---
![image](<https://github.com/user-attachments/assets/0c01849d-1be9-4300-8030-6a22899f3178>)

We're given the libc and linker file as well as the binary, first thing i did was to patch it using `pwninit`  
![image](<https://github.com/user-attachments/assets/ea897b75-497d-42a0-8f0f-a69eabdf2a5f>)

When we run it we either get to choose `yay or nay`

Checking the protections enabled on the binary shows this  
![image](<https://github.com/user-attachments/assets/6fd32695-12e9-4c1c-b507-2dc54bbc6e86>)

Ok not much of a protection enabled here, loading it up in IDA here's the main function  
![image](<https://github.com/user-attachments/assets/28c564e4-95a7-4427-bf96-1a7425c8f446>)

So if we choose `yay` the `send_message` function gets called  
![image](<https://github.com/user-attachments/assets/7a97c9ad-6668-422a-86b9-8caf98bd479f>)

We see there are two bugs here which are a format string bug & a buffer overflow

The goal is simple, we first use the fsb to leak a libc address then we leverege the overflow to perform a ret2libc

In order to leak libc we can just leak pointers on the stack, but because pie is disabled i just decided to leak it by reading the value of the got of printf

Here's my [exploit](<https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/nullcon25/Hateful/solve.py>)  
![image](<https://github.com/user-attachments/assets/e353d2af-9a47-4321-bb58-d41f30cfd317>)

Running it on the remote instance works  
![image](<https://github.com/user-attachments/assets/ecf1978d-f73d-4b7a-8047-9bf3f1468259>)

```  
Flag: ENO{W3_4R3_50RRY_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}$  
```

Fun fact, during the competition the libc didn't work for me, so i had to leak the got of printf then used a libc [database](https://libc.rip/) to retrieve the right libc being used remotely
