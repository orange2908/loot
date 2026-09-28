---
title: "SimpleNote - BlitzCTF"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["fastbins", "pwn", "heap", "tcache", "calloc", "rop", "fastbin", "use-after-free", "pie", "blitzctf", "ctf-writeup"]
summary: "This is a pwn challenge which has a note system, often met at heap challenges."
source:
  name: "CTFtime writeup #40338"
  url: "https://ctftime.org/writeup/40338"
original_source: "https://header.ro/posts/simplenote/"
ctf:
  name: "BlitzCTF"
  challenge: "SimpleNote"
---

## Metadata

- **CTF:** BlitzCTF
- **Task:** SimpleNote
- **Author team:** OctalO
- **CTFtime tags:** fastbins, pwn, heap, tcache, calloc
- **CTFtime:** <https://ctftime.org/writeup/40338>
- **Original writeup:** <https://header.ro/posts/simplenote/>

---
## Summary  
This is a pwn challenge which has a note system, often met at heap challenges. We are given the option to create, edit, show and delete chunks. There is also a secret function which allows us to get a leak. All protections are enabled and the binary uses a modern libc version. The creation of chunks is done via calloc, which doesn’t look in the tcache directly and also fills the allocated chunk with zeroes. We are also limited to 7 entries in our pointer list, which suggests that we can only have 7 chunks allocated. 

In order to solve this, I used the secret function to get PIE leak, exploited UAF vulnerability to overwrite keys in order to fill tcache, allocated a chunk over the pointer list by overwriting FD of a fastbin chunk and using that to read and write anywhere for libc leak, stack leak and ROP.

See the full writeup here: [<https://header.ro/posts/simplenote/>](<https://header.ro/posts/simplenote/>)
