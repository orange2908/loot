---
title: "slop_allocator - TRX CTF 2026"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "canary", "pie", "slop", "allocator", "stack", "trx-ctf", "trx-ctf-2026", "2026", "ctf-writeup"]
summary: "A NASA-themed memory-management simulator in C."
source:
  name: "CTFtime writeup #40717"
  url: "https://ctftime.org/writeup/40717"
original_source: "https://blog.rawpayload.com/blog/trx-ctf-2026-slop-allocator-writeup"
ctf:
  name: "TRX CTF 2026"
  year: 2026
  challenge: "slop_allocator"
---

## Metadata

- **CTF:** TRX CTF 2026
- **Task:** slop_allocator
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40717>
- **Original writeup:** <https://blog.rawpayload.com/blog/trx-ctf-2026-slop-allocator-writeup>

---
The challenge  
A NASA-themed memory-management simulator in C. The user manages "spaceships" (structs of permission + char *notes[16]) and "notes" (variable-size blobs), all served by a custom slab/page allocator called SLOP. The menu offers:

allocate spaceship  
allocate note (under a chosen ship+slot, with caller-chosen length)  
free note  
takeoff (prints the spaceship pointer if permission != 0)  
anything else → exit(1)  
The binary is full RELRO, PIE, canary, NX, plus IBT and shadow stack. Linked against glibc 2.41 (the docker uses ubuntu:25.04).
