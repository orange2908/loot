---
title: "hxp_silicon_foundaries_hack4 - hxp 38C3 CTF"
category: "pwn"
subcategory: "rop"
type: "writeup"
tags: ["amd64", "kernel", "qemu", "pwn", "x86-64", "rop", "shellcode", "hxp-38c3-ctf", "ctf-writeup"]
summary: "The challenge consists of a modified QEMU binary which adds new instructions to the existing x86-64 set, notably MTS (load bytes from scratch memory), STM (store bytes to scratch memory) which are unp"
source:
  name: "CTFtime writeup #40243"
  url: "https://ctftime.org/writeup/40243"
original_source: "https://hofhackerei.at/blog/hxp_38c3_hack4/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "hxp_silicon_foundaries_hack4"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** hxp_silicon_foundaries_hack4
- **Author team:** KuK Hofhackerei
- **CTFtime tags:** amd64, kernel, qemu, pwn, x86-64
- **CTFtime:** <https://ctftime.org/writeup/40243>
- **Original writeup:** <https://hofhackerei.at/blog/hxp_38c3_hack4/>

---
# TL;DR

The challenge consists of a modified QEMU binary which adds new instructions to the existing x86-64 set, notably `MTS` (load bytes from scratch memory), `STM` (store bytes to scratch memory) which are unprivileged and `SCRHLW` (update scratch memory) which is privileged. \  
Additionally two MSR (Model Specific Registers) where added `MSR_HACK4_SLICE_SIZE=0x400` and `MSR_HACK4_NUM_SLICES=33`  
The privileged `SCRHLW` instruction can be access through a patched in `prctl` option `PR_SET_SCRATCH_HOLE` inside the linux kernel and seems to directly update the TLB (Translation Lookaside Buffer) which we can exploit.

1\. We exploit the TLB update in `SCRHLW` to inject CPL0 shellcode  
2\. We modify the MSR to allow OOB Access, they are mapped to a stack array in QEMU  
3\. we use the OOB Access to write a ROP Chain inside QEMU, to escape and get the flag

# [more ...](<https://hofhackerei.at/blog/hxp_38c3_hack4/>)
