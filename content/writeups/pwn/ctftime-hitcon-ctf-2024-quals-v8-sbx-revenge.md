---
title: "V8 SBX Revenge - HITCON CTF 2024 Quals"
category: "pwn"
subcategory: "shellcode"
type: "writeup"
tags: ["pwn", "shellcode", "pie", "sbx", "revenge", "hitcon-ctf-2024-quals", "2024", "ctf-writeup"]
summary: "The challenge provides two exploitation primitives: writing a 64-bit value to the entry of the trusted pointer table and leaking the base address of PIE."
source:
  name: "CTFtime writeup #39322"
  url: "https://ctftime.org/writeup/39322"
original_source: "https://mem2019.github.io/jekyll/update/2024/07/14/HITCON.html"
ctf:
  name: "HITCON CTF 2024 Quals"
  year: 2024
  challenge: "V8 SBX Revenge"
---

## Metadata

- **CTF:** HITCON CTF 2024 Quals
- **Task:** V8 SBX Revenge
- **Author team:** r3kapig
- **CTFtime:** <https://ctftime.org/writeup/39322>
- **Original writeup:** <https://mem2019.github.io/jekyll/update/2024/07/14/HITCON.html>

---
The challenge provides two exploitation primitives: writing a 64-bit value to the entry of the trusted pointer table and leaking the base address of PIE. We can use the first primitive to fake a WasmExportedFunctionData instance, allowing us to set rip to an 8-byte value in the trusted memory region. To control the content in this region, we leverage the immediate number arguments of the bytecode instruction AddSmi.ExtraWide. We can set the rip to point to the immediate numbers in the RWX page, whose address can be leaked by the second primitive, to execute our shellcode.
