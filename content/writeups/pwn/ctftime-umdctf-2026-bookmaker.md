---
title: "bookmaker - UMDCTF 2026"
category: "pwn"
subcategory: "stack"
type: "writeup"
tags: ["pwn", "buffer-overflow", "heap", "use-after-free", "pie", "bookmaker", "stack", "umdctf", "umdctf-2026", "2026", "ctf-writeup"]
summary: "bookmaker is a pwn challenge built around a JavaScript runtime with native bindings."
source:
  name: "CTFtime writeup #40708"
  url: "https://ctftime.org/writeup/40708"
original_source: "https://blog.rawpayload.com/blog/umd-ctf-2026-bookmaker-writeup"
ctf:
  name: "UMDCTF 2026"
  year: 2026
  challenge: "bookmaker"
---

## Metadata

- **CTF:** UMDCTF 2026
- **Task:** bookmaker
- **Author team:** rawpayload
- **CTFtime:** <https://ctftime.org/writeup/40708>
- **Original writeup:** <https://blog.rawpayload.com/blog/umd-ctf-2026-bookmaker-writeup>

---
bookmaker is a pwn challenge built around a JavaScript runtime with native bindings. The bug is not a stack overflow; it is a native heap use-after-free exposed through a stale JavaScript ArrayBuffer.

The exploit flow is:

Allocate a native Ledger backing buffer of size 0x30.  
Obtain a JS ArrayBuffer view of that native allocation with ledger.view().  
Free the native allocation with ledger.recycle().  
Allocate a Wire object with mintWire(), which reuses the freed 0x30 chunk.  
Use the stale ArrayBuffer to read and corrupt the live Wire structure.  
Leak the PIE base from the Wire resolver function pointer.  
Convert wireWrite() into an arbitrary write by overwriting wire->dst and wire->len.  
Overwrite the global callback used by settle() with the hidden function that calls system("/bin/sh").  
Send cat flag.txt after the JS EOF marker so the spawned shell executes it.
