---
title: "Pool Party - Platypwn 2025"
category: "pwn"
subcategory: "heap"
type: "writeup"
tags: ["linux", "nginx", "pwn", "heap", "buffer-overflow", "base64", "platypwn", "platypwn-2025", "2025", "ctf-writeup"]
summary: "This challenges requires exploiting a modified nginx (/ɛn dʒɪŋks/, \"en jinks\") binary which added a handful of new functions, which can be found through the ngxhttppp prefix."
source:
  name: "CTFtime writeup #40502"
  url: "https://ctftime.org/writeup/40502"
original_source: "https://w0y.at/writeup/2025/11/21/platypwn-2025-pool-party.html"
ctf:
  name: "Platypwn 2025"
  year: 2025
  challenge: "Pool Party"
---

## Metadata

- **CTF:** Platypwn 2025
- **Task:** Pool Party
- **Author team:** WE_0WN_Y0U
- **CTFtime tags:** linux, nginx, pwn, heap
- **CTFtime:** <https://ctftime.org/writeup/40502>
- **Original writeup:** <https://w0y.at/writeup/2025/11/21/platypwn-2025-pool-party.html>

---
## TL;DR  
This challenges requires exploiting a modified nginx (/ɛn dʒɪŋks/, "en jinks") binary which added a handful of new functions, which can be found through the `ngx_http_pp_` prefix. 

We can exploit a Heap BOF (Buffer OverFlow) through missing size checks in the nginx function `ngx_decode_base64` to overwrite a destructor inside the nginx Pool struct and get RIP & RDI control, which we use to extract the flag.

## [more ...](<https://w0y.at/writeup/2025/11/21/platypwn-2025-pool-party.html>)
