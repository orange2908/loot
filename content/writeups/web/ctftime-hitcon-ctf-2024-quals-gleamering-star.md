---
title: "Gleamering Star - HITCON CTF 2024 Quals"
category: "web"
subcategory: "integer"
type: "writeup"
tags: ["web", "cryptography", "otp", "integer-overflow", "bit-by-bit", "gleam", "integer", "hitcon-ctf-2024-quals", "2024", "ctf-writeup"]
summary: "TL;DR <<userkey:128>> is a deadly security issue - keeps 128 least significant bits only."
source:
  name: "CTFtime writeup #39347"
  url: "https://ctftime.org/writeup/39347"
original_source: "https://lior.gg/posts/2024/hitcon/gleamering_star/"
ctf:
  name: "HITCON CTF 2024 Quals"
  year: 2024
  challenge: "Gleamering Star"
---

## Metadata

- **CTF:** HITCON CTF 2024 Quals
- **Task:** Gleamering Star
- **Author team:** Friendly Maltese Citizens
- **CTFtime tags:** web, cryptography, otp, integer-overflow, bit-by-bit, gleam
- **CTFtime:** <https://ctftime.org/writeup/39347>
- **Original writeup:** <https://lior.gg/posts/2024/hitcon/gleamering_star/>

---
TL;DR `<<user_key:128>>` is a deadly security issue - keeps 128 least significant bits only.

I've written a highly detailed writeup of the challenge and how we utilized this issue to recover the internal authorization key of the system.

You can read it here: <https://lior.gg/posts/2024/hitcon/gleamering_star/>

P.S accidentally set the description of the challenge in CTFtime to be a description of our writeup - CTFTime doesn't let me edit it :(
