---
title: "Bad OpSec - KubSTU CTF"
category: "misc"
type: "writeup"
tags: ["misc", "bad", "opsec", "kubstu-ctf", "ctf-writeup"]
summary: "Run the PDF417 decoder to decode the bar code on the boarding pass."
source:
  name: "CTFtime writeup #40768"
  url: "https://ctftime.org/writeup/40768"
ctf:
  name: "KubSTU CTF"
  challenge: "Bad OpSec"
---

## Metadata

- **CTF:** KubSTU CTF
- **Task:** Bad OpSec
- **Author team:** μAGMA
- **CTFtime:** <https://ctftime.org/writeup/40768>

---
Run the PDF417 decoder to decode the bar code on the boarding pass. Find the departing airport KRR and destination SVX - Yekaterinburg - and also the flight number U6210. According to the boarding pass the flight took part on 15 FEB. Find in one of the public online flight databases flights from KRR to SVX on 15.02.2026 and its arrival time 21:39 or 21:40 (differ from database to database) - the correct one is 21:39. Concatenate all the info as specified in the task to create the flag.
