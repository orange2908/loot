---
title: "Call me, maybe? No… wrong decade. - CTF@CIT 2026"
category: "misc"
type: "writeup"
tags: ["misc", "hashcat", "wordlists", "call", "maybe", "wrong", "decade", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "I don't have a witty description for this one..."
source:
  name: "CTFtime writeup #40745"
  url: "https://ctftime.org/writeup/40745"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Call me, maybe? No… wrong decade."
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Call me, maybe? No… wrong decade.
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40745>

---
# Writeup: Call me, maybe? No… wrong decade

\- Category: Misc  
\- Value: 887 pts  
\- Author: elemental

## Challenge

I don't have a witty description for this one...

`$2b$10$Ni0U3D5ibg1NY6G/k8CDHuXG7m/WNZzuV/9PDPnRzgKs4wUjaTwGO`

**FLAG FORMAT:** `CIT{password}`

## Recon

We are given a bcrypt hash (cost 10). The title "Call me, maybe? No... wrong decade." refers to the 2011 hit song "Call Me Maybe" by Carly Rae Jepsen, but implies the password is related to a famous phone number from a *different* decade.

The most famous phone number from an older decade is **867-5309** from the 1981 song "867-5309/Jenny" by Tommy Tutone.

## Solve

We can run the hash through `hashcat` on a GPU using the `rockyou.txt` wordlist:

```bash  
hashcat -m 3200 -a 0 hash.txt rockyou.txt  
```

Hashcat quickly cracks the bcrypt hash to reveal the password: `8675309jenny`

## Flag

```text  
CIT{8675309jenny}  
```
