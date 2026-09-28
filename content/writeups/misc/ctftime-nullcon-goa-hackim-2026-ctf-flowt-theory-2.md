---
title: "Flowt Theory 2 - Nullcon Goa HackIM 2026 CTF"
category: "misc"
subcategory: "lfi"
type: "writeup"
tags: ["misc", "path-traversal", "flowt", "theory", "lfi", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40656"
  url: "https://ctftime.org/writeup/40656"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/Flowt_Theory_2/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Flowt Theory 2"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Flowt Theory 2
- **Author team:** RootRunners
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40656>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/Flowt_Theory_2/README.md>

---
# Flowt Theory 2

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Misc   
**Points:** 362   
**Service:** `52.59.124.14:5070`

## Overview  
The app stores user data in per-session files and exposes a file viewer via `view_receipt`. In v2 the input is wrapped in `basename()`, which blocks path traversal but still allows reading any file **inside the session directory**. The `.lock` file reveals the randomized secret filename, which contains the flag.

## Vulnerability  
`basename()` only strips directory components. It does not prevent access to hidden/system files stored in the same directory as user receipts.

## Exploit Steps  
1\. Get a session cookie by visiting the site.  
2\. Read the `.lock` file:  
```bash  
curl -sb "PHPSESSID=..." "http://52.59.124.14:5070/?view_receipt=.lock"  
```  
3\. Use the returned `secret_XXXXXXXX` filename to read the secret file:  
```bash  
curl -sb "PHPSESSID=..." "http://52.59.124.14:5070/?view_receipt=secret_XXXXXXXX"  
```  
4\. The response contains the flag (second line).

## Flag  
`ENO{s33ms_l1k3_w3_h4d_4_pr0bl3m_k33p_y0ur_fl04t1ng_p01nts_1n_ch3ck}`
