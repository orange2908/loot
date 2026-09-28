---
title: "DragoNflieS - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "cry", "dragonflies", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40655"
  url: "https://ctftime.org/writeup/40655"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/DragoNflieS/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "DragoNflieS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** DragoNflieS
- **Author team:** RootRunners
- **CTFtime tags:** cry
- **CTFtime:** <https://ctftime.org/writeup/40655>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/DragoNflieS/README.md>

---
# DragoNflieS

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Misc   
**Points:** 257   
**Service:** `52.59.124.14:5053`

## Overview  
The DNS server uses EDNS Client Subnet (ECS) to return different TXT answers for `[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)` based on the client subnet. By spoofing ECS with the right internal address, the real flag is returned.

## Approach  
1\. Query without ECS: returns `NOPE`.  
2\. Add ECS and test private ranges to confirm split-horizon behavior.  
3\. The winning subnet is `10.13.37.1/32`, which returns the real flag.

## Winning Query  
```bash  
dig @52.59.124.14 -p 5053 [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net) TXT +subnet=10.13.37.1/32  
```

## Flag  
`ENO{Whirr_do_not_send_private_data_for_wrong_IP_Whirr}`
