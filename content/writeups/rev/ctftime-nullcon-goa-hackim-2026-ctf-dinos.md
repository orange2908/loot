---
title: "DiNoS - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "dinos", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge involves a DNS server at 52.59.124.14:5052 and a target domain dinos.nullcon.net."
source:
  name: "CTFtime writeup #40620"
  url: "https://ctftime.org/writeup/40620"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "DiNoS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** DiNoS
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40620>

---
**Challenge Description**:  
The challenge involves a DNS server at `52.59.124.14:5052` and a target domain `[dinos.nullcon.net](http://dinos.nullcon.net)`. The goal is to find the hidden flag.

**Analysis**:  
\- Zone transfer (AXFR/IXFR) failed.  
\- DNSSEC was enabled, indicated by the presence of NSEC records.  
\- NSEC records reveal the "next" domain in the zone, allowing us to walk the chain and enumerate all subdomains.  
\- The subdomains appeared to be hashes (e.g., `0utyff...`), but they had TXT records attached.

**Solution**:  
1\. We wrote a script `[walk_nsec.py](http://walk_nsec.py)` to traverse the NSEC chain starting from `[dinos.nullcon.net](http://dinos.nullcon.net)`.  
2\. For each discovered domain, we queried its TXT record.  
3\. The script found a TXT record containing the flag.

**Flag**: `ENO{RAAWR_RAAAAWR_You_found_me_hiding_among_some_NSEC_DiNoS}`
