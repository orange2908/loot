---
title: "Zoney - Nullcon Goa HackIM 2026 CTF"
category: "rev"
type: "writeup"
tags: ["rev", "zoney", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "The challenge involves a DNS server at 52.59.124.14:5054 and a target domain flag.ctf.nullcon.net."
source:
  name: "CTFtime writeup #40596"
  url: "https://ctftime.org/writeup/40596"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Zoney"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Zoney
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40596>

---
**Challenge Description**:  
The challenge involves a DNS server at `52.59.124.14:5054` and a target domain `[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)`. The goal is to find the flag hidden in the DNS records.

**Analysis**:  
Initial exploration revealed:  
\- `[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)` has an A record `10.13.37.1` and a TXT record "The flag was removed.".  
\- Standard AXFR zone transfers failed for both `[ctf.nullcon.net](http://ctf.nullcon.net)` and `[flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)`.  
\- No NSEC/NSEC3 records were found using `dig +dnssec`.  
\- `[CTF.nullcon.net](http://CTF.nullcon.net)` nameserver `[ns.ctf.nullcon.net](http://ns.ctf.nullcon.net)` did not resolve.

The "flag was removed" message and the challenge name "Zoney" hinted at Zone Transfers or history.  
Checking `IXFR` (Incremental Zone Transfer) allows requesting differences between versions.  
We probed `IXFR=1499` (since current serial was 1500) and saw a previous TXT record "Phew, removed the flag...".  
Deeper probing with `IXFR=1337` returned a large history of updates.

**Solution**:  
1\. Query the DNS server for an Incremental Zone Transfer starting from an old serial number (e.g., 1337).  
```bash  
dig @52.59.124.14 -p 5054 IXFR=1337 [flag.ctf.nullcon.net](http://flag.ctf.nullcon.net)  
```  
2\. Inspect the output for the flag in the transaction history.

**Flag**: `ENO{1337_1ncr3m3nt4l_z0n3_tr4nsf3r_m4st3r_8f9a2c1d}`
