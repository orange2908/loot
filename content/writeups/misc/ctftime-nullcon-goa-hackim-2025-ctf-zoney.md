---
title: "ZONEy - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "zoney", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This challenge was all about DNS enumeration and exploiting NSEC record leaks to uncover hidden subdomains."
source:
  name: "CTFtime writeup #40012"
  url: "https://ctftime.org/writeup/40012"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "ZONEy"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** ZONEy
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40012>

---
### Zoney Writeup

This challenge was all about **DNS enumeration** and exploiting **NSEC record leaks** to uncover hidden subdomains.

1\. **Initial Discovery:**   
Used `dig` to query the nameserver:   
```sh  
dig @52.59.124.14 -p 5007 www.zoney.eno +cmd  
```   
This revealed the existence of `challenge.zoney.eno`. 

2\. **Abusing NSEC Records:**   
Since **NSEC (Next Secure) records** can expose the next valid DNS entry, we queried:   
```sh  
dig @52.59.124.14 -p 5007 challenge.zoney.eno NSEC  
```   
This leaked another subdomain: **`hereisthe1337flag.zoney.eno`**. 

3\. **Extracting the Flag:**   
The final step was querying the TXT record for the leaked subdomain:   
```sh  
dig @52.59.124.14 -p 5007 hereisthe1337flag.zoney.eno TXT  
```   
And we got the flag `ENO{1337_FL4G_NSeC_W4LK3R}`
