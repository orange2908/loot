---
title: "ZONEy - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "zoney", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "name hints at dns zones, and updated connection info says \"UDP\" which also further hints at dns (which is dns usually)."
source:
  name: "CTFtime writeup #39881"
  url: "https://ctftime.org/writeup/39881"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "ZONEy"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** ZONEy
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39881>

---
name hints at dns zones, and updated connection info says "UDP" which also further hints at dns (which is dns usually).  
First we can find via basic enum (using zoney.eno from description)  
`dig +short MX @52.59.124.14 -p 5007 zoney.eno`  
Which gives us the record  
challenge.zoney.eno  
We can further find with basic enumeration  
`dig +dnssec @52.59.124.14 -p 5007 zoney.eno`  
Which shows dnssec is enabled. We can then find  
`dig +dnssec @52.59.124.14 -p 5007 <anything here>.challenge.zoney.eno`  
which gets us  
```  
challenge.zoney.eno. 86400 IN NSEC hereisthe1337flag.zoney.eno. A RRSIG NSEC  
```  
This is because its a NSEC record which basically gives us information about the next valid record in the zone, in this case the flag.  
Which we can lastly do:  
```  
dig TXT @52.59.124.14 -p 5007 hereisthe1337flag.zoney.eno  
```  
to get the flag
