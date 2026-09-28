---
title: "DiNoS - Nullcon Goa HackIM 2026 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "dinos", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40659"
  url: "https://ctftime.org/writeup/40659"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/DiNoS/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "DiNoS"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** DiNoS
- **Author team:** RootRunners
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40659>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Misc/DiNoS/README.md>

---
# DiNoS

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Misc   
**Points:** 50   
**Service:** `52.59.124.14:5052`

## Overview  
The challenge hosts a DNS zone at `[dinos.nullcon.net](http://dinos.nullcon.net)`. The flag is hidden in a TXT record of a subdomain. Because the zone uses DNSSEC with NSEC, we can enumerate the entire zone by walking the NSEC chain, then query TXT records to find the flag.

## Key Insight  
NSEC records link each existing name to the next name in canonical order. If NSEC is enabled (not NSEC3), you can iterate through the chain and list every name in the zone.

## Verification  
```sh  
dig @52.59.124.14 -p 5052 TXT "[verify.enodns.nullcon.net](http://verify.enodns.nullcon.net)" +short  
```  
Expected:  
```  
"connection_successful_Have_Fun_With_our_DiNoS_Challenge"  
```

## Enumeration via NSEC  
Query the zone apex and follow the `next` field until it loops.

```sh  
dig @52.59.124.14 -p 5052 [dinos.nullcon.net](http://dinos.nullcon.net) NSEC +short  
```

## Automated Walk + TXT Search (Python)  
```python  
import asyncio  
import dns.asyncresolver, dns.exception

server = "52.59.124.14"  
port = 5052  
zone = "[dinos.nullcon.net](http://dinos.nullcon.net)"

async def walk_nsec():  
resolver = dns.asyncresolver.Resolver(configure=False)  
resolver.nameservers = [server]  
resolver.port = port  
resolver.timeout = 1  
resolver.lifetime = 1

seen = set()  
order = []  
name = zone

for _ in range(2000):  
if name in seen:  
break  
seen.add(name)  
order.append(name)  
ans = await resolver.resolve(name, "NSEC", raise_on_no_answer=False)  
if ans.rrset is None:  
break  
nsec = ans.rrset[0]  
name = nsec.next.to_text(omit_final_dot=True)

return order

async def fetch_txt(names):  
resolver = dns.asyncresolver.Resolver(configure=False)  
resolver.nameservers = [server]  
resolver.port = port  
resolver.timeout = 1  
resolver.lifetime = 1

sem = asyncio.Semaphore(50)  
results = {}

async def one(name):  
async with sem:  
try:  
ans = await resolver.resolve(name, "TXT", raise_on_no_answer=False)  
except dns.exception.DNSException:  
return  
if ans.rrset is None:  
return  
txts = []  
for r in ans.rrset:  
parts = [s.decode(errors="ignore") for s in r.strings]  
txts.append("".join(parts))  
if txts:  
results[name] = txts

await asyncio.gather(*(one(n) for n in names))  
return results

async def main():  
names = await walk_nsec()  
txts = await fetch_txt(names)

for name, vals in txts.items():  
for v in vals:  
if "ENO{" in v:  
print(name, "->", v)

asyncio.run(main())  
```

## Flag  
`ENO{RAAWR_RAAAAWR_You_found_me_hiding_among_some_NSEC_DiNoS}`
