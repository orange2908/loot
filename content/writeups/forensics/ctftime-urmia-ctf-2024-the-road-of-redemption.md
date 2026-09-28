---
title: "The Road of Redemption - Urmia CTF 2024"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["forensics", "ecb", "pcap", "tshark", "cyberchef", "network", "urmia-ctf", "urmia-ctf-2024", "2024", "ctf-writeup"]
summary: "This task was quite frustrating because it was impossible to find IV, which, as it turned out later, didn’t exist, but let me explain step by step."
source:
  name: "CTFtime writeup #39460"
  url: "https://ctftime.org/writeup/39460"
ctf:
  name: "Urmia CTF 2024"
  year: 2024
  challenge: "The Road of Redemption"
---

## Metadata

- **CTF:** Urmia CTF 2024
- **Task:** The Road of Redemption
- **Author team:** MindCrafters
- **CTFtime tags:** forensics
- **CTFtime:** <https://ctftime.org/writeup/39460>

---
This task was quite frustrating because it was impossible to find IV, which, as it turned out later, didn’t exist, but let me explain step by step.

1\. Use NetworkMiner to extract the files  
index.html

[<https://icyberchef.com/#recipe=From_Hex('Auto')Render_Image('Raw')> ](http://)  
You will see blowfish

-  
key/index.html  
decode QXJhc1ZhbGxleV9NZWRpZXZhbFNocmluZV8xMjk3X3VjdGY= with bas64 and You will receive the password.

2.  
decode strings from pcap. It will be data encoded in Blowfish.  
`tshark -r The-Road-of-Redemption.pcap -Y "[dns.qry.name](http://dns.qry.name) contains [uctf.ir](http://uctf.ir)" -T fields -e [dns.qry.name](http://dns.qry.name) | uniq | sed 's/.uctf.ir//g' | tr -d '\n'`

3\. Put the binary to Cyberchef (but remember, old version 9.4, not newer ;)  
[<https://icyberchef.com/#recipe=Blowfish_Decrypt(%7B'option':'Hex','string':'ArasValley_MedievalShrine_1297_uctf'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw')>](http://)

Many teams probably had problems because they were using the new CyberChef.

thats all

Kerszi/MindCrafters
