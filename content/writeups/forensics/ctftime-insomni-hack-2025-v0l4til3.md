---
title: "v0l4til3 - Insomni'hack 2025"
category: "forensics"
subcategory: "memory"
type: "writeup"
tags: ["forensics", "volatility", "forensic", "memory-forensics", "v0l4til3", "memory", "insomni-hack", "insomni-hack-2025", "2025", "ctf-writeup"]
summary: "For this challenge, you need to find the flag that corresponds to the password hash of a user."
source:
  name: "CTFtime writeup #40085"
  url: "https://ctftime.org/writeup/40085"
original_source: "https://twditm.sirnef.com/writeups/insomnihack2025-v0l4til3.htm"
ctf:
  name: "Insomni'hack 2025"
  year: 2025
  challenge: "v0l4til3"
---

## Metadata

- **CTF:** Insomni'hack 2025
- **Task:** v0l4til3
- **Author team:** C8H10N4O2
- **CTFtime tags:** volatility, forensic
- **CTFtime:** <https://ctftime.org/writeup/40085>
- **Original writeup:** <https://twditm.sirnef.com/writeups/insomnihack2025-v0l4til3.htm>

---
For this challenge, you need to find the flag that corresponds to the password hash of a user.

Based on the name of the challenge, you can guess that you need to use Volatility.

1\. You can identify a Windows OS memory dump with the following command:

`$ [vol.py](http://vol.py) -f ~/Downloads/insomni/image.mem [windows.info](http://windows.info)`  
  
2\. Finally, use this command to retrieve the flag:

`$ [vol.py](http://vol.py)-f ~/Downloads/insomni/image.mem windows.hashdump`
