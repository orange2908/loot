---
title: "Initial Reconnaissance - KnightCTF 2025"
category: "misc"
subcategory: "network"
type: "writeup"
tags: ["misc", "wireshark", "nmap", "initial", "reconnaissance", "network", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "Find the basic web enumeration tool that is used by the attacker."
source:
  name: "CTFtime writeup #39817"
  url: "https://ctftime.org/writeup/39817"
original_source: "https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/Initial_Reconnaissance.md"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "Initial Reconnaissance"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** Initial Reconnaissance
- **Author team:** Not_So_Intelligent
- **CTFtime:** <https://ctftime.org/writeup/39817>
- **Original writeup:** <https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/Initial_Reconnaissance.md>

---
## Initial Reconnaissance

Find the basic web enumeration tool that is used by the attacker.

## Steps

**1.** Filter out the attacker's ip which is `192.168.1.9` and the `http` requets in `Wireshark`. Use the following display filter.

```bash  
ip.addr == 192.168.1.9 && http  
```

**2.** Find the name of the common web enumeration tools like `Nmap`, `Nikto`. Use `CTRL+F` to open the find tab.

**3.** We will be able to see a tool name in one of the `http` request like the one below:

![nikto_KnightCTF2025](<https://github.com/user-attachments/assets/a522ac78-b405-4606-82e6-cc439d23b2aa>)

**4.** We find that the tool `Nikto` has been used by the attacker. So, the flag is:

```bash  
KCTF{nikto}  
```
