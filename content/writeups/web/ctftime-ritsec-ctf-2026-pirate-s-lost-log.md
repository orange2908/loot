---
title: "Pirate's Lost Log - RITSEC CTF 2026"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "command-injection", "pirate", "lost", "log", "rce", "ritsec-ctf", "ritsec-ctf-2026", "2026", "ctf-writeup"]
summary: "Despite the DNS theme in the description, this was a command injection challenge."
source:
  name: "CTFtime writeup #40780"
  url: "https://ctftime.org/writeup/40780"
ctf:
  name: "RITSEC CTF 2026"
  year: 2026
  challenge: "Pirate's Lost Log"
---

## Metadata

- **CTF:** RITSEC CTF 2026
- **Task:** Pirate's Lost Log
- **Author team:** wombatwarfare
- **CTFtime:** <https://ctftime.org/writeup/40780>

---
Despite the DNS theme in the description, this was a command injection challenge.

1\. The web portal at `http://pirates-lost-log.ctf.ritsec.club/` has a hidden page at `/_sys/cfcd208495d565ef66e7dff9f98764da` (md5("0"))  
2\. This page contains a "Network Ping Tool" that takes a target IP  
3\. The input is passed to a shell command without proper sanitization  
4\. Command injection via semicolon: `127.0.0.1;cat /app/flag-9d444ad0f475b52e79a1713f25646dce.txt`  
5\. Flag was in `/app/flag-9d444ad0f475b52e79a1713f25646dce.txt`  
**Flag:** `RS{1_br0k3_17_e6ebced80740d006889f26ceeeee666b}`
