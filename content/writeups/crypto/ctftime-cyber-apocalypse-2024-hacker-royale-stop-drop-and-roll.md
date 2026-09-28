---
title: "Stop Drop and Roll - Cyber Apocalypse 2024: Hacker Royale"
category: "crypto"
type: "writeup"
tags: ["crypto", "stop", "drop", "roll", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "This video game is very simple"
source:
  name: "CTFtime writeup #38985"
  url: "https://ctftime.org/writeup/38985"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Stop Drop and Roll"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Stop Drop and Roll
- **Author team:** D0M BU$TЄR$
- **CTFtime:** <https://ctftime.org/writeup/38985>

---
## misc / Stop Drop and Roll

> The Fray: The Video Game is one of the greatest hits of the last... well, we don't remember quite how long. Our "computers" these days can't run much more than that, and it has a tendency to get repetitive...

```plaintext  
===== THE FRAY: THE VIDEO GAME =====  
Welcome!  
This video game is very simple  
You are a competitor in The Fray, running the GAUNTLET  
I will give you one of three scenarios: GORGE, PHREAK or FIRE  
You have to tell me if I need to STOP, DROP or ROLL  
If I tell you there's a GORGE, you send back STOP  
If I tell you there's a PHREAK, you send back DROP  
If I tell you there's a FIRE, you send back ROLL  
Sometimes, I will send back more than one! Like this:   
GORGE, FIRE, PHREAK  
In this case, you need to send back STOP-ROLL-DROP!  
Are you ready? (y/n)   
```

This challenge is connecting to a remote container, giving us strings containing GORGE, PHREAK, and FIRE. We are supposed to send the correct translation, of which GORGE is STOP, PHREAK, is DROP, and FIRE is ROLL.

```python  
from pwn import *

r = remote('94.237.62.240', 45066)

r.recvuntil(b'(y/n) ')

r.sendline(b'y')

r.recvuntil(b'\n')

tries = 0

while True:  
try:  
got = r.recvline().decode()  
payload = got.replace(", ", "-").replace("GORGE", "STOP").replace("PHREAK", "DROP").replace("FIRE", "ROLL").strip()

r.sendlineafter(b'What do you do?', payload.encode())  
tries = tries + 1  
[log.info](http://log.info)(f'{tries}: {payload}')  
except EOFError:  
log.success(got.strip())  
r.close()  
break  
```

And the flag is:

```text  
HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}  
```
