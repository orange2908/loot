---
title: "Server & Attacker IP - KnightCTF 2025"
category: "misc"
type: "writeup"
tags: ["misc", "server", "attacker", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "Find the ip of the server and the attacker"
source:
  name: "CTFtime writeup #39819"
  url: "https://ctftime.org/writeup/39819"
original_source: "https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/Server&amp;Attacker_IP.md"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "Server & Attacker IP"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** Server & Attacker IP
- **Author team:** Not_So_Intelligent
- **CTFtime:** <https://ctftime.org/writeup/39819>
- **Original writeup:** <https://github.com/Fuwad9096/CTF_WriteUPs/blob/main/KnightCTF-2025/Server&amp;Attacker_IP.md>

---
## Server & Attacker IP

Find the ip of the `server` and the `attacker`

## Steps

**1.** Filter out the `http` requests

**2.** We see the `http` requests as follows:

![Server_Attacker](<https://github.com/user-attachments/assets/c919989e-d34d-46df-b5e8-8995d97d457f>)

**3.** We see that the `source` and `destination` ip where the `http` requests are sent and recieved.

```bash  
source ip: 192.168.1.9  
destination ip: 192.168.1.10  
```

**4.** Here, we can see that, the `source` is the `attacker` and the `destination` is the `server`. So, the flag is:

```bash  
KCTF{192.168.1.10_192.168.1.9}  
```
