---
title: "coinflip - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "prng"
type: "writeup"
tags: ["crypto", "prng", "gcd", "lsb", "proof-of-work", "coinflip", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "This challenge requies to beat the odds against an RNG to collect enough coins to get the flag."
source:
  name: "CTFtime writeup #39886"
  url: "https://ctftime.org/writeup/39886"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "coinflip"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** coinflip
- **Author team:** thehackerscrew
- **CTFtime tags:** prng
- **CTFtime:** <https://ctftime.org/writeup/39886>

---
This challenge requies to beat the odds against an RNG to collect enough coins to get the flag.  
The RNG has a 64-bit state, and it outputs every one of the 64 bits going from MSB to LSB before advancing to the next state by calculating `next_state = a*pow(old_state, 3, m) % m` , where a, m are unknown constants. We start with a balance of 2 coins and need to get all the way up to 1000000000 to get the flag.  
Every round, we can choose how much of our balance to bet. Since the outputs are binary, we have a 50-50 chance of winning. We notice that we don't need to recover the entire state, as well as the a, m values which are initially unknown. All that's needed is to be able to accurately guess one bit (per state rotation) and bet all our money then in order to double it. For the other 63 bits per state, we can simply bet the minimum (1 coin) and suffer marginal changes to our balance due to the 50% chance of winning we have. 

We note that the modulus m is random, and not odd (or prime even as is often the case). As a result, if we're lucky and an even m is selected (50% chance), then the reductions modulo that m do not influence the parity, and thus the LSB of the number. This is interesting since, we can see in the source code that both a and the initial state are chosen so that they have gcd  1 with m , so if m is even, both a and the first state will be odd.

This in turn means that `a*pow(state0, 3)` will be odd (as the product of 4 odd numbers), and as mentioned already, applying % m to this will keep the LSB fixed. We can see that all subsequent state will therefore have the LSB equal to 1, and we can bet all our money for that bit in order to get the flag.

```py  
from pwn import *  
import random

TARGET = 1_000_000_000

def attempt():  
balance = 2  
conn = remote("52.59.124.14", 5032)  
try:  
while True:  
for i in range(63):  
balance = int(conn.recvline().decode().strip().split("? ")[-1].split()[-1][:-1])  
print(balance)  
  
if balance > TARGET:  
conn.interactive()  
exit()  
conn.sendline(b"1")  
conn.recvline()  
conn.sendline(["head", "tails"][random.getrandbits(1)].encode())  
conn.recvline()  
balance = int(conn.recvline().decode().strip().split("? ")[-1].split()[-1][:-1])  
print(balance)  
conn.sendline(str(balance).encode())  
conn.recvline()  
conn.sendline(["head", "tails"][1].encode())  
print(conn.recvline())  
if balance > TARGET//2:  
conn.interactive()  
exit()  
except Exception:  
conn.close()  
return  
while True:  
attempt()  
# ENO{1nfin1t3_r1che5_3re_y0ur5_1t_s33m5}  
```
