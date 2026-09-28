---
title: "ATM - Space Heroes 2024"
category: "rev"
subcategory: "prng"
type: "writeup"
tags: ["srand", "libc", "rev", "prng", "atm", "space-heroes", "space-heroes-2024", "2024", "ctf-writeup"]
summary: "In this writeup, we'll discuss the exploitation of the \"Space Heroes ATM\" challenge."
source:
  name: "CTFtime writeup #39057"
  url: "https://ctftime.org/writeup/39057"
ctf:
  name: "Space Heroes 2024"
  year: 2024
  challenge: "ATM"
---

## Metadata

- **CTF:** Space Heroes 2024
- **Task:** ATM
- **Author team:** mimicats
- **CTFtime tags:** srand, libc, rev
- **CTFtime:** <https://ctftime.org/writeup/39057>

---
# Space Heroes ATM Writeup

## Introduction  
In this writeup, we'll discuss the exploitation of the "Space Heroes ATM" challenge. The goal was to exploit a vulnerability in the provided binary to gain unauthorized access to the ATM and retrieve the flag.

## Initial Analysis  
Upon analyzing the binary, we discovered that it utilizes the current time as a seed for generating a random number. This random number is then used in the ATM service for some operation, likely related to processing transactions. Additionally, there was no apparent input validation or authentication mechanism.

## Exploitation Strategy  
1\. **Understanding Time-based Seed**: The binary generates a random number using the current time as a seed. This means that if we can predict or control the time at which the random number is generated, we can predict the generated random number.  
2\. **Exploiting Predictable Randomness**: We can predict the random number by manipulating the time zone offset used in the generation process. By setting the time zone offset to a specific value, we can ensure that the generated random number matches our expectation.  
3\. **Interacting with the ATM Service**: With the predictable random number, we interact with the ATM service to trigger the desired behavior. This may involve simulating a transaction or accessing a hidden functionality.

## Exploitation Code  
```python  
from pwn import *  
from ctypes import CDLL

#context.binary = binary = ELF("./atm.bin")

libc = CDLL('libc.so.6')

def generate_random_number():  
current_time = int(time.time())  
libc.srand(current_time)  
random_number = libc.rand()  
return random_number

#p = process()  
p = remote("[spaceheroes-atm.chals.io](http://spaceheroes-atm.chals.io)", 443, ssl=True, sni="[spaceheroes-atm.chals.io](http://spaceheroes-atm.chals.io)")  
random_num = generate_random_number()  
  
p.recvuntil(b"Option:")  
p.sendline(b"w")  
p.recvuntil(b"Amount:")  
p.sendline(str(random_num).encode())  
p.recvline()  
print(p.recvline())  
p.close()
