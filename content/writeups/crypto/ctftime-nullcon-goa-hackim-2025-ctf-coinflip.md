---
title: "coinflip - Nullcon Goa HackIM 2025 CTF"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "gcd", "proof-of-work", "coinflip", "pow", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Dr. Evil wants to play a game and he demands one million billion shitcoins for the flag."
source:
  name: "CTFtime writeup #39952"
  url: "https://ctftime.org/writeup/39952"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "coinflip"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** coinflip
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/39952>

---
# coinflip

## Decription

Dr. Evil wants to play a game and he demands one million billion shitcoins for the flag.

connection : `nc 52.59.124.14 5032`

## Source

```  
#!/usr/bin/env python3  
import os  
import sys  
from Crypto.Util.number import bytes_to_long, getRandomNBitInteger  
import math

flag = open('flag','r').read().strip()  
N = 64

def log(*err_messages):  
'''function for debugging purposes'''  
logs = open('err.log','a')  
for msg in err_messages:  
if type(msg) == bytes: msg = hexlify(msg).decode()  
logs.write(msg)  
logs.write('\n=====\n')  
logs.close()

class CRG(object):  
"""Cubic Random Generator"""

def __init__(self, n):  
'''n - bitlength of state'''  
self.n = n  
self.m = getRandomNBitInteger(n)  
while True:  
self.a = bytes_to_long(os.urandom(n >> 3)) % self.m # n/8 bytes  
if math.gcd(self.a, self.m) == 1: break  
while True:  
self.state = bytes_to_long(os.urandom(n >> 3)) % self.m # n/8 bytes  
if math.gcd(self.state, self.m) == 1: break  
self.buffer = []

def next(self):  
if self.buffer == []:  
self.buffer = [int(bit) for bit in bin(self.state)[2:].zfill(self.n)]  
self.state = self.a * pow(self.state, 3, self.m) % self.m  
#log('new state: ', self.state)  
return self.buffer.pop(0)

def loop():  
balance = 2  
coin = ['head','tails']  
crg = CRG(N)  
while True:  
if balance == 0:  
print('I do not talk to broke people.')  
return  
if balance >= 1000000000:  
print(f'Wow, here is your flag: {flag}')  
return  
print(f'How much do you want to bet? (you have {balance})')  
sys.stdout.flush()  
amount = int(sys.stdin.buffer.readline().strip())  
if amount > balance or amount <= 0:  
print('Ugh, cheater!')  
return  
print('What is your bet?')  
sys.stdout.flush()  
bet = sys.stdin.buffer.readline().strip().decode()  
if bet == coin[crg.next()]:  
print('you win')  
balance += amount  
else:  
print('you lose')  
balance -= amount

if __name__ == '__main__':  
try:  
loop()  
except Exception as err:  
print('Something went wrong')  
log('ERROR: ', repr(err))  
```

## Solution

\- The game is a simple head/tails guessing game based on the 0/1 generated from the CRG  
\- The state update logic of the CRG is `new_state = old_state**3 * a`  
\- And then the generator decide the next coin toss based on the bits of the current state from leftmost to rightmost  
\- We have to make bets on our guess and end up with 10**9 coins

\- Initially we can simply guess anything with small bets ( of 1 coin ), so that the states are revealed to us.  
\- Let s1, s2 and s3 be 3 consecutive states , so `s2 = a * s1**3` and `s3 = a * s2**3 = a**4 * s1**9`  
\- So `s3 * s1**3` should be equal to `s2**4` within modulus  
\- So, if we find multiples differences `s3 * s1**3 - s2**4` and get their gcd , it should be the modulus `m`  
\- Now we have `s1 mod m` and `a * s1**3 mod m` , so we can extract `a`  
\- From this point onwards we have the current `state`, mod `m` and `a`, so we can predict the net coin tosses and bet large coins

\- `[solve.py](http://solve.py)`  
```  
from pwn import *

found = True  
while found:  
try:  
r = remote("52.59.124.14",5032)  
# r.interactive()  
# context.log_level = 'debug'

bits = ''  
for i in range(64*5):  
r.recvuntil(b'(you have ')  
balance = int(r.recvuntil(b')\n')[:-2].decode().strip())  
r.sendline(b'1')  
r.recvuntil(b'?\n')  
r.sendline(b'head')  
if b'lose' in r.recvline():  
bits+='1'  
else:  
bits+='0'

s1 = int(bits[:64],2)  
s2 = int(bits[64:128],2)  
s3 = int(bits[128:64*3],2)  
s4 = int(bits[64*3:64*4],2)  
s5 = int(bits[64*4:64*5],2)  
print(f'{bits = }')  
print(f'{s1,s2,s3,s4,s5 = }')  
# s , as3 , a4s9, a13s27

diff1 = abs(pow(s2,4)-s3*pow(s1,3))  
diff2 = abs(pow(s3,4)-s4*pow(s2,3))  
diff3 = abs(pow(s4,4)-s5*pow(s3,3))

import math  
mod = math.gcd(math.gcd(diff1,diff2),diff3)  
print(mod)  
found = False  
print(balance)  
context.log_level = 'debug'  
a = (s2 * pow(pow(s1,-1,mod),3,mod))%mod  
state = (a*pow(s5,3,mod))%mod  
bits = ''  
while True:  
if balance>=1000000000:  
r.interactive()  
if bits=='':  
bits = bin(state)[2:].zfill(64)  
state = (a*pow(state,3,mod))%mod  
r.recvuntil(b'(you have ')  
balance = int(r.recvuntil(b')\n')[:-2].decode().strip())  
r.sendline(str(balance).encode())  
r.recvuntil(b'?\n')  
if bits[0] =='0':  
r.sendline(b'head')  
else:  
r.sendline(b'tails')  
bits = bits[1:]  
except:  
r.close()  
pass  
```

## Flag  
`ENO{1nfin1t3_r1che5_3re_y0ur5_1t_s33m5}`
