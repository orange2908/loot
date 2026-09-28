---
title: "Key in a Haystack - UIUCTF 2024"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "unexpected", "aes", "gcd", "ecb", "proof-of-work", "base64", "uiuctf", "uiuctf-2024", "2024", "ctf-writeup"]
summary: "from Crypto.Util.Padding import unpad"
source:
  name: "CTFtime writeup #39294"
  url: "https://ctftime.org/writeup/39294"
ctf:
  name: "UIUCTF 2024"
  year: 2024
  challenge: "Key in a Haystack"
---

## Metadata

- **CTF:** UIUCTF 2024
- **Task:** Key in a Haystack
- **Author team:** 5upernova
- **CTFtime tags:** unexpected, solution
- **CTFtime:** <https://ctftime.org/writeup/39294>

---
```  
#!/usr/bin/env python3  
# TEMPLATE-NAME: EMPTY  
from Crypto.Util.Padding import unpad  
from Crypto.Cipher import AES  
from hashlib import md5  
import gmpy2  
from pwn import connect, context  
import base64

context.log_level = "warn"

# == POW ==  
VERSION = 's'  
MODULUS = 2 ** 1279 - 1

def sloth_root(x, diff, p):  
exponent = (p + 1) // 4  
for i in range(diff):  
x = gmpy2.powmod(x, exponent, p).bit_flip(0)  
return int(x)

def sloth_square(x, diff, p):  
y = gmpy2.mpz(y)  
for i in range(diff):  
y = gmpy2.powmod(y.bit_flip(0), 2, p)  
return int(y)

def encode_number(num):  
size = (num.bit_length() // 24) * 3 + 3  
return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')

def decode_number(enc):  
return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')

def decode_challenge(enc):  
dec = enc.split('.')  
if dec[0] != VERSION:  
raise Exception('Unknown challenge version')  
return list(map(decode_number, dec[1:]))

def encode_challenge(arr):  
return '.'.join([VERSION] + list(map(encode_number, arr)))

# == POW END==

def solve_challenge(chal):  
[diff, x] = decode_challenge(chal)  
y = sloth_root(x, diff, MODULUS)  
return encode_challenge([y])

def decrypt(p, enc_flag):  
return AES.new(  
key=md5(b"%d" % p).digest(),  
mode=AES.MODE_ECB  
).decrypt(enc_flag)

def get_serv():  
while True:  
try:  
nc = connect("[key-in-a-haystack.chal.uiuc.tf](http://key-in-a-haystack.chal.uiuc.tf)", 1337, ssl=True)

nc.recvuntil(b' python3 <(curl -sSL https://goo.gle/kctf-pow) solve ')  
pow_val = nc.recvline().strip()  
sol = solve_challenge(pow_val.decode())  
#print(sol)  
nc.recvuntil(b'Solution? ')  
nc.sendline(sol.encode())  
assert nc.recvuntil(b'Correct\n')  
l0 = nc.recvline().strip().split()[1]  
l1 = nc.recvline(timeout=5)  
assert l1.endswith(b'\n')  
l1 = l1.strip().split()[1]  
enc_flag = bytes.fromhex(l0.decode())  
haystack = int(l1)  
try:  
nc.close()  
except:  
pass  
return enc_flag, haystack  
except:  
print("retry...")

enc_flag, haystack = get_serv()  
print("enc_flag =", enc_flag.hex())  
print("haystack.bit_length() =", haystack.bit_length())

while True:  
enc_flag_t, haystack_t = get_serv()  
print("...")  
d = gmpy2.gcd(haystack_t, haystack)  
if d == 1:  
continue  
print("d =", d, d.bit_length() % 1024)  
haystack //= d  
BL = haystack.bit_length()  
print("haystack.bit_length() =", BL)  
if BL < 100:  
break

flag = decrypt(haystack, enc_flag)  
print(haystack)  
print(flag)  
print(unpad(flag, 16))

```
