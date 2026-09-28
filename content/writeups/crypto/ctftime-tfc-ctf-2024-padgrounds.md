---
title: "PADGROUNDS - TFC CTF 2024"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "base64", "padgrounds", "tfc-ctf", "tfc-ctf-2024", "2024", "ctf-writeup"]
summary: "from Crypto.Util.number import"
source:
  name: "CTFtime writeup #39441"
  url: "https://ctftime.org/writeup/39441"
ctf:
  name: "TFC CTF 2024"
  year: 2024
  challenge: "PADGROUNDS"
---

## Metadata

- **CTF:** TFC CTF 2024
- **Task:** PADGROUNDS
- **Author team:** RedHazzarTeam
- **CTFtime:** <https://ctftime.org/writeup/39441>

---
```  
#!/usr/bin/env python3

from Crypto.Util.number import *  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import unpad,pad  
import os  
import base64  
import random  
import socket

#FLAG regex is TFCCTF{[bdefgmnprsu012345_]+}

def server_unpad(ct,conn):  
conn.send(ct.encode() + b'\n')  
r = conn.recv(4096).strip()  
return r

def my_unpad(ct,conn):  
global req  
ress = 0  
for i in range(30):  
if (server_unpad(ct,conn) == b'True'):  
ress +=1  
if (ress > 15):  
return True

def decryption(iv, ct, conn):  
alph = b'bdefgmnprsu012345_TFC{+}'  
fl = b''  
for _ in range(16):  
for i in alph:  
#print(i)  
x = b''  
x += bytes(a^(len(fl)+1) for a in (long_to_bytes(i)+fl))  
ivmask = b'\x00'*(16-1-len(fl))+x  
iv2 = bytes(a ^ b for a,b in zip(iv,ivmask))  
give2 = base64.b64encode(iv2 + ct).decode()  
if (my_unpad(give2,conn) == True):  
fl = long_to_bytes(i) + fl  
print('flag',fl)  
break  
return fl

if __name__ == '__main__':  
with socket.create_connection(('[challs.tfcctf.com](http://challs.tfcctf.com)', 31009)) as conn:  
res = b''  
res += conn.recv(4096)  
line, _, _ = res.split(b'\n')  
print(res)  
give = line.replace(b'Lets see you decode this: ', b'').strip()  
print(give)

try:  
ct = base64.b64decode(give)  
for p in range(0,3): #change 0 to 1,2 to find next parts of the key  
print(ct[p*16:(p+1)*16], ct[(p+1)*16:(p+2)*16])  
decryption(ct[p*16:(p+1)*16], ct[(p+1)*16:(p+2)*16],conn)  
except:  
print(Exception)  
```
