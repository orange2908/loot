---
title: "My Zed - PwnMe CTF Quals 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["aes", "crypto", "ecb", "cbc", "xor", "pwnme-ctf-quals", "pwnme-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "\\- Decompress ciphertext with zlib"
source:
  name: "CTFtime writeup #40066"
  url: "https://ctftime.org/writeup/40066"
original_source: "https://wepfen.github.io/writeups/easy_diffy_my_zed_my_betterzed/#my-zed"
ctf:
  name: "PwnMe CTF Quals 2025"
  year: 2025
  challenge: "My Zed"
---

## Metadata

- **CTF:** PwnMe CTF Quals 2025
- **Task:** My Zed
- **Author team:** the rizzlers
- **CTFtime tags:** aes, crypto
- **CTFtime:** <https://ctftime.org/writeup/40066>
- **Original writeup:** <https://wepfen.github.io/writeups/easy_diffy_my_zed_my_betterzed/#my-zed>

---
> Difficulty : Easy

> [Source files](<https://github.com/Phreaks-2600/PwnMeCTF-2025-quals/raw/refs/heads/main/Crypto/MyZed/attachments/my_zed.zip>)

> Description : Tried to make an opensource zedencrypt in 2 weeks but i got doubts about it ...

> Author : wepfen (me again)

## TL;DR

\- Decompress ciphertext with zlib

\- Get IV which is prepended to the cipertext

\- Intended way :  
1\. The IV is made of the concatenation of the username and the password, so it has a part of the password used to generate the key

2\. So we can get the 13 first characters of the password and we need to bruteforce the three lasts

3\. Decrypt the ciphertext

\- Unintended way :  
1\. Decode the hash in the metadata from hex

2\. Get the first 16 bytes and decrypt the ciphertext with it

## Introduction

For this challenge, we have got a custom lib that can encrypt files given an username, a password and a filename.

It then generate a ciphertext, prepend it by a magic bytes and the metadata in JSON format and write it to a file with "OZED" extension.

The plaintext is compressed with zlib before getting encrypted with AES-CBC-ZED, a mix of AES-CBC and AES-CFB.

>[ A paper from Camille Mougey at sstic 2024](<https://www.sstic.org/media/SSTIC2024/SSTIC-actes/zed-files__aux_frontires_du_rel/SSTIC2024-Article-zed-files__aux_frontires_du_rel-mougey_GIwCgVf.pdf>) gave me the idea of this challenge. We can find AES CBC ZED at section 2.5

## Code analysis

Here's the challenge script :

```python  
from openzedlib import openzed  
import os  
import zlib

from flag import FLAG

file = openzed.Openzed(b'zed', os.urandom(16), 'flag.txt', len(FLAG))

file.encrypt(FLAG)

file.generate_container()

with open(f"{file.filename}.ozed", "wb") as f:  
f.write(file.secure_container)  
```

Which relies on [openzed.py](http://openzed.py) :

```python  
from openzedlib.aes_cbc_zed import AES_CBC_ZED   
from hashlib import sha256

import json  
import zlib

class Openzed:

def __init__(self, user=b"user", password=b"OpenZEDdefaultpasswordtochangebeforedeployinproduction", filename="file", size=0):  
self.user = user  
self.password = password  
self.filename = filename  
self.size = size  
self.generate_metadata()

"""Metadata   
format : {"size": 0, "filename": "", "user": "", "password_hash": ""}+padding

(size = 300 bytes and formatted in json)  
  
header ("OZED") -> 4  
size -> 4  
filename -> 112  
user -> 32  
password_hash -> 64  
json size -> 60  
"""

def generate_metadata(self):  
  
metadata = {}  
metadata["user"] = self.user.decode()  
metadata["password_hash"] = sha256(self.password).hexdigest()  
metadata["filename"] = self.filename  
metadata["size"] = self.size

self.metadata = json.dumps(metadata).encode()

self.padding_len = 300-len(self.metadata)  
self.metadata += self.padding_len*b"\x00"  
  
return self.metadata  
  
def encrypt(self, data):  
  
cipher = AES_CBC_ZED(self.user, self.password)  
self.encrypted = cipher.encrypt(data)  
self.encrypted = zlib.compress(self.encrypted) # just for the lore  
  
return self.encrypted

def decrypt(self, ciphertext):

cipher = AES_CBC_ZED(self.user, self.password)  
ciphertext = zlib.decompress(ciphertext)  
self.decrypted = cipher.decrypt(ciphertext)  
  
return self.decrypted

def generate_container(self):  
self.secure_container = b'OZED' + self.metadata + self.encrypted  
return self.secure_container

def decrypt_container(self, container):

self.read_metadata()  
filename = self.parsed_metadata["filename"]  
  
ciphertext = container[304:]

plaintext = self.decrypt(ciphertext)  
return {"data":plaintext, "filename":filename}

def read_metadata(self):  
self.parsed_metadata = json.loads(self.secure_container[4:300-self.padding_len+4])  
return self.parsed_metadata  
```

Which relies on [aes_cbc_zed.py](http://aes_cbc_zed.py) :

```python  
from Crypto.Cipher import AES  
from hashlib import sha256

import os

def xor(a: bytes, b: bytes) -> bytes:  
return bytes(x^y for x,y in zip(a,b))

class AES_CBC_ZED:  
def __init__(self, user, password):  
self.user = user  
self.password = password  
self.derive_password()  
self.generate_iv()

def encrypt(self, plaintext: bytes):  
iv = self.iv  
ciphertext = b""  
ecb_cipher = AES.new(key=self.key, mode=AES.MODE_ECB)  
  
  
for pos in range(0, len(plaintext), 16):  
chunk = plaintext[pos:pos+16]  
  
# AES CFB for the last block or if there is only one block  
if len(plaintext[pos+16:pos+32]) == 0 :  
#if plaintext length <= 16, iv = self.iv  
if len(plaintext) <= 16 :  
prev=iv  
# else, iv = previous ciphertext  
else:  
prev=ciphertext[pos-16:pos]  
  
prev = ecb_cipher.encrypt(prev)  
ciphertext += xor(chunk, prev)  
  
# AES CBC for the n-1 firsts block  
elif not ciphertext:  
xored = bytes(xor(plaintext, iv))  
ciphertext += ecb_cipher.encrypt(xored)  
  
else:  
xored = bytes(xor(chunk, ciphertext[pos-16:pos]))  
ciphertext += ecb_cipher.encrypt(xored)

return iv + ciphertext

def decrypt(self, ciphertext: bytes):  
# TODO prendre un iv déjà connu en paramètre ?  
plaintext = b""  
ecb_cipher = AES.new(key=self.key, mode=AES.MODE_ECB)  
iv = ciphertext[:16]  
ciphertext = ciphertext[16:]  
  
for pos in range(0, len(ciphertext), 16):  
chunk = ciphertext[pos:pos+16]  
  
# AES CFB for the last block or if there is only one block  
if len(ciphertext[pos+16:pos+32]) == 0 :  
  
#if plaintext length <= 16, iv = self.iv  
if len(ciphertext) <= 16 :  
prev=iv  
# else, iv = previous ciphertext  
else:  
prev=ciphertext[pos-16:pos]

prev = ecb_cipher.encrypt(prev)  
plaintext += xor(prev, chunk)  
  
# AES CBC for the n-1 firsts block  
elif not plaintext:  
xored = ecb_cipher.decrypt(chunk)  
plaintext += bytes(xor(xored, iv))  
  
else:  
xored = ecb_cipher.decrypt(chunk)  
plaintext += bytes(xor(xored, ciphertext[pos-16:pos]))  
  
return plaintext  
  
  
def derive_password(self):  
for i in range(100):  
self.key = sha256(self.password).digest()[:16]

def generate_iv(self):  
self.iv = (self.user+self.password)[:16]  
```  
So, in `[challenge.py](http://challenge.py)`, a Openzed intance is created with the username `zed`, a random password and the filename "flag.txt".

`file = openzed.Openzed(b'zed', os.urandom(16), 'flag.txt', len(FLAG))`

It's encrypted with the method `encrypt()` and a generate the secure container.

Let's dig in the openzed object to see what happens here.

### Openzed 

First, the initialization of the class : 

```python  
class Openzed:

def __init__(self, user=b"user", password=b"OpenZEDdefaultpasswordtochangebeforedeployinproduction", filename="file", size=0):  
self.user = user  
self.password = password  
self.filename = filename  
self.size = size  
self.generate_metadata()  
```

The default variable values are unused because they are overwriten in [challenge.py](http://challenge.py).

A function is called, `generate_metadata()` :

```python  
def generate_metadata(self):  
  
metadata = {}  
metadata["user"] = self.user.decode()  
metadata["password_hash"] = sha256(self.password).hexdigest()  
metadata["filename"] = self.filename  
metadata["size"] = self.size

self.metadata = json.dumps(metadata).encode()

self.padding_len = 300-len(self.metadata)  
self.metadata += self.padding_len*b"\x00"  
  
return self.metadata  
```

Which put the username, the password hash in sha256, the filename and the size in a JSON and store it in `metadata` attribute.  
It adds padding at the end of it by substracting the length of the metadata with 300. **So the metadata length is maximum 300 characters**.

Now looking at the `encrypt()` function in openzed:

```python  
def encrypt(self, data):  
  
cipher = AES_CBC_ZED(self.user, self.password)  
self.encrypted = cipher.encrypt(data)  
self.encrypted = zlib.compress(self.encrypted) # just for the lore  
  
return self.encrypted  
```

It calls aes_cbc_zed python file, encrypt the data with the latter and compress the result with zlib (for the lore of the 'secure' **compressed** container).

Let's dive in `[aes_cbc_zed.py](http://aes_cbc_zed.py)`.

### AES CBC ZED

At initialization:

```python  
class AES_CBC_ZED:  
def __init__(self, user, password):  
self.user = user  
self.password = password  
self.derive_password()  
self.generate_iv()  
```

It sets the specified username and password, generate a key using `derive_password` and generate an iv.

Let's `derive_password()`

```python  
def derive_password(self):  
for i in range(100):  
self.key = sha256(self.password).digest()[:16]  
```

> Well, I badly messed up my code resulting in using the password hash as the key and having at the same time, the password hash in the metadata. Thanks to [nikloskoda](<https://x.com/nikloskoda>) who noticed that.

It was supposed to hashes the password 100 times in a row taking the 16 first bytes each times , and store the result in `self.key`.  
But i messed up, and actually it just hash the password one time.

It should have been that :

```python  
def derive_password(self):  
self.key = self.password  
for i in range(100):  
self.key = sha512(self.key).digest()[:16]  
```  
I use sha512 so that the player cannot recover the the key with the sha256 hash of the password in the metadata.

And what about `generate_iv()` :

```python  
def generate_iv(self):  
self.iv = (self.user+self.password)[:16]  
```  
Well, it leaks a pretty useful part of the password, we miss the last three characters, which allow us to bruteforce 256**3 == 16777216 possiblities (doable).  
And usually, the IV is supposed safe to share and is necessary to decrypt files, so it is given.

Reading `encrypt()`, we see that that the return value is `iv + ciphertext`.

```python  
def encrypt(self, plaintext: bytes):  
iv = self.iv  
ciphertext = b""  
ecb_cipher = AES.new(key=self.key, mode=AES.MODE_ECB)  
  
[ ... ]

return iv + ciphertext  
```  
And `decrypt()` function extract IV from the cipertext:

```python  
def decrypt(self, ciphertext: bytes):  
plaintext = b""  
ecb_cipher = AES.new(key=self.key, mode=AES.MODE_ECB)  
iv = ciphertext[:16]  
ciphertext = ciphertext[16:]

[ ... ]

return plaintext  
```

So, we can recover the part of the password from there and bruteforce the 3 last bytes. 

## Solving 

So knowing that, we can extract the ciphertext from the output file `flag.txt.ozed`.

Remember that the file is made of the 'OZED' magic byte followed by 300 bytes of metadata and then, the ciphertext which is composed of the IV followed by the ciphertext.

Then to get the IV we can read from the ozed file and get 16 bytes after 304 bytes:

```python  
container_file = open("flag.txt.ozed", "rb").read()  
ciphertext = zlib.decompress(container_file[304:])

iv = ciphertext[:16]  
```  
### Intended (by bruteforcing the 3 remaining bytes of the password)

We extracted the IV we can get the first 13 bytes of the password :

```python  
part_password = iv[3:16]  
```

Now we got two solutions:

\- naive : bruteforce the three lasts bytes of the password and try to decrypt each time until we find `PWNME` in the plaintext. (10 minutes to solve)  
\- less naive : bruteforce the three lasts bytes of the password, hash the candidates and compare it with password_hash in the metadata. (10 sec to solve). Doing that, we only derive the password (which take a lot of ressources), only if we know we got the correct password.

Try to guess which one I first implemented.

![clueless](<https://emoji.discadia.com/emojis/833e681b-504e-4746-9bbe-ad5c0bca8240.PNG>)

example of script :

```python  
#! /usr/bin/env python3

import zlib  
import itertools  
import hashlib  
import re  
import json

from tqdm import tqdm  
from openzedlib.aes_cbc_zed import AES_CBC_ZED 

container_file = open("flag.txt.ozed", "rb").read()  
ciphertext = zlib.decompress(container_file[304:])

# Manually read the ozed file and copy the json in the metadata

metadata = json.loads(re.search(b"{(?:[^{}])*}", container_file).group(0))  
password_hash = metadata["password_hash"]

# we got user = "zed" et part_password = iv[3:16]

def bruteforce_password(ciphertext):

iv = ciphertext[:16]  
ct = ciphertext[16:]

user = iv[:3]  
password = iv[3:16]  
  
cipher = AES_CBC_ZED(user, password)  
  
# get all bytes possibilities  
bytes_possibilities = list(itertools.product(range(256), repeat=3))  
  
for suffix in tqdm(bytes_possibilities):  
candidate_password = password+bytes(suffix)  
hashed = hashlib.sha256(candidate_password).hexdigest()

if hashed == password_hash:  
cipher.password = candidate_password  
cipher.derive_password()  
plaintext = cipher.decrypt(ciphertext)  
print(plaintext)  
break

if __name__ == "__main__":  
bruteforce_password(ciphertext) # about 10 sec to solve   
```

FLAG : `PWNME{49e531f28d1cedef03103af6cec79669_th4t_v3Ct0r_k1nd4_l3aky}`  
7  
### Unintended (using the hash)

For this one, we just have to decode the password hash from hex which is in the metadata, and take the first 16 bytes, and decrypt everything.

```python  
import zlib

from hashlib import sha256  
from openzedlib.aes_cbc_zed import AES_CBC_ZED

container_file = open("flag.txt.ozed", "rb").read()  
ciphertext = zlib.decompress(container_file[304:])

key = bytes.fromhex("b3a97eb583db5a940c0705e6450b81f4d702a9122d7342a25768e3d75be739be")[:16]

cipher = AES_CBC_ZED(b"", b"")  
cipher.key = key  
cipher.iv = ciphertext[:16]  
plaintext = cipher.decrypt(ciphertext)  
print(plaintext)  
```

And it works perfectly : `b'PWNME{49e531f28d1cedef03103af6cec79669_th4t_v3Ct0r_k1nd4_l3aky}'`
