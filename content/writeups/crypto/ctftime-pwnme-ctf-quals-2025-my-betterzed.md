---
title: "My BetterZED - PwnMe CTF Quals 2025"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["aes", "crypto", "iv", "ecb", "cbc", "xor", "flask", "render-template", "pwnme-ctf-quals", "pwnme-ctf-quals-2025", "2025", "ctf-writeup"]
summary: "\\- When requesting the flag, the key doesn't change, only the IV does."
source:
  name: "CTFtime writeup #40067"
  url: "https://ctftime.org/writeup/40067"
original_source: "https://wepfen.github.io/writeups/easy_diffy_my_zed_my_betterzed/#my-betterzed"
ctf:
  name: "PwnMe CTF Quals 2025"
  year: 2025
  challenge: "My BetterZED"
---

## Metadata

- **CTF:** PwnMe CTF Quals 2025
- **Task:** My BetterZED
- **Author team:** the rizzlers
- **CTFtime tags:** aes, crypto, iv
- **CTFtime:** <https://ctftime.org/writeup/40067>
- **Original writeup:** <https://wepfen.github.io/writeups/easy_diffy_my_zed_my_betterzed/#my-betterzed>

---
> Difficulty : Easy

> [Source files](<https://github.com/Phreaks-2600/PwnMeCTF-2025-quals/raw/refs/heads/main/Crypto/My_better_Zed/attachments/my_betterzed.zip>)

> Description : Patched OpenZed an made it more secure.

> Author : wepfen (still me)

## TL;DR

\- When requesting the flag, the key doesn't change, only the IV does.

\- Notice that the flag has a length of 16 bytes, and so, is encrypted with AES CFB. The IV is encrypted and then xored with the flag.

\- Request a flag a keep the IV, send 16 bytes with the same IV used for the flag and encrypt it. Compares the resulting ciphertext with the encrypted flag.

\- Or, send 16 null bytes with the same IV, resulting in the IV encrypted and xor it with the encrypted flag.

## Introduction

This challenge is as My ZED but with some patches and with a web interface.  
On the web interface, we can choose to :

\- request an encrypted flag

\- encrypt a file and submit optional username, password and IV

\- decrypt a file by giving username and password

I will just focus on the edited parts since I already explained My ZED.

## Code analysis

There is the file running the web application :

```python  
import os  
import io  
import string

from flask import Flask, render_template, send_file, request  
from openzedlib import openzed

app = Flask(__name__,   
template_folder="./web/templates",  
static_folder="./web/static")  
  
FLAG = os.getenv("FLAG", "PWNME{flag_test}")  
KEY = os.urandom(16)  
USER = b"pwnme"

assert len(FLAG) <= 16

@app.route('/', methods=['GET'])  
def home():  
return render_template('index.html')

@app.route('/encrypt_flag/', methods=['GET'])  
def encrypt_flag():  
#chiffrer avec des creds random

file = openzed.Openzed(USER, KEY, 'flag.txt.ozed')  
file.encrypt(FLAG.encode())  
file.generate_container()

#tricking flask into thinking the data come from a file  
encrypted = io.BytesIO(file.secure_container)

return send_file(  
encrypted,  
mimetype='text/plain',  
as_attachment=False,  
download_name='flag.txt.ozed'  
)

@app.route('/encrypt/', methods=['POST'])  
def encrypt_file():  
  
if request.form["username"] and request.form["password"]:  
username = request.form["username"].encode()  
password = bytes.fromhex(request.form["password"])  
else:  
username = USER  
password = KEY

if request.form["iv"] :  
try :   
iv = request.form["iv"]  
except:  
return "Please submit iv hex encoded"  
else:  
iv = None

if not request.files or not request.files["file"].filename:  
return "Please upload a file"  


filename = request.files["file"].filename  
file_to_encrypt = request.files['file']

data = file_to_encrypt.stream.read()

file = openzed.Openzed(username, password, filename, iv)  
file.encrypt(data)  
file.generate_container()

encrypted = io.BytesIO(file.secure_container)

return send_file(  
encrypted,  
mimetype='text/plain',  
as_attachment=False,  
download_name=filename+".ozed"  
)

@app.route('/decrypt/', methods=['POST'])  
def decrypt_file():

if not request.form["username"] :  
return "Please submit an username"

if not request.form["password"]:  
return "Please submit a password"

try :   
bytes.fromhex(request.form["password"])  
except:  
return "Please submit the password hex encoded"

if not request.files or not request.files["file"].filename:  
return "Please upload a file"  
  
username = request.form["username"].encode()  
password = bytes.fromhex(request.form["password"])

filename = request.files["file"].filename  
file_to_decrypt = request.files['file']  
data = file_to_decrypt.stream.read()  
  
file = openzed.Openzed(username, password, filename)  
file.secure_container = data  
  
decrypted = file.decrypt_container(file.secure_container)  
decrypted = io.BytesIO(decrypted["data"])

return send_file(  
decrypted,  
mimetype='text/plain',  
as_attachment=False,  
download_name=filename+".dec"  
)

# 10 MB = 2**20 * 10  
if __name__ == "__main__":  
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  
app.run(debug=False, host='0.0.0.0', port=5000)  
```

I removed the size value from the metadata in `[openzed.py](http://openzed.py)` and added the future to submit an IV at the creation of the instance. If no IV is submitted, then a random one will be chosen.

```python  
def generate_iv(self, iv):  
if iv == None:  
self.iv = os.urandom(16)  
return  
  
try:

iv = bytes.fromhex(iv)  
if len(iv) != 16:  
raise ValueError("IV should have a length of 16")  
self.iv = iv

except Exception as e:  
raise e  
```

I also removed the size value from the metadata and edited the `derive_password` function from `[aes_cbc_zed.py](http://aes_cbc_zed.py)` :

```python  
class AES_CBC_ZED:  
def __init__(  
self,   
user : str,   
password : str,   
iv : bytes  
):  
self.user = user  
self.iv = iv  
self.password = password  
self.derive_password()

[ ... ]

def derive_password(self):  
salt = b"LESELFRANCAIS!!!"  
self.key = PBKDF2(self.password, salt, 16, count=10000, hmac_hash_module=SHA256)

```

### Web interface endpoints

Reading [app.py](http://app.py) :

```python  
FLAG = os.getenv("FLAG", "PWNME{flag_test}")  
KEY = os.urandom(16)  
USER = b"pwnme"

assert len(FLAG) <= 16  
```

We can understand that the key is defined once, so when requesting the flag multiple times, the same key will be used until we deploy another instance. Also, the user is "pwnme".

Requesting `/encrypt_flag/`, we get the flag encrypted with the key generated at the start : 

```python  
@app.route('/encrypt_flag/', methods=['GET'])  
def encrypt_flag():  
#chiffrer avec des creds random

file = openzed.Openzed(USER, KEY, 'flag.txt.ozed')  
file.encrypt(FLAG.encode())  
file.generate_container()

return send_file(encrypted, mimetype='text/plain', as_attachment=False, download_name='flag.txt.ozed')  
```

Looking at `/encrypt/` : 

```python  
@app.route('/encrypt/', methods=['POST'])  
def encrypt_file():  
  
if request.form["username"] and request.form["password"]:  
username = request.form["username"].encode()  
password = bytes.fromhex(request.form["password"])  
else:  
username = USER  
password = KEY  
```

If one submit an user and a password, the file will be encrypted with it.  
Else, the user and the key defined at the start of the instance will be used.

And after that, the file will be encrypted and returned to us.

Finally, looking at `/decrypt/` :

```python  
@app.route('/decrypt/', methods=['POST'])  
def decrypt_file():

if not request.form["username"] :  
return "Please submit an username"

if not request.form["password"]:  
return "Please submit a password"

try :   
bytes.fromhex(request.form["password"])  
except:  
return "Please submit the password hex encoded"

if not request.files or not request.files["file"].filename:  
return "Please upload a file"  
```

We must submit an username and a password but not an IV because the IV is supposed to already be inside the ciphertext.

```python  
  
filename = request.files["file"].filename  
file_to_decrypt = request.files['file']  
data = file_to_decrypt.stream.read()  
  
file = openzed.Openzed(username, password, filename)  
file.secure_container = data  
  
decrypted = file.decrypt_container(file.secure_container)  
decrypted = io.BytesIO(decrypted["data"])

return send_file(decrypted, mimetype='text/plain', as_attachment=False, download_name=filename+".dec")  
```  
Then, it is decrypted with the submitted parameter and returned to us.

### Where's the vulnerability ?

The previous vulnerability from **My Zed** is not relevant because the password is derived differently and the : 

```python  
def derive_password(self):  
salt = b"LESELFRANCAIS!!!"  
self.key = PBKDF2(self.password, salt, 16, count=10000, hmac_hash_module=SHA256  
```

So let's look deeper at the process of encrypting and decrypting.

To get **decrypted/encrypted**, a call to encrypt() or decrypt() have to be made to an openzed object :

```python  
def encrypt(self, data):  
  
cipher = AES_CBC_ZED(self.user, self.password, self.iv)  
self.encrypted = cipher.encrypt(data)  
self.encrypted = zlib.compress(self.encrypted) # just for the lore 

return self.encrypted

def decrypt(self, ciphertext):

cipher = AES_CBC_ZED(self.user, self.password, self.iv)  
ciphertext = zlib.decompress(ciphertext)  
self.decrypted = cipher.decrypt(ciphertext)  
  
return self.decrypted  
```

Which call an underlying function **decrypt/encrypt** from AES_CBC_ZED object. Let's look at the encrypt function :

```python  
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

return ciphertext  
```

In shorts, if the plaintext as a length of more than 16 : 

![aes cbc zed encrypt](<https://wepfen.github.io/images/writeups/pwnme/aes_cbc_zed_encrypt.jpg>)

The first blocks are encrypted with AES CBC and the last with AES CFB.

But when the plaintext has a length below or equal to 16 :

![aes cbc zed encrypt](<https://wepfen.github.io/images/writeups/pwnme/aes_cbc_zed_encrypt_2.jpg>)

The plaintext is encrypted with AES CFB.

With `decrypt()`, the process is reproduced but in reverse.

Fast forward, remember the flag has a length of 16 in [app.py:18](http://app.py:18) : `assert len(FLAG) <= 16`.

So it is encrypted with the CFB part which is :

\- encrypt the IV with the KEY (the key never change)  
\- xor it with the plaintext

There are two ways to recover the flag :

1\.   
\- Send a file of length 16 with only null bytes  
\- The result will be the encrypted IV xored with null bytes, so still the IV   
\- Then now we got the encrypted IV, we can XOR it with the encrypted flag and get the flag

2\.   
\- Send 256 files with 16 bytes of value `int.from_bytes(i)` with i from 0 to 255  
\- Send the data one after another with the same IV as the flag  
\- See if in the result there are the same byte at the same position on the encrypted file and the encrypted flag  
\- recover the flag

![betterzed second solution](<https://wepfen.github.io/images/writeups/pwnme/aes_cbc_zed_encrypt_2.jpg>)

## Solving 

Here's a script for the second solution (2 seconds to solve) :

```python  
from openzedlib import openzed  
from tqdm import tqdm

import requests  
import re  
import io  
import zlib

URL = "http://127.0.0.1:5000/"

# request the encrypt file and get the filename

flag_enc = requests.get(URL+"encrypt_flag/")  
d = flag_enc.headers['content-disposition']  
filename = re.findall("filename=(.+)", d)[0]

# create a openzed object with an user with same length as in the ciphertext, any password,   
# any iv as in the ciphertext and the filename we recovered before

flag_enc_openzed = openzed.Openzed(b"pwnme", b"idk", filename)

# load the flag ciphertext and read it's metadata to get the correct values and recover the IV  
# We can also recover the IV manually by reading flag_enc

flag_enc_openzed.secure_container = flag_enc.content  
flag_enc_openzed.read_metadata()

iv = flag_enc_openzed.parsed_metadata["iv"]

# Now we can start to craft a payload  
# We will encrypt it through /encrypt_file endpoint

flag_ciphertext = flag_enc_openzed.secure_container[304:]  
flag = [0] * 16

# trick requests into thinking file.content come from a file by using io.BytesIO  
# empty password and username so the oracle KEY and USER get used

for i in tqdm(range(255)):  
payload = [i] * 16

r = [requests.post](http://requests.post)(URL+"/encrypt/", files={'file': ('file.txt', io.BytesIO(bytearray(payload)))}, data = {"iv" : iv, "username":"", "password":""})

tmp_ozed = openzed.Openzed(b"pwnme", b"idk", filename, iv)  
tmp_ozed.secure_container = r.content

# the ciphertext is compressed, openzed.py.openzed.encrypt  
my_ct = zlib.decompress(tmp_ozed.secure_container[304:])  
flag_ct = zlib.decompress(flag_ciphertext)

for counter, tupl in enumerate(zip(my_ct, flag_ct)):  
if tupl[0] == tupl[1]:  
flag[counter] = i  
print(bytes(flag))

print(bytes(flag))  
```

Flag : `PWNME{zEd_15_3z}`
