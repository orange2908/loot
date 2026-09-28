---
title: "shiny-shells - DEF CON CTF Qualifier 2024"
category: "crypto"
subcategory: "pow"
type: "writeup"
tags: ["crypto", "gcd", "proof-of-work", "subprocess", "shiny-shells", "pow", "def-con-ctf-qualifier", "def-con-ctf-qualifier-2024", "2024", "ctf-writeup"]
summary: "1\\. decompile the challenge binary file, easy to understand, nothing to say"
source:
  name: "CTFtime writeup #39142"
  url: "https://ctftime.org/writeup/39142"
ctf:
  name: "DEF CON CTF Qualifier 2024"
  year: 2024
  challenge: "shiny-shells"
---

## Metadata

- **CTF:** DEF CON CTF Qualifier 2024
- **Task:** shiny-shells
- **Author team:** 5upernova
- **CTFtime tags:** crypto
- **CTFtime:** <https://ctftime.org/writeup/39142>

---
1\. decompile the challenge binary file, easy to understand, nothing to say

1\. In file [backdoor.py](http://backdoor.py) found that:

```  
ctxt = (pow(g, int.from_bytes(ptxt, 'big'), n_sq) * pow(r, n, n_sq)) % n_sq  
```

because of : 

```  
ctxt == (g ^ ptxt) * (r ^ n) mod n_sq  
=> ctxt^a == ((g ^ ptxt) * (r ^ n))^a mod n_sq  
=> ctxt^a == (g ^ ptxt)^a * (r ^ n)^a mod n_sq  
=> ctxt^a == (g ^ (ptxt*a)) * ((r ^a)^ n) mod n_sq  
```

lookat [backdoor.py](http://backdoor.py) :

```  
while True:  
r = random.randrange(1, n)  
if gcd(r, n) == 1:  
break  
```

when execute [backdoor.py](http://backdoor.py) without arguments, it will print the cipher result of 'ls' (ptxt)

So we need to find a payload instead of 'ls', and the payload : int(palyload) == int('ls') * n

because of:

```  
def run(msg: dict):  
ptxt = dec(msg['hash'], msg['ctxt'])  
subprocess.run(ptxt.split())  
```

we use the follow script to find out payload and n:

```  
from Crypto.Util.number import long_to_bytes, bytes_to_long

ls = bytes_to_long(b'ls')

# char in bytes.split() is seperator  
TAB = b' \x09\x0a\x0b\x0c\x0d'

sh_b = b'sh'  
for i0 in TAB:  
for i1 in TAB:  
for i2 in TAB:  
for i3 in TAB:  
for i4 in TAB:  
for i5 in TAB:  
b = sh_b + bytes([i0, i1, i2, i3, i4, i5])  
a = bytes_to_long(b)%ls  
if a==0:  
n = bytes_to_long(b)//ls  
print(n, b)  
break

# b = ls * n  
```

After run it, we got payload: b'sh\t \x0c\t\r ', and n = 299531993847392

Finally, write the full exploit:

```  
#!/usr/bin/env python3  
import json

from pwn import *

HOST = os.environ.get('HOST', 'localhost')  
PORT = 31337

io = remote(HOST, int(PORT))

# GET THE 'ls' cipher result  
io.recvuntil(b'> ')  
io.sendline(b'5')  
ret = io.recvuntil(b'Welcome to Shiny Shell Hut!')  
idx = ret.index(b'{"hash":')  
end = ret.index(b'}', idx + 1)  
msg = ret[idx:end+1]  
msg = json.loads(msg)

ctxt = msg["ctxt"]  
n = msg["n"]

# MAKE new payload  
payload = b'sh\t \x0c\t\r '  
h = int(hashlib.sha256(payload).hexdigest(), 16)  
ctxt = pow(ctxt, 299531993847392, n*n)  
msg = {'hash': h, 'ctxt': ctxt, 'n': n}  
io.sendline(b'4'+json.dumps(msg).encode())  
io.interactive()  
```
