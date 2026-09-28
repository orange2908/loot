---
title: "cube cipher - BuckeyeCTF 2025"
category: "crypto"
type: "writeup"
tags: ["crypto", "cube", "cipher", "buckeyectf", "buckeyectf-2025", "2025", "ctf-writeup"]
summary: "import socket,ssl,re,sys,time"
source:
  name: "CTFtime writeup #40498"
  url: "https://ctftime.org/writeup/40498"
original_source: "https://rxx2me.github.io/posts/cube-cipher/"
ctf:
  name: "BuckeyeCTF 2025"
  year: 2025
  challenge: "cube cipher"
---

## Metadata

- **CTF:** BuckeyeCTF 2025
- **Task:** cube cipher
- **Author team:** W4llz
- **CTFtime:** <https://ctftime.org/writeup/40498>
- **Original writeup:** <https://rxx2me.github.io/posts/cube-cipher/>

---
\---

## Solver

```python  
#!/usr/bin/env python3  
import socket,ssl,re,sys,time  
HEX=re.compile(rb"[0-9a-f]{54}",re.I)  
def recv_until(s,token=b"Option:",t=20.0):  
s.settimeout(t);b=bytearray()  
while token not in b:  
c=s.recv(4096)  
if not c:break  
b+=c  
return bytes(b)  
def sendline(s,x): s.sendall((x+"\n").encode())

ctx=ssl.create_default_context()  
host="[cube-cipher.challs.pwnoh.io](http://cube-cipher.challs.pwnoh.io)";port=1337  
with socket.create_connection((host,port)) as tcp, ctx.wrap_socket(tcp,server_hostname=host) as s:  
recv_until(s)   
sendline(s,"3")   
data=recv_until(s)  
m=HEX.search(data)  
if not m: sys.exit("no hex found after option 3")  
c0=m.group(0).decode(); prev=c0  
for i in range(1,3000):  
sendline(s,"4"); recv_until(s)  
sendline(s,"3"); data=recv_until(s)  
m=HEX.search(data)  
if not m: continue  
ci=m.group(0).decode()  
if ci==c0:  
flag=bytes.fromhex(prev).rstrip(b"\\\x00")  
try: print(flag.decode())  
except: print(flag)  
break  
prev=ci

```

**Output:**  
```  
FLAG: bctf{r0t4t10n_0f_th3_cub3}  
```
