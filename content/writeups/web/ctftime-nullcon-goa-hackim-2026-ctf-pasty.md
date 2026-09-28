---
title: "Pasty - Nullcon Goa HackIM 2026 CTF"
category: "web"
type: "writeup"
tags: ["web", "pasty", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40640"
  url: "https://ctftime.org/writeup/40640"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Pasty/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Pasty"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Pasty
- **Author team:** RootRunners
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40640>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Pasty/README.md>

---
# Pasty

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Web   
**Points:** 50   
**Service:** `52.59.124.14:5005` 

## Overview  
The service signs paste IDs with a custom construction built from SHA-256. The signature is linear in three secret 8-byte blocks derived from the key, so we can recover those blocks from a few valid signatures and forge a signature for `id=flag`.

## Vulnerability  
The signature uses:  
\- `h = SHA256(id)`  
\- `m = SHA256(key)[:24]` split into three 8-byte blocks  
\- Each output block is a linear combination of `h` blocks and one of the three secret blocks

This linearity allows recovering all three secret blocks from a small number of signatures.

## Solution  
1\. Create a few random pastes to get `(id, sig)` pairs.  
2\. Compute `SHA256(id)` and derive the corresponding secret block used at each position.  
3\. Once all three blocks are recovered, rebuild the signature for `id=flag`.  
4\. Request `view.php?id=flag&sig=<forged>`.

## Exploit Script  
```python  
#!/usr/bin/env python3  
import hashlib  
import http.client  
import urllib.parse  
import re

HOST = "52.59.124.14"  
PORT = 5005

pat = re.compile(r"view\\.php\?id=([^&]+)&sig=([0-9a-f]+)")

def sha256(data: bytes) -> bytes:  
return hashlib.sha256(data).digest()

def compute_c_parts(data: bytes, sig_hex: str):  
h = sha256(data)  
o = bytes.fromhex(sig_hex)  
parts = []  
for i in range(4):  
s = i * 8  
b = h[s : s + 8]  
if i == 0:  
c = bytes([o[j] ^ b[j] for j in range(8)])  
else:  
prev = o[s - 8 : s]  
c = bytes([o[s + j] ^ b[j] ^ prev[j] for j in range(8)])  
sel = h[s] % 3  
parts.append((sel, c))  
return parts

def get_pair():  
conn = http.client.HTTPConnection(HOST, PORT, timeout=5)  
params = urllib.parse.urlencode({"content": "hi"})  
headers = {"Content-Type": "application/x-www-form-urlencoded"}  
conn.request("POST", "/create.php", params, headers)  
resp = conn.getresponse()  
loc = resp.getheader("Location", "")  
conn.close()  
q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)  
url = q.get("url", [None])[0]  
if not url:  
return None  
url = urllib.parse.unquote(url)  
m = pat.search(url)  
if not m:  
return None  
return m.group(1), m.group(2)

def build_sig(m_parts, data: bytes):  
h = sha256(data)  
out = b""  
for i in range(4):  
s = i * 8  
b = h[s : s + 8]  
sel = h[s] % 3  
c = m_parts[sel]  
if i == 0:  
out += bytes([b[j] ^ c[j] for j in range(8)])  
else:  
prev = out[s - 8 : s]  
out += bytes([b[j] ^ c[j] ^ prev[j] for j in range(8)])  
return out.hex()

def main():  
m_parts = [None, None, None]  
# collect enough pairs to fill m_parts  
for _ in range(10):  
pair = get_pair()  
if not pair:  
continue  
pid, sig = pair  
parts = compute_c_parts(pid.encode(), sig)  
for sel, c in parts:  
if m_parts[sel] is None:  
m_parts[sel] = c  
if all(m_parts):  
break

if not all(m_parts):  
raise SystemExit("failed to recover all parts")

sig_flag = build_sig(m_parts, b"flag")  
print(f"http://{HOST}:{PORT}/view.php?id=flag&sig={sig_flag}")

if __name__ == "__main__":  
main()  
```

## Flag  
`ENO{cr3at1v3_cr7pt0_c0nstruct5_cr4sh_c4rd5}`
