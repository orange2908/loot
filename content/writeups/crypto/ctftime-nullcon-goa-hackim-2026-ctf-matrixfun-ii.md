---
title: "Matrixfun II - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["crypto", "cry", "chinese-remainder", "proof-of-work", "base64", "matrixfun", "number-theory", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40653"
  url: "https://ctftime.org/writeup/40653"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Matrixfun_II/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Matrixfun II"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Matrixfun II
- **Author team:** RootRunners
- **CTFtime tags:** cry
- **CTFtime:** <https://ctftime.org/writeup/40653>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Crypto/Matrixfun_II/README.md>

---
# Matrixfun II

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Crypto   
**Points:** 50   
**Service:** `52.59.124.14:5101` 

## Overview  
The server encrypts base64 text with an affine transformation over `Z_65`:

```  
c = A * x + b (mod 65)  
```

The alphabet is a custom base64 set with 65 symbols (including `=`), and the plaintext is padded to 16-symbol blocks.

## Key Insight  
The encryption oracle lets us recover `b` and every column of `A`:  
\- Encrypting a block of 16 `'a'` (index 0) yields `b`.  
\- Replacing a single position with `'b'` (index 1) reveals the corresponding column of `A`.

Because `65 = 5 * 13`, we invert `A` modulo 5 and 13 and recombine with CRT.

## Solution  
1\. Send 17 chosen plaintext blocks to recover `b` and `A`.  
2\. Invert `A` modulo 5 and 13.  
3\. For each ciphertext block, solve `A * x = c - b` in both moduli and combine with CRT.  
4\. Rebuild the base64 string and decode it.

## Exploit Script  
```python  
#!/usr/bin/env python3  
import socket  
import base64

HOST = "52.59.124.14"  
PORT = 5101  
alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="  
MOD = len(alphabet)  
N = 16

def recv_until(sock, marker: bytes) -> bytes:  
data = b""  
while marker not in data:  
chunk = sock.recv(4096)  
if not chunk:  
break  
data += chunk  
return data

def modinv(a, p):  
return pow(a, p - 2, p)

def mat_inv_mod(A, p):  
n = len(A)  
M = [[a % p for a in row] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(A)]  
r = 0  
for c in range(n):  
pivot = None  
for i in range(r, n):  
if M[i][c] % p != 0:  
pivot = i  
break  
if pivot is None:  
continue  
M[r], M[pivot] = M[pivot], M[r]  
inv = modinv(M[r][c] % p, p)  
for j in range(2 * n):  
M[r][j] = (M[r][j] * inv) % p  
for i in range(n):  
if i == r:  
continue  
factor = M[i][c] % p  
if factor == 0:  
continue  
for j in range(2 * n):  
M[i][j] = (M[i][j] - factor * M[r][j]) % p  
r += 1  
return [row[n:] for row in M]

def mat_vec_mul(A, v, p):  
n = len(A)  
return [sum(A[i][j] * v[j] for j in range(n)) % p for i in range(n)]

def main():  
base_char = chr(alphabet[0])  
block0 = base_char * 16  
blocks = [block0]  
for i in range(N):  
blk = list(block0)  
blk[i] = chr(alphabet[1])  
blocks.append("".join(blk))  
msgs = [base64.b64decode(b) for b in blocks]

s = socket.create_connection((HOST, PORT), timeout=5)  
recv = recv_until(s, b"enter your message")  
first_line = recv.decode().split("\n")[0].strip()  
flag_cipher = list(map(int, first_line.strip("[]").split(",")))

ciphers = []  
for data in msgs:  
s.sendall(data.hex().encode() + b"\n")  
resp = recv_until(s, b"enter your message")  
line = resp.decode().split("\n")[0].strip()  
cipher = list(map(int, line.strip("[]").split(",")))  
ciphers.append(cipher)

bvec = ciphers[0][:N]  
A = [[0] * N for _ in range(N)]  
for col in range(N):  
c = ciphers[col + 1][:N]  
colvec = [(c[i] - bvec[i]) % MOD for i in range(N)]  
for row in range(N):  
A[row][col] = colvec[row]

A5 = [[x % 5 for x in row] for row in A]  
A13 = [[x % 13 for x in row] for row in A]  
A5_inv = mat_inv_mod(A5, 5)  
A13_inv = mat_inv_mod(A13, 13)

cipher = flag_cipher  
blocks_ct = [cipher[i : i + N] for i in range(0, len(cipher), N)]  
plain_idx = []

for blk in blocks_ct:  
y = [(blk[i] - bvec[i]) % MOD for i in range(N)]  
y5 = [v % 5 for v in y]  
y13 = [v % 13 for v in y]  
x5 = mat_vec_mul(A5_inv, y5, 5)  
x13 = mat_vec_mul(A13_inv, y13, 13)  
for i in range(N):  
x = None  
for v in range(65):  
if v % 5 == x5[i] and v % 13 == x13[i]:  
x = v  
break  
plain_idx.append(x)

b64 = "".join(chr(alphabet[i]) for i in plain_idx)  
b64 = b64.rstrip("=")  
b64 += "=" * ((-len(b64)) % 4)  
msg = base64.b64decode(b64)  
print(msg.decode(errors="ignore"))

s.sendall(b"exit\n")

if __name__ == "__main__":  
main()  
```

## Flag  
`ENO{l1ne4r_alg3br4_i5_ev3rywh3re}`
