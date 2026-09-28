---
title: "Rock my Password - SwampCTF 2025"
category: "crypto"
type: "writeup"
tags: ["crypto", "rock", "password", "swampctf", "swampctf-2025", "2025", "ctf-writeup"]
summary: "Before we start taking active steps on the task, let's figure out what and how."
source:
  name: "CTFtime writeup #40127"
  url: "https://ctftime.org/writeup/40127"
ctf:
  name: "SwampCTF 2025"
  year: 2025
  challenge: "Rock my Password"
---

## Metadata

- **CTF:** SwampCTF 2025
- **Task:** Rock my Password
- **Author team:** V4L1D4T0R
- **CTFtime:** <https://ctftime.org/writeup/40127>

---
# Solve  
Before we start taking active steps on the task, let's figure out what and how.  
It is noted that a certain password from "rockyou.txt", which is 10 characters long, was inserted into the "swampCTF{}" flag, and then the flag with the password was hashed. The hashing order is as follows: 100 times md5 -> 100 times sha256 -> 100 times sha512.  
Obviously, going through the hashes is incredibly long and impractical. Therefore, you can do the following: extract all 10-character passwords from "rockyou.txt", hash them in the order described above, and check whether the resulting hashes match the given hash "f600d59a5cdd245a45297079299f2fcd811a8c5461d979f09b73d21b11fbb4f899389e588745c6a9af13749eebbdc2e72336cc57ccf90953e6f9096996a58dcc".

Let's write the following code in Python:  
```  
import hashlib

def multihash(password):  
s = f"swampCTF{{{password}}}".encode('utf-8')  
# MD5 100 times  
for _ in range(100):  
md5 = hashlib.md5()  
md5.update(s)  
s = md5.digest()  
# SHA256 100 times  
for _ in range(100):  
sha256 = hashlib.sha256()  
sha256.update(s)  
s = sha256.digest()  
# SHA512 100 times  
for _ in range(100):  
sha512 = hashlib.sha512()  
sha512.update(s)  
s = sha512.digest()  
return s.hex()

target_hash = "f600d59a5cdd245a45297079299f2fcd811a8c5461d979f09b73d21b11fbb4f899389e588745c6a9af13749eebbdc2e72336cc57ccf90953e6f9096996a58dcc"

# we read rockyou.txt from current directory, take all passwords with length == 10, and then compute hash for each pass and compare with our target hash  
with open('rockyou.txt', 'r', errors='ignore') as f:  
for line in f:  
password = line.rstrip('\n') # Only remove the newline character  
if len(password) == 10:  
computed_hash = multihash(password)  
if computed_hash == target_hash:  
print(f"Found password: {password}")  
print(f"Flag: swampCTF{{{password}}}")  
exit()  
print("Password not found in the rockyou.txt dataset or there was an error...")  
```  
  


Code is simple enough.We loop through each password, and if it is 10 characters long, we call the function "multihash()" to calculate 300 hashes. If the computed hash is equals to target hash - that's our flag!  
```  
Found password: secretcode  
Flag: swampCTF{secretcode}  
```
