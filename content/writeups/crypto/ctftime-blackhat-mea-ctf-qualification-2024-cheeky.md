---
title: "Cheeky - BlackHat MEA CTF Qualification 2024"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "cryptography", "aes", "aes-ctr", "ctr", "xor", "one-time-pad", "blackhat-mea-ctf-qualification", "blackhat-mea-ctf-qualification-202", "2024", "ctf-writeup"]
summary: "Difficulty: Medium - 180pts"
source:
  name: "CTFtime writeup #39411"
  url: "https://ctftime.org/writeup/39411"
original_source: "https://medium.com/@irenavk/black-hat-mea-ctf-2024-quals-crypto-writeups-26f341a971b6"
ctf:
  name: "BlackHat MEA CTF Qualification 2024"
  year: 2024
  challenge: "Cheeky"
---

## Metadata

- **CTF:** BlackHat MEA CTF Qualification 2024
- **Task:** Cheeky
- **Author team:** V3n0m.py
- **CTFtime tags:** cryptography, aes, aes-ctr
- **CTFtime:** <https://ctftime.org/writeup/39411>
- **Original writeup:** <https://medium.com/@irenavk/black-hat-mea-ctf-2024-quals-crypto-writeups-26f341a971b6>

---
# Cheeky  
**Category:** Crypto

**Difficulty:** Medium — 180pts

**Description:** Just a cheeky lil’ challenge for you, that’s all ~ !

The code makes a database system that takes in some bytes, i.e. a “file”, encrypts it, then stores it. It then allows the user to interact with it through inserting bytes to a file, or deleting bytes from a file, and returning the encrypted bytes.  
```python  
class Database:  
def __init__(self, passkey: bytes):  
if isinstance(passkey, str):  
passkey = passkey.encode()  
self.key = sha256(b"::".join([b"KEY(_FLAG)", passkey, len(passkey).to_bytes(2, 'big')])).digest()  
self.uiv = int(sha256(b"::".join([b"UIV(_KEY)", self.key, len(self.key).to_bytes(2, 'big')])).hexdigest()[:24], 16)  
self.edb = {}  
```  
The database class uses the flag as the encryption key, and initialized a nonce/IV with the key as well.  
```python  
def _GetUIV(self, f: str, l: int, t: int = 0) -> bytes:  
if not (0 < t < int(time.time())):  
t = int(time.time()); time.sleep(2)  
u = (self.uiv + t).to_bytes(12, 'big')  
v = sha256(b"::".join([b"UIV(_FILE)", f.encode(), l.to_bytes(2, 'big')])).digest()  
return t, bytes([i^j for i,j in zip(u, v)])  
```  
A utility function used when encrypting/decrypting calculates a nonce/IV based on 1. time, 2. the initial IV, 3. the length and name of the file.  
```python  
def _Encrypt(self, f: str, x: bytes) -> bytes:  
if isinstance(x, str):  
x = x.encode()  
t, uiv = self._GetUIV(f, len(x))  
aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)  
return t.to_bytes(4, 'big') + aes.encrypt(x)

def _Decrypt(self, f: str, x: bytes) -> bytes:  
t, x = int.from_bytes(x[:4], 'big'), x[4:]  
_, uiv = self._GetUIV(f, len(x), t=t)  
aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)  
return aes.decrypt(x)  
```  
Encryption and decryption using AES in CTR mode.  
```python  
def Insert(self, f, i, j):  
if isinstance(j, str):  
j = j.encode()  
if isinstance(j, int):  
j = j.to_bytes(-(-len(bin(j)[:2])//8), 'big')  
if f in self.edb:  
x = self._Decrypt(f, self.edb[f])  
else:  
x = b""  
y = x[:i] + j + x[i:]  
z = self._Encrypt(f, y)  
self.edb[f] = z  
return z

def Delete(self, f, i, j):  
if f not in self.edb:  
return b""  
x = self._Decrypt(f, self.edb[f])  
y = x[:i] + x[i+j:]  
z = self._Encrypt(f, y)  
self.edb[f] = z  
return z  
```  
The Insert function can update an existing “file”, or make a new “file” in the database, it adds certain bytes at a certain index, then returns the encrypted text.  
```python  
database = Database(FLAG)  
database.Insert('flag', 0, FLAG)

# Server loop  
TUI = "|\n| Menu:\n| [I]nsert\n| [D]elete\n| [Q]uit\n|"

while True:  
try:

print(TUI)  
choice = input("| > ").lower()

if choice == 'q':  
raise KeyboardInterrupt

elif choice == 'i':  
uin = json.loads(input("| > (JSON) "))  
assert uin.keys() == {'f', 'i', 'j'}  
ret = database.Insert(uin['f'], uin['i'], uin['j'])  
print("| '{}' updated to 0x{}".format(uin['f'], ret.hex()))

elif choice == 'd':  
uin = json.loads(input("| > (JSON) "))  
assert uin.keys() == {'f', 'i', 'j'}  
ret = database.Delete(uin['f'], uin['i'], uin['j'])  
print("| '{}' updated to 0x{}".format(uin['f'], ret.hex()))  
```  
The database is initialized and uses the flag as its key, then the flag is stored in it and we can interact with the server.

Now onto the solution:

AES in CTR mode works a bit like one time pad, the IV is encrypted with the key, then XOR’ed with a block of plaintext. It is then incremented, encrypted with the key, then XOR, and so on.  
![](<https://miro.medium.com/v2/resize:fit:1400/format:webp/0*Kj62sVvAtOfW6uIk.png>)

This means that each block is independent of the first block, and if we use the same key and IV, the keystream will be the same.

We know that the IV is dependent on two things, time, and file length. First let’s interact with the server to find the length of the flag, (we can send a delete block that doesn’t delete anything to get the encrypted flag):  
![](<https://miro.medium.com/v2/resize:fit:1100/format:webp/1*Vezfiw6Xqg3ywarOd7hVng.png>)

We know from the code that the time of the IV generation is the first 4 bytes, so the flag is 41 bytes long.

Since IV is dependent on time, if we open two connections, on the first, delete the flag. Then at asynchronously, the first connection will insert 41 bytes, and the second will retrieve the flag using a bogus delete. Both texts will be encrypted with the same keystream, which we can retrieve since we know the first plain text.

```python  
# LOCAL SOLVER

import threading  
from pwn import process, context

context.log_level = 'info'   
challenge_script = './[challenge.py](http://challenge.py)'

# Event to synchronize the threads  
delete_event = threading.Event()

def handle_insert():  
try:  
# Start the local challenge script  
conn = process([challenge_script])  
print("[+] Insert connection established")

# Wait for the menu to be displayed  
conn.recvuntil(b'| > ')

# First, send the Delete option and JSON data  
conn.sendline(b'd')  
conn.sendline(b'{"f":"flag", "i":0, "j":41}')

# Signal the other delete thread to run  
delete_event.set()

# Continue with the Insert operation  
conn.recvuntil(b'| > ') # Wait for menu to reappear  
conn.sendline(b'i')  
conn.sendline(b'{"f":"flag", "i":0, "j":"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}')

# Print all output  
response = conn.recvall(timeout=5)  
print(f"[Insert Connection Output]:\n{response.decode()}")

# Close the connection  
conn.close()  
except Exception as e:  
print(f"Error in handle_insert: {e}")

def handle_delete():  
try:  
# Wait for the insert thread to initiate delete  
delete_event.wait()

# Start the local challenge script  
conn = process([challenge_script])  
print("[+] Delete connection established")

# Wait for the menu to be displayed  
conn.recvuntil(b'| > ')

# Send the Delete option and JSON data  
conn.sendline(b'd')  
conn.sendline(b'{"f":"flag", "i":57, "j":57}')

# Print all output  
response = conn.recvall(timeout=5)  
print(f"[Delete Connection Output]:\n{response.decode()}")

# Close the connection  
conn.close()  
except Exception as e:  
print(f"Error in handle_delete: {e}")

if __name__ == "__main__":  
# Create threads for both insert and delete operations  
insert_thread = threading.Thread(target=handle_insert)  
delete_thread = threading.Thread(target=handle_delete)

# Start both threads  
insert_thread.start()  
delete_thread.start()

# Wait for both threads to complete  
insert_thread.join()  
delete_thread.join()

print("[+] Both operations completed.")  
```  
This will result in two ciphertexts, use them in the below code to get the keystream and decrypt.  
```python  
import sys  
from pwn import xor

ct1 = bytes.fromhex("...") # Fill from script output  
t1, x1 = int.from_bytes(ct1[:4], 'big'), ct1[4:]  
ct2 = bytes.fromhex("...") # Fill from script output  
t2, x2 = int.from_bytes(ct2[:4], 'big'), ct2[4:]

a = b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

if t1 != t2:  
print("Different t, rerun script")  
sys.exit()

key = xor(x1, a)  
flag = xor(x2, key)

print(flag)  
```
