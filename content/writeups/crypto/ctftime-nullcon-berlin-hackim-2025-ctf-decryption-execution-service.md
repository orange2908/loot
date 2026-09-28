---
title: "decryption execution service - Nullcon Berlin HackIM 2025 CTF"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "oracle", "aes", "padding-oracle", "cbc", "xor", "eval", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Challenge: decryption execution service"
source:
  name: "CTFtime writeup #40409"
  url: "https://ctftime.org/writeup/40409"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-09-05-decryption-execution-service-writeup"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "decryption execution service"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** decryption execution service
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** crypto, oracle
- **CTFtime:** <https://ctftime.org/writeup/40409>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-09-05-decryption-execution-service-writeup>

---
## decryption execution service - nullcon HackIM CTF Berlin 2025 Write-up 

![Banner](https://writeups.thebusfactoris1.online/assets/files/execser/image.png)

**Challenge:** decryption execution service   
**Category:** Crypto   
**Points:** 311   
**Author:** LTFZP 

\---

## A Glimpse of the Target

We’re presented with a service that behaves like a digital genie. It promises to execute any command we give it—but only if our command is wrapped in a properly encrypted format. 

Looking at the server’s Python code, we see it’s using **AES in CBC mode**. Any incorrectly formatted command is rejected with explicit error messages. Our task is to figure out how to craft a valid encrypted command so the genie grants our wish: the flag.

### Finding the Chink in the Armor

Here’s the key part of the server code [**[chall.py](http://chall.py)**](https://writeups.thebusfactoris1.online/assets/files/execser/[chall.py](http://chall.py)):

```python  
def decrypt(cipher : bytes):  
if len(cipher) % 16 > 0: raise PaddingError  
decrypter = AES.new(key, AES.MODE_CBC, iv = cipher[:16])  
msg_raw = decrypter.decrypt(cipher[16:])  
return unpad(msg_raw)

if __name__ == '__main__':  
while True:  
try:  
cipher_hex = input('input cipher (hex): ')  
cipher = decrypt(bytes.fromhex(cipher_hex))  
json_token = json.loads(cipher.decode())  
eval(json_token['command'])  
except PaddingError:  
print('invalid padding')  
except (json.JSONDecodeError, UnicodeDecodeError):  
print('no valid json')  
except:  
print('something else went wrong')  
````

Observations:

* First 16 bytes are the **IV**.  
* The rest is ciphertext.  
* After decryption, it calls `unpad`. If padding is wrong, it prints `invalid padding`.

This is a **Padding Oracle**. The server leaks whether the padding is valid. That tiny piece of information is all we need to both decrypt and *encrypt* arbitrary messages.

### The Art of Forgery: Becoming the Oracle

AES-CBC decryption works as:

```  
Plaintext_Block = Decrypt(Key, Ciphertext_Block) ⊕ Previous_Ciphertext_Block  
```

The value `Decrypt(Key, Ciphertext_Block)` is called the **intermediate state**.  
We don’t know the key, but we can manipulate `Previous_Ciphertext_Block` (or IV for the first block).

By brute forcing byte values and observing padding validity, we can solve for the intermediate state. Step by step, byte by byte, we recover it.

\---

## Reversing the Attack: From Decryption to Encryption

Now comes the trick. We don’t just want to decrypt—we want to **encrypt** our own payload:

```json  
{"command": "print(open('flag.txt').read())"}  
```

Steps:

1\. **Pick a random final block** `C_n`.  
2\. Use padding oracle to recover `I_n = Decrypt(Key, C_n)`.  
3\. Compute the previous ciphertext block:

```  
C_{n-1} = I_n ⊕ P_{n-1}  
```

where `P_{n-1}` is the plaintext block of our JSON payload.

4\. Repeat this process block by block, working backwards until we build the full ciphertext.

The solver script automates this entire backwards construction. It pads our payload, splits it into blocks, and forges each block until the final ciphertext is ready.

```py  
from pwn import *  
import os  
import json  
import re

HOST = "52.59.124.14"  
PORT = 5102

BLOCK_SIZE = 16

def pkcs7_pad(data):  
pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)  
return data + bytes([pad_len]) * pad_len

def check_padding(payload):  
p.sendlineafter(b'input cipher (hex): ', payload.hex().encode())  
response = p.recvline().strip()  
return response != b'invalid padding'

def get_intermediate_block(ciphertext_block):  
[log.info](http://log.info)(f"Cracking intermediate state for block: {ciphertext_block.hex()}")  
intermediate_state = bytearray(BLOCK_SIZE)  
crafted_iv = bytearray(BLOCK_SIZE)

for i in range(BLOCK_SIZE - 1, -1, -1):  
padding_byte = BLOCK_SIZE - i  
progress = log.progress(f'Cracking byte {i}')

for j in range(i + 1, BLOCK_SIZE):  
crafted_iv[j] = intermediate_state[j] ^ padding_byte

for guess in range(256):  
crafted_iv[i] = guess  
payload = bytes(crafted_iv) + ciphertext_block  
if check_padding(payload):  
intermediate_state[i] = guess ^ padding_byte  
progress.success(f"Found: {hex(intermediate_state[i])}")  
break  
else:  
progress.failure("Failed to find byte")  
return None

return bytes(intermediate_state)

def encrypt_payload(data):  
padded = pkcs7_pad(data)  
blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]  
log.success(f"Padded payload split into {len(blocks)} blocks.")

final_ciphertext = os.urandom(BLOCK_SIZE) # random last block (IV)  
for block in reversed(blocks):  
intermediate = get_intermediate_block(final_ciphertext[:BLOCK_SIZE])  
prev_cipher_block = xor(intermediate, block)  
final_ciphertext = prev_cipher_block + final_ciphertext

log.success("Successfully crafted full ciphertext.")  
return final_ciphertext

p = remote(HOST, PORT)

command = 'print(open("flag.txt").read())'  
json_payload = json.dumps({"command": command}).encode()

crafted_ciphertext = encrypt_payload(json_payload)

[log.info](http://log.info)("Sending final payload to server...")  
p.sendlineafter(b'input cipher (hex): ', crafted_ciphertext.hex().encode())

response_bytes = p.recvall(timeout=5)  
response_str = response_bytes.decode(errors='ignore')

m = re.search(r"ENO\\{[^\\}]+\\}", response_str)  
if m:  
log.success(f"Flag: {m.group(0)}")  
else:  
log.failure("Could not find flag in response:\n" + response_str)

p.close()  
```

\---

## Execution

When we send our crafted ciphertext, the server:

1\. Decrypts with AES-CBC.  
2\. Sees valid padding.  
3\. Parses JSON.  
4\. Executes our malicious command:

```python  
print(open("flag.txt").read())  
```

And with that, the genie grants our wish.  
```  
/bin/python3 /root/ctf/nullcon/[next.py](http://next.py)  
[+] Opening connection to 52.59.124.14 on port 5102: Done  
[+] Padded payload split into 3 blocks.  
[*] Cracking intermediate state for block: 52f15199fa4a504b0d1f9696bce10920  
[+] Cracking byte 15: Found: 0x7d  
[+] Cracking byte 14: Found: 0x91  
[+] Cracking byte 13: Found: 0xd6  
[+] Cracking byte 12: Found: 0xc4  
[+] Cracking byte 11: Found: 0xb2  
[+] Cracking byte 10: Found: 0x33  
[+] Cracking byte 9: Found: 0xa1  
[+] Cracking byte 8: Found: 0xc1  
[+] Cracking byte 7: Found: 0x40  
[+] Cracking byte 6: Found: 0x92  
[+] Cracking byte 5: Found: 0x15  
[+] Cracking byte 4: Found: 0x4c  
[+] Cracking byte 3: Found: 0xa3  
[+] Cracking byte 2: Found: 0x48  
[+] Cracking byte 1: Found: 0x26  
[+] Cracking byte 0: Found: 0x8b  
[*] Cracking intermediate state for block: f3521481653be025a0c51b9bedf4ec7c  
[+] Cracking byte 15: Found: 0xc9  
[+] Cracking byte 14: Found: 0xde  
[+] Cracking byte 13: Found: 0xcc  
[+] Cracking byte 12: Found: 0x5e  
[+] Cracking byte 11: Found: 0x53  
[+] Cracking byte 10: Found: 0x33  
[+] Cracking byte 9: Found: 0xbc  
[+] Cracking byte 8: Found: 0x2b  
[+] Cracking byte 7: Found: 0xc5  
[+] Cracking byte 6: Found: 0x8  
[+] Cracking byte 5: Found: 0x6a  
[+] Cracking byte 4: Found: 0x1a  
[+] Cracking byte 3: Found: 0x34  
[+] Cracking byte 2: Found: 0xbe  
[+] Cracking byte 1: Found: 0x78  
[+] Cracking byte 0: Found: 0x33  
[*] Cracking intermediate state for block: 5d0c965b6a0f66ed779e553f3fabf0bd  
[+] Cracking byte 15: Found: 0xf4  
[+] Cracking byte 14: Found: 0x2  
[+] Cracking byte 13: Found: 0x23  
[+] Cracking byte 12: Found: 0x6e  
[+] Cracking byte 11: Found: 0x97  
[+] Cracking byte 10: Found: 0x1e  
[+] Cracking byte 9: Found: 0x87  
[+] Cracking byte 8: Found: 0xd  
[+] Cracking byte 7: Found: 0x6d  
[+] Cracking byte 6: Found: 0xbc  
[+] Cracking byte 5: Found: 0xe0  
[+] Cracking byte 4: Found: 0xd1  
[+] Cracking byte 3: Found: 0xb0  
[+] Cracking byte 2: Found: 0x32  
[+] Cracking byte 1: Found: 0x6c  
[+] Cracking byte 0: Found: 0x20  
[+] Successfully crafted full ciphertext.  
[*] Sending final payload to server...  
[+] Receiving all data: Done (73B)  
[*] Closed connection to 52.59.124.14 port 5102  
[+] Flag: ENO{the_oracle_can_also_create_messages_as_desired}  
```

\---

## FLAG

```bash  
FLAG : ENO{the_oracle_can_also_create_messages_as_desired}  
```
