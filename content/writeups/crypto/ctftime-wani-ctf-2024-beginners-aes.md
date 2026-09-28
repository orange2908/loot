---
title: "beginners_aes - Wani CTF 2024"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "aes", "cbc", "beginners", "wani-ctf", "wani-ctf-2024", "2024", "ctf-writeup"]
summary: "from Crypto.Util.Padding import unpad"
source:
  name: "CTFtime writeup #39240"
  url: "https://ctftime.org/writeup/39240"
original_source: "https://medium.com/@zeroair41/cracking-the-code-a-dive-into-aes-encryption-with-wanictf2024-36c8b5fc5e51"
ctf:
  name: "Wani CTF 2024"
  year: 2024
  challenge: "beginners_aes"
---

## Metadata

- **CTF:** Wani CTF 2024
- **Task:** beginners_aes
- **Author team:** NCA@Nepal
- **CTFtime:** <https://ctftime.org/writeup/39240>
- **Original writeup:** <https://medium.com/@zeroair41/cracking-the-code-a-dive-into-aes-encryption-with-wanictf2024-36c8b5fc5e51>

---
[decrypt.py](http://decrypt.py)

```  
from Crypto.Util.Padding import unpad  
from Crypto.Cipher import AES  
import hashlib

# Known parts of the key and IV  
base_key = b'the_enc_key_is_'  
base_iv = b'my_great_iv_is_'

# Encrypted message (obtained from the original script)  
enc = b'\x16\x97,\xa7\xfb_\xf3\x15.\x87jKRaF&"\xb6\xc4x\xf4.K\xd77j\xe5MLI_y\xd96\xf1$\xc5\xa3\x03\x990Q^\xc0\x17M2\x18'

# Original message hash (obtained from the original script)  
flag_hash = '6a96111d69e015a07e96dcd141d31e7fc81c4420dbbef75aef5201809093210e'

def brute_force_decrypt(enc, base_key, base_iv, flag_hash):  
for key_suffix in range(256): # Loop through all possible byte values for the key suffix  
for iv_suffix in range(256): # Loop through all possible byte values for the IV suffix  
key = base_key + bytes([key_suffix])  
iv = base_iv + bytes([iv_suffix])  
try:  
cipher = AES.new(key, AES.MODE_CBC, iv)  
decrypted_msg = unpad(cipher.decrypt(enc), 16)  
if hashlib.sha256(decrypted_msg).hexdigest() == flag_hash: # Check if the decrypted message matches the hash  
return decrypted_msg, key, iv  
except (ValueError, KeyError): # Catch any errors during decryption and continue  
continue  
return None, None, None

decrypted_msg, found_key, found_iv = brute_force_decrypt(enc, base_key, base_iv, flag_hash)

if decrypted_msg:  
print(f'Decrypted message: {decrypted_msg}')  
print(f'Key: {found_key}')  
print(f'IV: {found_iv}')  
else:  
print('Failed to decrypt the message.')  
```
