---
title: "Decrypt Chrome Passwords (Forensics)"
category: "forensics"
subcategory: "aes"
type: "technique"
tags: ["my-notes", "personal", "aes", "gcm", "base64", "sqlite", "wordlists", "forensics"]
summary: "Personal note: Decrypt Chrome Passwords (Forensics)."
source:
  name: "Personal notes"
origin_path: "Forensics/Decrypt Chrome Passwords.md"
---

```
https://github.com/ohyicong/decrypt-chrome-passwords
```

### run this script

```
https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/DPAPImk2john.py
```

### sid and masterkey can be found here

```
AppData/Roaming/Microsoft/Protect/S-1-5-21-3702016591-3723034727-1691771208-1002
```

### get the hash

```
python DPAPImk2john.py --sid="S-1-5-21-3702016591-3723034727-1691771208-1002" --masterkey="865be7a6-863c-4d73-ac9f-233f8734089d" --context="local" > ~/Desktop/HTB/Challenges/forensics/Seized/hash.txt
```

### crack the hash using

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### decrypt the key at `AppData/Local/Google/Chrome/User Data/Local State`

```
import base64
import json

fh = open('AppData/Local/Google/Chrome/User Data/Local State' ,'rb') 
encrypted_key = json.load(fh)

encrypted_key = encrypted_key['os_crypt']['encrypted_key']

decrypted_key = base64.b64decode(encrypted_key)

with open('dec_data','wb') as f:
    f.write(decrypted_key[5:])
```

### We can now use mimikatz to decrypt the master key.

```
dpapi::masterkey /in:865be7a6-863c-4d73-ac9f-233f8734089d /sid:S-1-5-21-3702016591-3723034727-1691771208-1002 /password:ransom /protected
```

```
key : 138f089556f32b87e53c5337c47f5f34746162db7fe9ef47f13a92c74897bf67e890bcf9c6a1d1f4cc5454f13fcecc1f9f910afb8e2441d8d3dbc3997794c630
```

### And then decrypt the DPAPI blob which is the private AES key.

```
dpapi::blob /masterkey:138f089556f32b87e53c5337c47f5f34746162db7fe9ef47f13a92c74897bf67e890bcf9c6a1d1f4cc5454f13fcecc1f9f910afb8e2441d8d3dbc3997794c630 /in:"dec_data" /out:aes.dec
```

```
masterkey     : 138f089556f32b87e53c5337c47f5f34746162db7fe9ef47f13a92c74897bf67e890bcf9c6a1d1f4cc5454f13fcecc1f9f910afb8e2441d8d3dbc3997794c630
```

### Modify the script and run it

```
https://github.com/ohyicong/decrypt-chrome-passwords
```

```
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

def get_secret_key():
    secret_key = open('aes.dec', 'rb').read()
    return secret_key

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        return sqlite3.connect(chrome_path_login_db)
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    secret_key = get_secret_key()
    chrome_path_login_db = r"C:\Users\ahmed\Desktop\Seized\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    conn = get_db_connection(chrome_path_login_db)
    if(secret_key and conn):
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for index,login in enumerate(cursor.fetchall()):
            url = login[0]
            username = login[1]
            ciphertext = login[2]
            if(url!="" and username!="" and ciphertext!=""):
                decrypted_password = decrypt_password(ciphertext, secret_key)
                print("Sequence: %d"%(index))
                print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                print("*"*50)
        cursor.close()
        conn.close()
```

### Reference

```
https://www.hackthebox.com/blog/seized-ca-ctf-2022-forensics-writeup
```

---

*From your own notes: `Forensics/Decrypt Chrome Passwords.md`*
