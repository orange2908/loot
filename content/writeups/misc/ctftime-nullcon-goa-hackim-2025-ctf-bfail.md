---
title: "bfail - Nullcon Goa HackIM 2025 CTF"
category: "misc"
type: "writeup"
tags: ["misc", "bfail", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "In this challenge, we were presented with a bcrypt password hash for an admin account."
source:
  name: "CTFtime writeup #40006"
  url: "https://ctftime.org/writeup/40006"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "bfail"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** bfail
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40006>

---
## Challenge Overview  
In this challenge, we were presented with a bcrypt password hash for an admin account. The twist was that the original password is longer than 72 bytes, but due to bcrypt's design, only the first 72 bytes of any input are considered. This allowed the attacker to exploit the extra byte(s) by brute-forcing the 73rd byte to match the stored hash.

## Background: Bcrypt's 72-Byte Limitation  
Bcrypt is a popular password hashing function that, by design, only processes the first 72 bytes of any input. Any bytes beyond this limit are ignored during the hash computation. This limitation can sometimes be used to an attacker's advantage, as it might be possible to manipulate or brute-force the unused portion of the password without affecting the computed hash.

## Exploitation Process

1\. **Extract the Salt:**   
The bcrypt hash contains the salt in its first 29 characters. This salt is essential for re-computing the hash for any candidate password.

2\. **Prepare the Partial Password:**   
We are provided with the first 72 bytes of the password. Since bcrypt ignores bytes beyond 72, these bytes are all that matter for the hash computation.

3\. **Brute-force the Missing Byte:**   
The challenge lies in determining the 73rd byte. By iterating through all 256 possible values for this byte and appending it to the 72-byte partial password, we can generate candidate passwords. Each candidate is hashed using the extracted salt, and when the resulting hash matches the given bcrypt hash, the correct last byte has been found.

4\. **Send the Exploit Request:**   
Once the full password (73 bytes) is determined, it is URL-encoded along with the username ("admin") and sent as a request to the target URL. A successful response typically indicates that the exploit has worked, granting access to the admin account.

## The Solve Script

Below is the complete Python script used to solve the challenge:

```python  
import bcrypt  
import requests  
import urllib.parse

# Target URL (change if needed)  
TARGET_URL = "http://52.59.124.14:5013/" # Update with actual server URL

# Partial password (first 72 bytes)  
partialPass = b'\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76'

# Admin's bcrypt password hash  
bcryptHash = b"$2b$12$8bMrI6D9TMYXeMv8pq8RjemsZg.HekhkQUqLymBic/cRhiKRa3YPK"

# Extract salt from the hash (first 29 characters)  
salt = bcryptHash[:29]

# Brute-force the last byte  
found_password = None  
for i in range(256):  
testPass = partialPass + bytes([i])  
testHash = bcrypt.hashpw(testPass, salt)

if testHash == bcryptHash:  
print(f"[+] Found last byte: {hex(i)}")  
found_password = testPass  
break

if not found_password:  
print("[-] Failed to brute-force the last byte.")  
exit()

# URL encode the username and password  
username = urllib.parse.quote_from_bytes(b"admin")  
password = urllib.parse.quote_from_bytes(found_password)

# Send request to the target  
data = {"username": username, "password": password}  
response = requests.get(TARGET_URL, data=data)

# Print the response  
print(response.text)
