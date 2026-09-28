---
title: "Interlock - justCTF 2024 teaser"
category: "crypto"
subcategory: "ecdsa"
type: "writeup"
tags: ["crypto", "ecdsa", "interlock", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "We were given a python program which will execute an executable binary called timer."
source:
  name: "CTFtime writeup #39249"
  url: "https://ctftime.org/writeup/39249"
original_source: "https://hackmd.io/@vidner/just-sksd-2024#Interlock"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "Interlock"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** Interlock
- **Author team:** SKSD
- **CTFtime:** <https://ctftime.org/writeup/39249>
- **Original writeup:** <https://hackmd.io/@vidner/just-sksd-2024#Interlock>

---
## Interlock

We were given a python program which will execute an executable binary called `timer`. The given python program is a simulation of man-in-the-middle attack, where we can intercept encrypted communication between Alice and Bob.

```python  
#!/usr/bin/env python

from subprocess import PIPE, Popen  
from time import sleep  
import threading  
from datetime import datetime  
from queue import Queue, Empty  
import json  
from sys import stderr  
import hpke  
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding  
from cryptography.hazmat.primitives.asymmetric import ec  
from cryptography.hazmat.primitives import hashes  
import os  
from binascii import hexlify, unhexlify

FLAG = os.environ['FLAG'] if 'FLAG' in os.environ else 'justCTF{temporary-interlock-flag}'  
K = 4  
suite = hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305

timer = Popen(["./timer"], stdin=PIPE, stdout=PIPE, bufsize=1, encoding="ascii")  
timer_lock = threading.Lock()

alice_x1, alice_x2, bob_x1, bob_x2 = None, None, None, None

def get_time():  
timer_lock.acquire()  
try:  
timer.stdin.write("gettimeofday\n")  
t = timer.stdout.readline().strip()[:-3]  
return datetime.strptime(t, "%Y-%m-%d %H:%M:%S.%f")  
finally:  
timer_lock.release()

def fmt(data):  
return hexlify(data).decode()

def ufmt(data):  
return unhexlify(data.encode())

def alice(qr, qw, ev):  
try:  
alice_w(qr, qw)  
except Exception as e:  
ev.set()  
qr.put("ERROR")

def alice_w(qr, qw):  
global alice_x1, alice_x2  
msg = ""  
while msg != "start":  
msg = qw.get()

ska = suite.KEM.generate_private_key()  
pka = ska.public_key().public_bytes(  
encoding=Encoding.X962, format=PublicFormat.UncompressedPoint  
)

x1 = os.urandom(128)  
n1 = os.urandom(64)  
alice_x1 = x1

m1 = json.dumps({"x1": fmt(x1), "n1": fmt(n1), "pka": fmt(pka)})  
c1_d = hashes.Hash(hashes.SHA3_256())  
c1_d.update(m1.encode())  
c1 = c1_d.finalize()

qr.put(fmt(c1))

sleep(K)

s1 = ska.sign(m1.encode(), ec.ECDSA(hashes.SHA3_256()))  
m1_sig = json.dumps({"m1": m1, "s1": fmt(s1)})  
qr.put(m1_sig)

start_time = get_time()  
m2_enc = json.loads(qw.get())  
stop_time = get_time()

if (stop_time - start_time).total_seconds() >= K:  
raise Exception("too late")

encap, ct, pkb = ufmt(m2_enc["encap"]), ufmt(m2_enc["ct"]), ufmt(m2_enc["pkb"])  
pkb_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pkb)  
m2 = suite.open_auth(  
encap,  
ska,  
pkb_k,  
info=b"interlock",  
aad=pkb,  
ciphertext=ct,  
)  
m2 = json.loads(m2)  
if ufmt(m2["pka"]) != pka:  
raise Exception("wrong data")  
if m2["m1"] != m1:  
raise Exception("wrong data")

x2 = ufmt(m2["x2"])  
alice_x2 = x2

def bob(qr, qw, ev):  
try:  
bob_w(qr, qw)  
except Exception as e:  
ev.set()  
qr.put("ERROR")

def bob_w(qr, qw):  
global bob_x1, bob_x2  
msg = ""  
while msg != "start":  
msg = qw.get()

skb = suite.KEM.generate_private_key()  
pkb = skb.public_key().public_bytes(  
encoding=Encoding.X962, format=PublicFormat.UncompressedPoint  
)

c1 = ufmt(qw.get())

sleep(K)

m1_sig = json.loads(qw.get())  
m1 = json.loads(m1_sig["m1"])  
s1 = ufmt(m1_sig["s1"])  
x1, n1, pka = ufmt(m1["x1"]), ufmt(m1["n1"]), ufmt(m1["pka"])  
bob_x1 = x1

m1 = json.dumps({"x1": fmt(x1), "n1": fmt(n1), "pka": fmt(pka)})  
c1_d = hashes.Hash(hashes.SHA3_256())  
c1_d.update(m1.encode())  
if c1 != c1_d.finalize():  
raise Exception("wrong hash")

pka_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pka)  
pka_k.verify(s1, m1.encode(), ec.ECDSA(hashes.SHA3_256()))

x2 = os.urandom(128)  
n2 = os.urandom(64)  
bob_x2 = x2

m2 = json.dumps(  
{"x2": fmt(x2), "pka": fmt(pka), "m1": m1, "n2": fmt(n2)}  
)  
encap, ct = suite.seal_auth(  
pka_k, skb, info=b"interlock", aad=pkb, message=m2.encode()  
)  
m2_enc = json.dumps({"encap": fmt(encap), "ct": fmt(ct), "pkb": fmt(pkb)})  
qr.put(m2_enc)

def router(targets, aliceE, bobE):  
while True:  
if aliceE.is_set() or bobE.is_set():  
raise Exception("Communication error")

data = input()  
data = json.loads(data)

if not isinstance(data, dict):  
raise Exception("Communication error")

if data.get("type") not in targets:  
raise Exception("Communication error")

if data["type"] == "quit":  
return  
else:  
if data.get("target") not in targets[data["type"]]:  
raise Exception("Communication error")

if data["type"] == "write":  
if "msg" not in data:  
raise Exception("Communication error")  
targets[data["type"]][data["target"]].put(data["msg"])

elif data["type"] == "read":  
try:  
msg = targets[data["type"]][data["target"]].get(True, 1)  
print(msg)  
except Empty:  
print("none")

def main():  
aliceQW, bobQW = Queue(), Queue()  
aliceQR, bobQR = Queue(), Queue()  
aliceE, bobE = threading.Event(), threading.Event()  
aliceT, bobT = threading.Thread(  
target=alice, args=(aliceQR, aliceQW, aliceE)  
), threading.Thread(target=bob, args=(bobQR, bobQW, bobE))  
targets = {  
"read": {"alice": aliceQR, "bob": bobQR},  
"write": {"alice": aliceQW, "bob": bobQW},  
"quit": None,  
}  
aliceT.start(), bobT.start()

print(f"Welcome in {get_time()} at World Chess Championship!")

try:  
router(targets, aliceE, bobE)  
except:  
print("Error")  
os._exit(1)

aliceT.join(), bobT.join()  
timer.stdin.write("q\n")  
timer.communicate()

if aliceE.is_set() or bobE.is_set():  
print("NOPE")  
return

print("Communication established, check if MITM was successful")

try:  
x1 = unhexlify(input("Give me x1: ").strip())  
x2 = unhexlify(input("Give me x2: ").strip())  
except:  
print("Error")  
return

if x1 == alice_x1 == bob_x1:  
if x2 == alice_x2 == bob_x2:  
print(FLAG)  
return  
print("NOPE")

if __name__ == "__main__":  
main()  
```  
The goal is to make `x1 == alice_x1 == bob_x1` and `x2 == alice_x2 == bob_x2`. `alice_x1` and `bob_x2` are random, meanwhile `bob_x1` and `alice_x2` are given from the received payload on each function. Notice that `alice_x1` goes unencrypted, so we can know the value. But, `bob_x2` is encrypted, and we can't know Alice's private key to decrypt it. So, we need to send another key to Bob so we can get the value of `bob_x2` and send it to Alice. Thanks to the author, the skeleton of the solver was given so we just need to complete it.

There was one more problem to solve, the `timer`. Notice that we just can get `alice_x1` just before the timer starts in `alice_w`. And we can't send anything to Bob just yet because we need to send `m1_sig` before we send forged `m1`. We also need to wait `K` seconds to get `bob_x2`, so the time difference checking will always failed.

Because the calculation uses the binary `timer`, and the tag of the challenge is `pwn`, but we can't influence the binary. We tried to run the binary and noticed that no matter what the inputs are, the `timer` binary will just outputting the time at the end of the year 1990. After some trial and error, we noticed that there is a bug that shows inaccurate time.

![image](<https://hackmd.io/_uploads/HkDRVZwLC.png>)

After some testing, we concluded that we can start the timer from `K` seconds before new year to make the time differences below `K`.  
```python  
#!/usr/bin/env python

import sys  
from datetime import datetime  
import threading  
from subprocess import PIPE, Popen  
from time import sleep

timer = Popen(["./timer"], stdin=PIPE, stdout=PIPE, bufsize=1, encoding="ascii")  
timer_lock = threading.Lock()

def get_time():  
timer_lock.acquire()  
try:  
timer.stdin.write("gettimeofday\n")  
t = timer.stdout.readline().strip()[:-3]  
return datetime.strptime(t, "%Y-%m-%d %H:%M:%S.%f")  
finally:  
timer_lock.release()

K = 4  
t = get_time()  
while not (t.minute == int(sys.argv[1]) and t.second == int(sys.argv[2])):  
print(f'{t = }')  
t = get_time()  
sleep(1)  
start = get_time()  
sleep(K)  
end = get_time()  
print((end - start).total_seconds())  
```  
![Screenshot from 2024-06-16 00-21-49](<https://hackmd.io/_uploads/S1X10-P8C.png>)

Solver:  
```python  
import json, os  
import hpke  
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding  
from cryptography.hazmat.primitives.asymmetric import ec  
from cryptography.hazmat.primitives import hashes  
from binascii import hexlify, unhexlify  
from pwn import *  
from time import sleep  
from datetime import datetime

suite = hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__ChaCha20Poly1305

eve_x1, eve_x2 = None, None

ske = suite.KEM.generate_private_key()  
pke = ske.public_key().public_bytes(  
encoding=Encoding.X962, format=PublicFormat.UncompressedPoint  
)

def send(conn, t, msg):  
conn.sendline(json.dumps({"type": "write", "target": t, "msg": msg}).encode())

def send_alice(conn, msg):  
send(conn, "alice", msg)

def send_bob(conn, msg):  
send(conn, "bob", msg)

def recv(conn, t):  
conn.sendline(json.dumps({"type": "read", "target": t}).encode())  
msg = conn.recvline(keepends=False)  
if msg == b"none":  
return None  
return msg

def recv_blocking(conn, t):  
msg = None  
while msg is None:  
msg = recv(conn, t)  
return msg

def recv_alice(conn):  
return recv_blocking(conn, "alice")

def recv_bob(conn):  
return recv_blocking(conn, "bob")

def fmt(data):  
return hexlify(data).decode()

def ufmt(data):  
return unhexlify(data.encode())

def eve_to_bob(m1_sig):  
global eve_x1

m1_sig = json.loads(m1_sig)  
m1 = json.loads(m1_sig["m1"])

x1 = ufmt(m1["x1"])  
n1 = ufmt(m1["n1"])

eve_x1 = x1

m1 = json.dumps({"x1": fmt(x1), "n1": fmt(n1), "pka": fmt(pke)})  
c1_d = hashes.Hash(hashes.SHA3_256())  
c1_d.update(m1.encode())  
c1 = c1_d.finalize()

s1 = ske.sign(m1.encode(), ec.ECDSA(hashes.SHA3_256()))  
m1_sig = {"m1": m1, "s1": fmt(s1)}

return fmt(c1), json.dumps(m1_sig)

def eve_to_alice(m1_sig, m2_enc):  
global eve_x2

m1_sig = json.loads(m1_sig)  
m2_enc = json.loads(m2_enc)

encap, ct, pkb = ufmt(m2_enc["encap"]), ufmt(m2_enc["ct"]), ufmt(m2_enc["pkb"])  
pkb_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pkb)  
m2 = suite.open_auth(  
encap,  
ske,  
pkb_k,  
info=b"interlock",  
aad=pkb,  
ciphertext=ct,  
)  
m2 = json.loads(m2)

x2 = ufmt(m2["x2"])  
n2 = ufmt(m2["n2"])  
eve_x2 = x2

m1 = json.loads(m1_sig["m1"])  
s1 = ufmt(m1_sig["s1"])  
x1, n1, pka = ufmt(m1["x1"]), ufmt(m1["n1"]), ufmt(m1["pka"])

m1 = json.dumps({"x1": fmt(x1), "n1": fmt(n1), "pka": fmt(pka)})  
c1_d = hashes.Hash(hashes.SHA3_256())  
c1_d.update(m1.encode())

pka_k = ec.EllipticCurvePublicKey.from_encoded_point(suite.KEM.CURVE, pka)  
pka_k.verify(s1, m1.encode(), ec.ECDSA(hashes.SHA3_256()))

m2 = json.dumps({"x2": fmt(x2), "pka": fmt(pka), "m1": m1, "n2": fmt(n2)})  
encap, ct = suite.seal_auth(  
pka_k, ske, info=b"interlock", aad=pke, message=m2.encode()  
)  
m2_enc = {"encap": fmt(encap), "ct": fmt(ct), "pkb": fmt(pke)}

return json.dumps(m2_enc)

def main():  
conn = remote("[interlock.nc.jctf.pro](http://interlock.nc.jctf.pro)", 7331)  
welcome = conn.recvline(keepends=False).decode()

current_datetime = datetime.strptime(welcome[len('Welcome in '):-(len(' at World Chess Championship!') + 3)], "%Y-%m-%d %H:%M:%S.%f")  
print(current_datetime)  
expected_datetime = datetime.strptime("1990-12-31 23:59:52.500", "%Y-%m-%d %H:%M:%S.%f")

sleep((expected_datetime - current_datetime).total_seconds())

send_bob(conn, "start")  
send_alice(conn, "start")

c1 = recv_alice(conn).decode()  
m1_sig = recv_alice(conn).decode()

original_m1_sig = m1_sig

c1, m1_sig = eve_to_bob(m1_sig)

print("sending c1 to bob: ", c1)  
send_bob(conn, c1)

print("sending m1_sig to bob: ", m1_sig)  
send_bob(conn, m1_sig)

m2_enc = recv_bob(conn).decode()  
print("received m2_enc: ", m2_enc)

m2_enc = eve_to_alice(original_m1_sig, m2_enc)

send_alice(conn, m2_enc)  
print("sending m2_enc to alice")

conn.sendline(json.dumps({"type": "quit"}).encode())

print(conn.recvline_startswith(b"Communication"))

conn.recvuntil(b"Give me x1: ")  
conn.sendline(fmt(eve_x1))

conn.recvuntil(b"Give me x2: ")  
conn.sendline(fmt(eve_x2))

err = conn.recvline().strip()  
print(err)  
conn.interactive()  
conn.close()  
```  
![Screenshot from 2024-06-16 00-21-19](<https://hackmd.io/_uploads/ryaOVbwUA.png>)  
> justCTF{p3rf3c71y_un6r34k4b13_1f_n0t_71m3_7r4v31s}
