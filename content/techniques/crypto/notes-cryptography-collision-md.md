---
title: "Collision (Cryptography)"
category: "crypto"
type: "technique"
tags: ["my-notes", "personal", "collision", "cryptography", "crypto"]
summary: "Personal note: Collision (Cryptography)."
source:
  name: "Personal notes"
origin_path: "Cryptography/collision.md"
---

#birthday #attack #birthdayattack
## SHA256 Collision
```python
#!/usr/bin/env python3
import hashlib, math

hash_called=0

def my_hash(s):
    global hash_called
    hash_called=hash_called+1
    m = hashlib.sha256()
    m.update(s.encode('utf-8'))
    return int.from_bytes(m.digest()[12:17], byteorder='big')

hashes={}

s1="Hello, world!"
s2="Goodbye, cruel world..."

ctr=0
while True:
    # hash both strings

    s=s1+"|"+str(ctr)
    h=my_hash(s)
    # stash this hash in hashes dictionary for future use
    hashes[h]=s

    s=s2+"|"+str(ctr)
    h=my_hash(s)
    if h in hashes:
        print ("collision found")
        print ("hash:", h)
        print ("first string: ["+s+"]")
        print ("second string: ["+hashes[h]+"]")
        print ("hash_called:", hash_called)
        print ("binlog(hash_called): %2.3f" % math.log(hash_called, 2))
        exit(0)
    ctr=ctr+1
```
- https://dreamhack.io/wargame/challenges/1124
- https://yurichev.org/birthday/ 
## MD5 Collision
```python
Here is a 72-byte alphanum MD5 collision with 1-byte difference for fun:
md5("TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak") = md5("TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak")
```
- https://x.com/realhashbreaker/status/1770161965006008570?t=w999AnD5Z-m8znFYsTP_0Q&s=19

---

*From your own notes: `Cryptography/collision.md`*
