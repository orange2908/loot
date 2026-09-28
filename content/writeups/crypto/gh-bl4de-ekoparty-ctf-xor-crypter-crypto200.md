---
title: "XOR Crypter Crypto200 - Ekoparty CTF 2015"
category: "crypto"
subcategory: "crypto"
type: "writeup"
tags: ["crypto", "xor", "base64", "crypter", "crypto200", "cryptography"]
summary: "Description: The state of art on encryption, can you defeat it?"
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/Ekoparty_CTF_2015/XOR_Crypter_Crypto200.md"
ctf:
  name: "Ekoparty CTF"
  year: 2015
  challenge: "XOR Crypter Crypto200"
---

## Source

- **CTF:** Ekoparty CTF 2015
- **Challenge:** XOR Crypter Crypto200
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2015/Ekoparty_CTF_2015/XOR_Crypter_Crypto200.md>

---
### XOR Crypter - Crypto 200pts

## Problem


Description: The state of art on encryption, can you defeat it?
CjBPewYGc2gdD3RpMRNfdDcQX3UGGmhpBxZhYhFlfQA=

## Solution

We get Python script used for encrypt the flag. Output of this script is Base64 string contains encrypted flag (CjBPewYGc2gdD3RpMRNfdDcQX3UGGmhpBxZhYhFlfQA=)

```python
import struct
import sys
import base64

if len(sys.argv) != 2:
    print "Usage: %s data" % sys.argv[0]
    exit(0)

data = sys.argv[1]
padding = 4 - len(data) % 4
if padding != 0:
    data = data + "\x00" * padding

result = []
blocks = struct.unpack("I" * (len(data) / 4), data)
for block in blocks:
    result += [block ^ block >> 16]

output = ''
for block in result:
    output += struct.pack("I", block)

print base64.b64encode(output)
```

To resolve this, we have to create "decrypter".

Here's my sample solution for this, maybe not state-of-the-art, but I was able to get the flag :)


```python
#!/usr/bin/env python

import struct
import sys
import base64

data = base64.b64decode(sys.argv[1])
padding = 4 - len(data) % 4

if padding != 0:
    data = data + "\x00" * padding

print data

i = 0
padding = 4
output = ''
result = ''
while i < len(data):
    junk = data[i:i + padding]
    print i, padding
    output = struct.unpack("I", junk)
    for s in output:
        r = s ^ s >> 16
        result += struct.pack("I", r)
    i += 4

print result
 
```


And here's output with flag:

```
$ ./test.py CjBPewYGc2gdD3RpMRNfdDcQX3UGGmhpBxZhYhFlfQA=
 
0O{♠♠sh↔☼ti1‼_t7►_u♠→hi▬ab◄e}
0 4
4 4
8 4
12 4
16 4
20 4
24 4
28 4
32 4
EKO{unshifting_the_unshiftable}
```
