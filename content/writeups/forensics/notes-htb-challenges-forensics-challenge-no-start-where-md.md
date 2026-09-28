---
title: "Challenge- No Start Where (Forensics)"
category: "forensics"
subcategory: "htb-challenges"
type: "writeup"
tags: ["my-notes", "personal", "aes", "pcap", "tshark", "forensics", "htb-challenges"]
summary: "cmd.exe executed this script"
source:
  name: "Personal notes"
origin_path: "HTB Challenges/Forensics/Challenge- No Start Where.md"
---

- [https://sourceforge.net/projects/processhacker/](https://sourceforge.net/projects/processhacker/)

cmd.exe executed this script

```
C:\Users\commando\AppData\Local\Temp\2B4E.tmp\2B4F.tmp\2B50.bat
```

## packets decryption

```
00 00 00 d2 de ad be ef 19 45 ac c4 00 00 00 00
00 00 00 63 d6 70 78 c4 42 24 e6 58 f4 02 ae 44
7a 10 12 06 e8 8e 20 ca 30 28 06 2c 66 8e 60 a4
10 82 fa b8 8a 34 bc e4 2c c4 6a 2a d0 a4 8e bc
fe b0 aa 36 20 66 74 11 b3 47 89 8d 9e 4d 21 76
bf 18 87 e4 2b e2 c7 a9 f1 7a c6 b1 b5 c6 e2 0b
d9 6a 9f 34 20 83 fa 60 2c 4d 65 a2 47 02 5a b6
f1 52 2a 62 52 2a d3 19 75 06 99 91 e1 e6 b5 52
b9 e0 3e 45 32 39 9c 06 9a 79 6a 27 55 fd f5 7b
e8 6d 7d 2c 92 32 0e e5 07 50 cd 7b 48 11 13 95
9d a9 34 be a2 dd 16 6d 90 88 04 6c 02 68 10 0d
67 b3 c4 c3 11 9a 59 a3 96 2f 9f d7 ba 80 77 44
4d 0d 45 18 78 16 3d 03 cf 2d c4 a1 2f 8b ba bd
97 35 46 2a 02 16
```

### Demon.c

```c
Header (if specified):
[       ] 4 bytes
[ Magic Value  ] 4 bytes
[ Agent ID     ] 4 bytes
[ COMMAND ID   ] 4 bytes
[ Request ID   ] 4 bytes

MetaData:
[ AES KEY      ] 32 bytes
[ AES IV       ] 16 bytes
[ Magic Value  ] 4 bytes
[ Demon ID     ] 4 bytes
[ Host  ] size + bytes
[ User  ] size + bytes
[ Do    ] size + bytes
[ IP Add] 16 bytes?
[ Process Name ] size + bytes
[ Process ID   ] 4 bytes
[ Parent  PID  ] 4 bytes
[ Process Arch ] 4 bytes
[ Elev  ] 4 bytes
[ Base Address ] 8 bytes
[ OS    ] ( 5 * 4 ) bytes
[ OS    ] 4 bytes
[ SleepD] 4 bytes
[ SleepJitter  ] 4 bytes
[ Kill  ] 8 bytes
[ WorkingHours ] 4 bytes
..... more
[ Opti  ] Eg: Pivots, Extra data about the host or network etc.
```

- mode : CTR

### get aes , iv key

```python
b = ["00","00","00","d2","de","ad","be","ef","19","45","ac","c4","00","00","00","00","00","00","00","63","d6","70","78","c4","42","24","e6","58","f4","02","ae","44","7a","10","12","06","e8","8e","20","ca","30","28","06","2c","66","8e","60","a4","10","82","fa","b8","8a","34","bc","e4","2c","c4","6a","2a","d0","a4","8e","bc","fe","b0","aa","36","20","66","74","11","b3","47","89","8d","9e","4d","21","76","bf","18","87","e4","2b","e2","c7","a9","f1","7a","c6","b1","b5","c6","e2","0b","d9","6a","9f","34","20","83","fa","60","2c","4d","65","a2","47","02","5a","b6","f1","52","2a","62","52","2a","d3","19","75","06","99","91","e1","e6","b5","52","b9","e0","3e","45","32","39","9c","06","9a","79","6a","27","55","fd","f5","7b","e8","6d","7d","2c","92","32","0e","e5","07","50","cd","7b","48","11","13","95","9d","a9","34","be","a2","dd","16","6d","90","88","04","6c","02","68","10","0d","67","b3","c4","c3","11","9a","59","a3","96","2f","9f","d7","ba","80","77","44","4d","0d","45","18","78","16","3d","03","cf","2d","c4","a1","2f","8b","ba","bd","97","35","46","2a","02","16"]

print(f"[+] AES Key is: {''.join(b[20:20+32])}")
print(f"[+] AES IV is:  {''.join(b[52:52+16])}")


# [+] AES Key is: d67078c44224e658f402ae447a101206e88e20ca3028062c668e60a41082fab8
# [+] AES IV is:  8a34bce42cc46a2ad0a48ebcfeb0aa36
```

### extract the data from the pcap

- extract server packets

```bash
tshark -r capture.pcap -Y 'http && frame.len != 153 && frame.len != 206 && frame.len != 78' -T fields -e data.data > data2.txt
```

- extract result packets

```bash
tshark -r capture.pcap -Y 'http && frame.len != 153 && frame.len != 206 && frame.len != 78 && frame.len != 660 && frame.len != 111 && frame.len != 268' -T fields -e media.type > data.txt
```

### decrypt response

```python
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_decrypt(iv,key,ciphertext):
    ctr = Counter.new(128,initial_value=int.from_bytes(iv,byteorder='big'))
    cipher = AES.new(key,AES.MODE_CTR,counter=ctr)

    plaintext = cipher.decrypt(ciphertext)

    return plaintext

key = bytes.fromhex('d67078c44224e658f402ae447a101206e88e20ca3028062c668e60a41082fab8')
iv = bytes.fromhex('8a34bce42cc46a2ad0a48ebcfeb0aa36')

with open('response.txt','r') as f:
    enc = f.read().split()

for c in enc:
    cipher = bytes.fromhex(c)
    ciphertext = cipher[20:]

    plaintext = aes_decrypt(iv,key,ciphertext)

    print(plaintext.decode('latin-1'))
```

### decrypt request

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

def aes_decrypt(key,iv,ciphertext):
    ctr = Counter.new(128,initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(key,AES.MODE_CTR,counter=ctr)

    plaintext = cipher.decrypt(ciphertext)

    return plaintext

key = bytes.fromhex('d67078c44224e658f402ae447a101206e88e20ca3028062c668e60a41082fab8')
iv = bytes.fromhex('8a34bce42cc46a2ad0a48ebcfeb0aa36')

with open('request.txt','r') as f:
    enc = f.read().split()

for c in enc:
    cipher = bytes.fromhex(c)
    ciphertext = cipher[12:]

    plaintext = aes_decrypt(key,iv,ciphertext)
    print(plaintext.decode('latin-1'))
    \#with open('bin_output','w') as f:
    #    f.write(plaintext.decode('latin-1'))
```

### decrypt flag

```python
import codecs

def unhide(key,_string):
    array = bytearray(len(_string))
    for i in range(len(_string)):
        array[i] = key[i % len(key)] ^ _string[i]
    return array.decode()

key = bytearray([156,164,143,100,219,10,34,92,113,212,132,229,159,196,170,56])
_string = bytearray([212,240,205,31,239,85,80,104,31,167,180,136,232,240,216,11,195,144,227,19,239,115,81,3,6,166,183,209,244,241,245,80,168,210,191,7,166])

result = unhide(key,_string)
print(result)

# HTB{4_r4ns0mw4r3_4lw4ys_wr34k5_h4v0c}
```

---

*From your own notes: `HTB Challenges/Forensics/Challenge- No Start Where.md`*
