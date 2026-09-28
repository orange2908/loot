---
title: "Budget SoC - justCTF 2024 teaser"
category: "forensics"
subcategory: "disk"
type: "writeup"
tags: ["forensics", "binwalk", "xtensa", "aes", "esp32", "ecb", "heap", "ghidra", "firmware", "disk", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "Category : forensics, misc"
source:
  name: "CTFtime writeup #39210"
  url: "https://ctftime.org/writeup/39210"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "Budget SoC"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** Budget SoC
- **Author team:** ECSC Team France
- **CTFtime tags:** binwalk, xtensa, aes, esp32
- **CTFtime:** <https://ctftime.org/writeup/39210>

---
# Budget SoC

Category : forensics, misc

> We’ve obtained a mysterious device. Our forensic team tried to retrieve the original source code, but something went wrong. Fortunately, we managed to dump the memory into a file. Can you find what we need?

Attached, we find `flashdump.bin` which looks like a flash dump.

## Loading the firmware

This is very similar to [Baby SoC challenge](<https://ctftime.org/task/28535>).  
As with Baby SoC, we use [`esp32.magic`](<https://blog.nanax.fr/assets/images/hardware-longrange2/esp32.magic>) definitions.

```  
$ binwalk flashdump.bin

DECIMAL HEXADECIMAL DESCRIPTION  
\--------------------------------------------------------------------------------  
65862 0x10146 HTML document header  
66286 0x102EE HTML document footer  
69043 0x10DB3 AES Inverse S-Box  
69299 0x10EB3 AES S-Box  
97967 0x17EAF Neighborly text, "neighbor entry"  
131380 0x20134 SHA256 hash constants, little endian  
159525 0x26F25 Intel x86 or x64 microcode, sig 0x014d061e, pf_mask 0x660660, 1D00-14-01, rev 0x-1000000, size 1  
160465 0x272D1 Intel x86 or x64 microcode, sig 0x014d061e, pf_mask 0x660660, 1D00-14-01, rev 0x-1000000, size 1

$ binwalk -m esp32.magic ./flashdump.bin

DECIMAL HEXADECIMAL DESCRIPTION  
\--------------------------------------------------------------------------------  
32768 0x8000 ESP-IDF partition table entry, label: "nvs", NVS data, offset: 0x9000, size: 0x5000  
32800 0x8020 ESP-IDF partition table entry, label: "otadata", OTA selection data, offset: 0xE000, size: 0x2000  
32832 0x8040 ESP-IDF partition table entry, label: "app0", OTA_0 app, offset: 0x10000, size: 0x140000  
32864 0x8060 ESP-IDF partition table entry, label: "app1", OTA_1 app, offset: 0x150000, size: 0x140000  
32896 0x8080 ESP-IDF partition table entry, label: "spiffs", SPIFFS partition, offset: 0x290000, size: 0x160000  
32928 0x80A0 ESP-IDF partition table entry, label: "coredump", coredump data, offset: 0x3F0000, size: 0x10000  
```

Much information! The layout is very similar to Baby SoC, but **we now have an AES S-Box and Inverse S-Box!**

We load the firmware in Ghidra 11 using [ghidra-esp32-flash-loader](<https://github.com/dynacylabs/ghidra-esp32-flash-loader>).

## Reverse

Ghidra is quite bad at disassembling Xtensa instructions:  
\- some sections are recognized as code, but are strings,  
\- some instructions are misaligned and then fails to disassemble.

To speedrun the reverse, we directly start by annotating the AES functions.  
The AES S-Box found by binwalk is at `0x3f400eb3` (`db[256]`).  
The AES Inverse S-Box found by binwalk is at `0x3f400db3` (`db[256]`).

Why do we have a non-inverse S-Box ? Because the S-Box might be used for key scheduling.  
This hypothesis is quickly confirmed by looking at the crossref at `0x400d7dd8`.  
After a bit of analyses, we guess the following function signature:  
```  
undefined8 aes_key_schedule(aes_t *aex_ctx,byte *key,ushort len)  
```

Going back a few function crossrefs, we find a hardcoded key at `rwip_heap_non_ret + 0xc`: `33bdfb724c22873362ff7541d514f6fd`.  
As this key is 16-byte long, this is AES-128.

After a bit of reversing, we find the following at `0x400d296c`:

![function aes decrypt](<https://i.imgur.com/9J4MEmQ.png>)

The last argument of `call_aes_decrypt` seems to be an IV. It is set to `0` by `memset`.

To recap :

* AES-128  
* key = 33bdfb724c22873362ff7541d514f6fd  
* iv = 0000000000000000

The plaintext points to some data in SRAM, that might be initialized during runtime.  
Because we are doing static analysis, we don't have the plaintext.

One solution would be to emulate the firmware, and dump the memory at this address.  
Another solution would be to assume that the plaintext is still somewhere in the flash and bruteforce its location:

```python  
from Crypto.Cipher import AES  
from tqdm import *

d = open("flashdump.bin", "rb").read()

k = bytes.fromhex("33bdfb724c22873362ff7541d514f6fd")  
E = AES.new(k, AES.MODE_ECB)

for i in trange(len(d) - 32):  
c = d[i:][:16]  
m = E.decrypt(c)  
if b"justCTF" in m:  
print(i, m)  
```

And we get the offset of the plaintext in 12 seconds:  
```  
42308 b'justCTF{dUmp3d_r'  
```

Then we decrypt the rest and flag!  
```  
justCTF{dUmp3d_r3v3rs3d_h4ck3d}  
```
