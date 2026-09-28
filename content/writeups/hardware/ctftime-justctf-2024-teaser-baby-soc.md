---
title: "Baby SoC - justCTF 2024 teaser"
category: "hardware"
subcategory: "heap"
type: "writeup"
tags: ["hardware", "xtensa", "xor", "esp32", "heap", "ghidra", "binwalk", "firmware", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "Category : forensics, misc"
source:
  name: "CTFtime writeup #39209"
  url: "https://ctftime.org/writeup/39209"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "Baby SoC"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** Baby SoC
- **Author team:** ECSC Team France
- **CTFtime tags:** xtensa, xor, esp32
- **CTFtime:** <https://ctftime.org/writeup/39209>

---
# Baby SoC

Category : forensics, misc

> We found really funny device. It was broken from the beginning, trust us! Can you help with recovering the truth?

Attached, we find `flashdump.bin` which looks like a flash dump.

## Loading the firmware

As always, let's start with `file` and `binwalk`.  
```  
$ file baby_flashdump.bin  
baby_flashdump.bin: data

$ binwalk flashdump.bin

DECIMAL HEXADECIMAL DESCRIPTION  
\--------------------------------------------------------------------------------  
65862 0x10146 HTML document header  
66286 0x102EE HTML document footer  
97467 0x17CBB Neighborly text, "neighbor entry"  
130884 0x1FF44 SHA256 hash constants, little endian  
159021 0x26D2D Intel x86 or x64 microcode, sig 0x014d061e, pf_mask 0x660660, 1D00-14-01, rev 0x-1000000, size 1  
159961 0x270D9 Intel x86 or x64 microcode, sig 0x014d061e, pf_mask 0x660660, 1D00-14-01, rev 0x-1000000, size 1  
```

Mmh... not much. There are some HTML pages in the flash.  
Some strings in the file makes us think this is a dump of an Espressif ESP32 chip.

As binwalk definitions are not as complete as file/libmagic, let's copy some definitions from [upstream](<https://github.com/file/file/blob/c64eed8b1eccd1721ddbe17d53441810dd5bb44c/magic/Magdir/firmware#L71>).  
We put these defnitions in [`esp32.magic`](<https://blog.nanax.fr/assets/images/hardware-longrange2/esp32.magic>) and call binwalk again:  
```  
$ binwalk baby_flashdump.bin -m esp32.magic

DECIMAL HEXADECIMAL DESCRIPTION  
\--------------------------------------------------------------------------------  
32768 0x8000 ESP-IDF partition table entry, label: "nvs", NVS data, offset: 0x9000, size: 0x5000  
32800 0x8020 ESP-IDF partition table entry, label: "otadata", OTA selection data, offset: 0xE000, size: 0x2000  
32832 0x8040 ESP-IDF partition table entry, label: "app0", OTA_0 app, offset: 0x10000, size: 0x140000  
32864 0x8060 ESP-IDF partition table entry, label: "app1", OTA_1 app, offset: 0x150000, size: 0x140000  
32896 0x8080 ESP-IDF partition table entry, label: "spiffs", SPIFFS partition, offset: 0x290000, size: 0x160000  
32928 0x80A0 ESP-IDF partition table entry, label: "coredump", coredump data, offset: 0x3F0000, size: 0x10000  
65536 0x10000 ESP-IDF application image for ESP32, project name: "arduino-lib-builder", version esp-idf: v4.4.5 ac5d805d0e, compiled on Jun 12 2023 16:41:45, IDF version: v4.4.5, entry address: 0x40082BA0  
```

Wow! much better. So it's a firmware, using ESP-IDF inside of the Arduino framework.  
We note down the entry address: `0x40082BA0`.

As this is quite an old Espressif chip, we can directly use [ghidra-esp32-flash-loader](<https://github.com/dynacylabs/ghidra-esp32-flash-loader>) without patching to add another ESP32 bootROM or SVD.  
We install the plugin, then open the firmware in Ghidra 11, and tadam! We got bootROM symbols!

## Baby reverse

Ghidra is quite bad at disassembling Xtensa instructions:  
\- some sections are recognized as code, but are strings,  
\- some instructions are misaligned and then fails to disassemble.

After a bit of cleaning, we notice a function writing a HTML document.

![function printing flag](<https://i.imgur.com/A7aru5t.png>)

Ghidra fails to decompile this function, but from the disassembly we understand it is a XOR within a loop.

![flag function](<https://i.imgur.com/KmbDpIk.png>)

We XOR both sections of `rwip_heap_non_ret` and flag!  
```  
justCTF{you_x0r_me_r1ght_r0und_b4by}  
```
