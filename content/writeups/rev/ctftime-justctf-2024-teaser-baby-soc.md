---
title: "Baby SoC - justCTF 2024 teaser"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "esp32", "reversing", "xor", "ghidra", "binwalk", "static-analysis", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "In this easy misc/forensics challenge, we are given only a flashdump.bin file and this description:"
source:
  name: "CTFtime writeup #39212"
  url: "https://ctftime.org/writeup/39212"
original_source: "https://github.com/msanft/writeups/blob/ad7bfc16949e1c1666bf98a9a344156a4d36f865/2024/justctf-teaser/misc-baby-soc.md"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "Baby SoC"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** Baby SoC
- **Author team:** FluxFingers
- **CTFtime tags:** esp32, reversing
- **CTFtime:** <https://ctftime.org/writeup/39212>
- **Original writeup:** <https://github.com/msanft/writeups/blob/ad7bfc16949e1c1666bf98a9a344156a4d36f865/2024/justctf-teaser/misc-baby-soc.md>

---
# Baby SoC

In this easy misc/forensics challenge, we are given only a `flashdump.bin` file and this description:

> We found really funny device. It was broken from the beginning, trust us! Can you help with recovering the truth?

## Analyzing the Flashdump

`binwalk`ing over the file doesn't yield any interesting results, but calling `strings` on it shows some ESP32-related symbols. We can assume that this is  
a flashdump of an ESP32 microcontroller. Now, how to analyze what's going on here?

I found a nice [blog post](<https://olof-astrand.medium.com/reverse-engineering-of-esp32-flash-dumps-with-ghidra-or-ida-pro-8c7c58871e68>) on reversing ESP32 flash dumps, which recommends  
a tool called [`esp32-image-parser`](<https://github.com/tenable/esp32_image_parser>). With some patches from the open PRs applied, we can dump the sections of the flashdump:

```shell-session  
$ ./[esp32_image_parser.py](http://esp32_image_parser.py) show_partitions ../flashdump.bin  
reading partition table...  
entry 0:  
label : nvs  
offset : 0x9000  
length : 20480  
type : 1 [DATA]  
sub type : 2 [NVS]

entry 1:  
label : otadata  
offset : 0xe000  
length : 8192  
type : 1 [DATA]  
sub type : 0 [OTA]

entry 2:  
label : app0  
offset : 0x10000  
length : 1310720  
type : 0 [APP]  
sub type : 16 [ota_0]

entry 3:  
label : app1  
offset : 0x150000  
length : 1310720  
type : 0 [APP]  
sub type : 17 [ota_1]

entry 4:  
label : spiffs  
offset : 0x290000  
length : 1441792  
type : 1 [DATA]  
sub type : 130 [SPIFFS]

entry 5:  
label : coredump  
offset : 0x3f0000  
length : 65536  
type : 1 [DATA]  
sub type : 3 [COREDUMP]

MD5sum:  
972dae2ff872a0142d60bad124c0666b  
Done  
```

As per the blog post, we can now transform the application sections (only `app0` turned out to matter in our case) to ELF  
files:

```shell-session  
./[esp32_image_parser.py](http://esp32_image_parser.py) create_elf ../flashdump.bin -partition app0 -output app0.elf  
```

Now we have an ELF file that we can analyze with Ghidra.

## Analyzing the Application

Looking through the strings used in the file, we can quickly find that there's some HTML for displaying the flag. Therefore, this should be a web server  
of sorts.

![Function writing the HTML](<https://github.com/msanft/writeups/raw/main/2024/justctf-teaser/misc-baby-soc-1.png?raw=true>)

Looking at where the stuff gets written to, we can quickly find the part that should write the flag:

![Function writing the HTML (Analyzed)](<https://github.com/msanft/writeups/raw/main/2024/justctf-teaser/misc-baby-soc-2.png?raw=true>)

Analyzing where the values come from, we can find that the flag is computed by XORing two values from the data section into `something_in_flag`:

![Function computing the flag]*<https://github.com/msanft/writeups/raw/main/2024/justctf-teaser/misc-baby-soc-3.png?raw=true>)

Performing this XOR in Python gives us the flag:

> `justCTF{you_x0r_me_r1ght_r0und_b4by}`
