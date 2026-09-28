---
title: "chest-mix - b01lers CTF 2024"
category: "misc"
subcategory: "packers"
type: "writeup"
tags: ["misc", "minecraft", "packer", "chest-mix", "packers", "b01lers-ctf", "b01lers-ctf-2024", "2024", "ctf-writeup"]
summary: "We are given Minecraft world save file, look for ways to parse this."
source:
  name: "CTFtime writeup #39100"
  url: "https://ctftime.org/writeup/39100"
original_source: "https://xeunwa.github.io/b01lers-2024/#miscchest-mix"
ctf:
  name: "b01lers CTF 2024"
  year: 2024
  challenge: "chest-mix"
---

## Metadata

- **CTF:** b01lers CTF 2024
- **Task:** chest-mix
- **Author team:** 25ji
- **CTFtime tags:** misc, minecraft
- **CTFtime:** <https://ctftime.org/writeup/39100>
- **Original writeup:** <https://xeunwa.github.io/b01lers-2024/#miscchest-mix>

---
# misc/chest-mix  
> Here's a minecraft world, the flag is on a piece of paper in the the chest by spawn, it's hard to miss. Version 1.20

We are given Minecraft world save file, look for ways to parse this. I found a chunk extractor script that can extract contents from a region save. From there we can grep each region for any minecraft chunk/block we want.

<https://github.com/sudofox/minecraft-utils/blob/master/region-parser/region-parser.sh>

```bash  
# unzip the save file and under regions run the script for each .mca file  
./[region-parser.sh](http://region-parser.sh) r.0.-1.mca   
./[region-parser.sh](http://region-parser.sh) r.0.0.mca   
# ... 

# after unpacking all we can check each content if it contains chest / paper  
find . -name "*.nbt" -exec grep minecraft:chest {} \;  
find . -name "*.nbt" -exec grep minecraft:paper {} \;

# we can just search for the flag   
find . -name "*.nbt" -exec grep -a bctf {} \;

```  
![chest-mix](<https://xeunwa.github.io/b01lers-2024/image-2.png>)

**flag**: bctf{ch1st_ch2st_ch3st_ch4st_ch5st}
