---
title: "playful-puppy - ImaginaryCTF 2024"
category: "misc"
type: "writeup"
tags: ["minecraft", "misc", "playful-puppy", "imaginaryctf", "imaginaryctf-2024", "2024", "ctf-writeup"]
summary: "Let's look at all available hints:"
source:
  name: "CTFtime writeup #39335"
  url: "https://ctftime.org/writeup/39335"
original_source: "https://github.com/Team-Kirby/ictf-2024-writeups/blob/main/misc/playful-puppy/solve.txt"
ctf:
  name: "ImaginaryCTF 2024"
  year: 2024
  challenge: "playful-puppy"
---

## Metadata

- **CTF:** ImaginaryCTF 2024
- **Task:** playful-puppy
- **Author team:** Team Kirby
- **CTFtime tags:** minecraft, misc
- **CTFtime:** <https://ctftime.org/writeup/39335>
- **Original writeup:** <https://github.com/Team-Kirby/ictf-2024-writeups/blob/main/misc/playful-puppy/solve.txt>

---
Let's look at all available hints:  
\- img.png: photo of a black dog with blue collar  
\- \world\advancements: "DataVersion": 3953  
\- The given minecraft version is 1.21  
\- So blue collar is id: 11  
\- \world\datapacks\Dog data\data\test\function\dog.mcfunction: bunch of filtered summon info but provides information on the data field for dog in minecraft  
\- The dog is a minecraft:wolf  
\- Color field would be variant:black

Now let's download and use NBTExplorer:  
\- Expand the "world" and click on "entities"  
\- Go to "Search" -> "Find..." and enter:  
\- Name: "id", Value: "CollarColor:11"

Under each search result, look for:  
\- id: "minecraft:wolf"  
\- variant: "minecraft:black"  
\- has the entry "CustomName"

The flag is ictf{6ed247d7539bb3bf}
