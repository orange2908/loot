---
title: "Library - SAS CTF 2025 Quals"
category: "web"
type: "writeup"
tags: ["web", "minecraft", "library", "sas-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "This challenge was quite easy."
source:
  name: "CTFtime writeup #40319"
  url: "https://ctftime.org/writeup/40319"
original_source: "https://github.com/looy3/ctf-writeups/blob/main/SASCTF/minecraft/library.md"
ctf:
  name: "SAS CTF 2025 Quals"
  year: 2025
  challenge: "Library"
---

## Metadata

- **CTF:** SAS CTF 2025 Quals
- **Task:** Library
- **Author team:** Team14
- **CTFtime tags:** minecraft
- **CTFtime:** <https://ctftime.org/writeup/40319>
- **Original writeup:** <https://github.com/looy3/ctf-writeups/blob/main/SASCTF/minecraft/library.md>

---
This challenge was quite easy.

The description was " I know nobody likes reading, but this book worth reading from cover to cover. Already finished? Draw the conclusion. Version: 1.21." Based on the category (minecraft), the nature of the challenge was pretty obvious. Unzipping the attached .zip, I found the following contents:

Library % ls  
DIM1 DIM-1 advancements data entities icon.png level.dat level.dat_old playerdata poi region session.lock stats  
Pretty obviously a minecraft saves file. We not only have level data, an icon, region data, but we also have advancements (which are saved locally in minecraft). I moved it to my C:/Users/tjesau/AppData/Roaming/.minecraft/saves and booted up minecraft. Sure enough, minecraft recognized it as a valid save file. The world I loaded into looked like this: I hate alt text I hate alt text I hate alt text

As you can see, it was a single chunk with a ton of item frames with books containing the entirety of Moby Dick inside. I used to play around with command blocks a lot, so I quickly knew that these were entities. Thus, I navigated to the saves/Library/entities. Only one anvil file had a size indicating so much text: r.0.0.mca. It was 1.6MB, which indicates a looooot of entities or entity data. Having previously needed to delete entity data on a minecraft server (to prevent crashing/fix a corrupted save), I knew where to go to access it. I downloaded an app called NBTExplorer (In hindsight, use NBTStudio, it's way better), loaded the relevant mca file, and searched for values which might be related to the challenge. "SAS" revealed nothing but "{" gave me this:

Let's append { to the end of the new book and continue reading part 3 on page 19  
Ok, so the challenge is probably splitting all char into their own pages like this. Given that these books are parts of the same book (Moby Dick) and each minecraft book has a total of 100 pages maximum, "part" probably refers to the minecraft book and "page" is obviously the page. I looked at the 3rd book by searching for the value The Whale - 3 because in the title is stored as a value rather than name. Sure enough, there was an identical "Let's append" value. But I couldn't start at the middle of finding the flag. I can't look for "S" to confirm (because it's everywhere in the book) so I instead just cntrl+F for the value of "Let's append". I found the same pattern from every char. Knowing the flag started with SAS{, I skipped the first letters and began with the pointer from {. Eventually following these pointers (while noting it down in case I forgot) gave me the flag:

SAS{0ld_5ch00l_r37r13v4l_4ugm3nt3d_g3n3r4t10n}
