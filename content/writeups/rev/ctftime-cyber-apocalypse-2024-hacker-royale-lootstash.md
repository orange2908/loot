---
title: "LootStash - Cyber Apocalypse 2024: Hacker Royale"
category: "rev"
subcategory: "static-analysis"
type: "writeup"
tags: ["rev", "binaryninja", "lootstash", "static-analysis", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "Hi All, I saw while ago writeup by Cyber R0nin (<https://ctftime.org/task/27826>) and I like it."
source:
  name: "CTFtime writeup #39342"
  url: "https://ctftime.org/writeup/39342"
original_source: "https://medium.com/@embossdotar/ctf-writeup-cyber-apocalypse-2024-hacker-royale-reversing-lootstash-60f485a11142"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "LootStash"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** LootStash
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39342>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-cyber-apocalypse-2024-hacker-royale-reversing-lootstash-60f485a11142>

---
Hi All, I saw while ago writeup by Cyber R0nin (<https://ctftime.org/task/27826>) and I like it. It's correct way - faster way (use grep etc).

I was wondering that should I add here my writeup, but yeah, I decided to add this, mainly because I hope it can be useful for people without Linux in use (or in general, similar tools like used there) and I hope someone also can meet new tools, solutions (it will show alternate way to solve this).

So, thank you for your time and short writeup from me below:

As you can see, with this task you have to download some files (rev_lootstash.zip). It is “stash” file.

You can check this in different ways, I will show you here two methods — online, without need of installing additional tools (browser required:D).

(1) FILExt — The File Extension Source: <https://filext.com/>  
As you can see from this site — description: “[FILExt.com](http://FILExt.com) is the file extension source. Here you’ll find a collection of file extensions; many linked to the programs that created the files”

(2) Binary Ninja: https://binary.ninja/ “Binary Ninja is a modern reverse engineering platform with a scriptable and extensible decompiler”

Referring to the option (1 — FILExt):

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*S2zutkH0QaqK6tCy9_bYtQ.png>)

Step 1. Source: <https://filext.com/>

![](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*rXLtKhNvob_q2fFEPSlJoQ.png>)

Step 2. Source: <https://filext.com/>

Referring to the option (2 — Binary Ninja):

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*8JJ8vlVC4dBxaM1T4NxA5Q.png>)

Source: https://binary.ninja/

FLAG: **HTB{n33dl3_1n_a_l00t_stack}**

I hope you enjoy!
