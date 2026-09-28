---
title: "Math Gone Wrong - IRON CTF 2024"
category: "cloud"
subcategory: "azure"
type: "writeup"
tags: ["cloud", "floating-point", "azure", "math", "gone", "wrong", "iron-ctf", "iron-ctf-2024", "2024", "ctf-writeup"]
summary: "Challenge description is like below:"
source:
  name: "CTFtime writeup #39539"
  url: "https://ctftime.org/writeup/39539"
original_source: "https://medium.com/@embossdotar/ctf-writeup-iron-ctf-2024-math-gone-wrong-ccc0b463e38f"
ctf:
  name: "IRON CTF 2024"
  year: 2024
  challenge: "Math Gone Wrong"
---

## Metadata

- **CTF:** IRON CTF 2024
- **Task:** Math Gone Wrong
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39539>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-iron-ctf-2024-math-gone-wrong-ccc0b463e38f>

---
Hi All,

Challenge description is like below:

"Bob: Computers are excellent in maths  
CTFplayer: No!!  
Bob: prove me!!  
Author: AbdulHaq

nc misc.1nf1n1ty.team 30011 "

There is no attachment/s.

So, need to connect via [netcat](<https://en.wikipedia.org/wiki/Netcat/>) with given source.

Quick note — if you want to solve it yourself, give yourself some time now — later it will be too late, because you will already see the solution; that means no such fun:P

The sample of interaction you can see below:

![img1](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*wnYIeqOOCfs0N9VHZntYpQ.png>)

Initial interaction, source: IRON CTF 2024

Initial interaction, source: IRON CTF 2024  
It seems like this challenge is asking for two numbers  
n1 and n2  
where the following condition holds true:

n1*10+n2*10 ≠ (n1+n2)*10

You can/could check many use cases. I like this task, because as a [Software Engineer](<https://en.wikipedia.org/wiki/Software_engineering>) I was fixing connected with this [PBI](<https://learn.microsoft.com/en-us/azure/devops/boards/work-items/agile-glossary?view=azure-devops>) issue years ago where the point was [floating point error](<https://stackoverflow.com/questions/588004/is-floating-point-math-broken>).

![img2](<https://miro.medium.com/v2/resize:fit:640/format:webp/1*TixDpnO33hkOODTFvGeQTA.png>)

Solution — flag, source: IRON CTF 2024

Flag:

**ironCTF{s1mpl3_r3m4ind3r_70_b3w4r3_0f_fl047ing_p0in7_3rr0r}**

I hope you enjoy! 

Best wishes,
