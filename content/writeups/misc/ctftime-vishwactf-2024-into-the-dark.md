---
title: "INTO THE DARK - VishwaCTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "dark", "vishwactf", "vishwactf-2024", "2024", "ctf-writeup"]
summary: "Inside heirloom.txt file you can see there is encrypted text at the bottom which requires password ."
source:
  name: "CTFtime writeup #39518"
  url: "https://ctftime.org/writeup/39518"
ctf:
  name: "VishwaCTF 2024"
  year: 2024
  challenge: "INTO THE DARK"
---

## Metadata

- **CTF:** VishwaCTF 2024
- **Task:** INTO THE DARK
- **Author team:** CyberCellVIIT
- **CTFtime:** <https://ctftime.org/writeup/39518>

---
### Solution:  
Inside heirloom.txt file you can see there is encrypted text at the bottom which requires password . You can get the password from the image itself as the hex addressed are provided .

From here you will get the password along with some additional characters --‘torlogowikisaveaspng’ just follow what it says and get the image (The last hex value when converted to decimal gives 2011 which helps you get the exact image) . Also apply the given transformation on the image .

Step 1 : Search for tor on google … open only the Wikipedia link

Step 2 : Rigth click on the tor logo …. And save the image as png file

Step 3 : Add the tor image in the world image using python code (OpenCV library) and get the flag image .  
(You may need to resize the tor logo image)

Step 4 : Enter the flag in the specified format

`FLAG: :- VishwaCTF{YCGU_34AY3D_70TH3_W05RlD}`
