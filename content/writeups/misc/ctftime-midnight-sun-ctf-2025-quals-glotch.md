---
title: "glotch - Midnight Sun CTF 2025 Quals"
category: "misc"
type: "writeup"
tags: ["misc", "glotch", "midnight-sun-ctf-2025-quals", "2025", "ctf-writeup"]
summary: "It seems the challenge wants us to play and solve.Don’t be fooled by its apparent simplicity."
source:
  name: "CTFtime writeup #40375"
  url: "https://ctftime.org/writeup/40375"
original_source: "https://sevcankazdag.com.tr/midnight-sun-ctf-2025-write-up-glotch/"
ctf:
  name: "Midnight Sun CTF 2025 Quals"
  year: 2025
  challenge: "glotch"
---

## Metadata

- **CTF:** Midnight Sun CTF 2025 Quals
- **Task:** glotch
- **Author team:** kuzukaykayi
- **CTFtime tags:** misc
- **CTFtime:** <https://ctftime.org/writeup/40375>
- **Original writeup:** <https://sevcankazdag.com.tr/midnight-sun-ctf-2025-write-up-glotch/>

---
It seems the challenge wants us to play and solve.Don’t be fooled by its apparent simplicity.

Although it was not visible because the CTF had ended, the flag could be seen illegibly in the middle of the site ?

<html lang="en">  
<head>  
<meta charset="UTF-8">  
<meta name="viewport" content="width=device-width, initial-scale=1.0">  
<title>Glotchy Flag</title>  
<style>  
body, html {  
margin: 0;  
padding: 0;  
width: 100%;  
height: 100%;  
overflow: hidden;  
background-image: url('/bg.gif');  
background-size: cover;  
background-position: center;  
background-repeat: no-repeat;  
display: flex;  
align-items: center;  
justify-content: center;  
}  
.image-container {  
width: 90%;  
max-width: 2100px;  
display: flex;  
align-items: center;  
justify-content: center;  
}  
#challengeImage {  
max-width: 100%;  
height: auto;  
object-fit: contain;  
image-rendering: pixelated; /* Keeps pixels sharp */  
image-rendering: -moz-crisp-edges;  
image-rendering: crisp-edges;  
}  
</style>  
</head>  
<body>  
<div class="image-container">  
![](https://ctftime.org/flag.png)  
</div>  
</body>  
</html>

Of course, download /flag.png (free flag is not cheap) and see what’s going on.  
flag.png

It’s definitely a flag that’s not fully understood. It seems possible to access the flag by changing the image using image manipulation tools.

But flag.png still does not give a full flag. So I decided to try another image tool. I definitely tried a lot of different flags and finally decided on this one.  
FLAG: midnight{YUM_SCR4MBL3D_3G6Z!!} 

Orijinal Writeup: <https://sevcankazdag.com.tr/midnight-sun-ctf-2025-write-up-glotch/>
