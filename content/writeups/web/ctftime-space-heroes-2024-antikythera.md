---
title: "antikythera - Space Heroes 2024"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "python", "jinja2", "antikythera", "space-heroes", "space-heroes-2024", "2024", "ctf-writeup"]
summary: "No source file(s) was given."
source:
  name: "CTFtime writeup #39054"
  url: "https://ctftime.org/writeup/39054"
original_source: "https://github.com/pspspsps-ctf/writeups/tree/main/2024/Space%20Heroes%202024/Web/antikythera"
ctf:
  name: "Space Heroes 2024"
  year: 2024
  challenge: "antikythera"
---

## Metadata

- **CTF:** Space Heroes 2024
- **Task:** antikythera
- **Author team:** pspspsps
- **CTFtime tags:** ssti, python, jinja2
- **CTFtime:** <https://ctftime.org/writeup/39054>
- **Original writeup:** <https://github.com/pspspsps-ctf/writeups/tree/main/2024/Space%20Heroes%202024/Web/antikythera>

---
# antikythera

> Lost in the labyrinthine calculations of planetary motion, I stumbled upon an anomaly. Ancient Greek symbols, not our modern equations, whispered of celestial mechanics. Driven by a scientist's curiosity, I cracked their cryptic code. The unearthed knowledge, a testament to their forgotten ingenuity, fueled the creation of the "Greek Astronomical Calculator." This isn't just a tool for prediction; it's a portal to a bygone era's uncanny understanding of the cosmos  
>   
> <http://antikythera.martiansonly.net>  
>   
> Author: bl4ckp4r4d1s3

Solution:

No source file(s) was given. Let's check the challenge site...

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/1.png>)

Oh, displays via iframe, let's grab the link and access that directly instead.

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/2.png>)

Hmm, nothing striking in the source.

Let's try to submit `'` to initiate an error with SQL.

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/3.png>)

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/4.png>)

Oh, it only displayed the single quote back.

How about SSTI focusing on Python since it showed `gunicorn` as the webserver being used...

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/5.png>)

Oh, that worked!

Let's try `{{config.items()}}`

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/6.png>)

Hmm, it's not hidden there. Time to RCE!

Let's display the builtins as a test...`{{ self.__init__.__globals__.__builtins__ }}`

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/7.png>)

Cool, we can use `__import__`, let's list the files via `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}`!

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/8.png>)

There's the target file! Time to read it via `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}`!!

![image](<https://raw.githubusercontent.com/pspspsps-ctf/writeups/main/2024/Space%20Heroes%202024/Web/antikythera/9.png>)

Boom!

Flag: `shctf{SSTI_1s_m0r3_fun_!_Wh3n_1t_b3c0m3s_RC3!}`
