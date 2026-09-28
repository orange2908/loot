---
title: "Beep Boop - RITSEC CTF 2024"
category: "misc"
type: "writeup"
tags: ["misc", "cyberchef", "base64", "beep", "boop", "ritsec-ctf", "ritsec-ctf-2024", "2024", "ctf-writeup"]
summary: "We can suppose that we should get into interaction with mentioned site: https://beep-boop.ctf.ritsec.club/"
source:
  name: "CTFtime writeup #39349"
  url: "https://ctftime.org/writeup/39349"
original_source: "https://medium.com/@embossdotar/ctf-writeup-ritctf-2024-beep-boop-f07ef3f83bd5"
ctf:
  name: "RITSEC CTF 2024"
  year: 2024
  challenge: "Beep Boop"
---

## Metadata

- **CTF:** RITSEC CTF 2024
- **Task:** Beep Boop
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39349>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-ritctf-2024-beep-boop-f07ef3f83bd5>

---
Hi All,

We can suppose that we should get into interaction with mentioned site: https://beep-boop.ctf.ritsec.club/

After quick manual checking, you will get to know that there is not interesting item — the Flag (from CTF task point of view).

For example ‘About us’ gives “<https://geometrydash.io/about-us”> which is external page (versus “https://beep-boop.ctf.ritsec.club”).

Let’s make little bit larger our manual recon here — check [/robots.txt](<https://en.wikipedia.org/wiki/Robots.txt>)

So, take a look at https://beep-boop.ctf.ritsec.club/robots.txt

Good idea! Exists. We can see there:

```  
“User-agent: *  
Disallow: / # Disallow all robots from indexing any content

UlN7ZzMwbTJ0eV9kQHNoXyFzX2whZjN9"  
```

Now, you can use [CyberChef](<https://gchq.github.io/CyberChef/>) tool for instance:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*IzDmWeVqCi2QRs3sPVhjcQ.png>)

Source: CyberChef

You can see that [Base64](<https://en.wikipedia.org/wiki/Base64>) was used there.

In the same while, you can get a Flag!

Flag: **RS{g30m2ty_d@sh_!s_l!f3}**

I hope you enjoy!
