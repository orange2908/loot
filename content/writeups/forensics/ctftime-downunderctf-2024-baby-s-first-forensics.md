---
title: "Baby’s First Forensics - DownUnderCTF 2024"
category: "forensics"
subcategory: "network"
type: "writeup"
tags: ["wireshark", "baby", "first", "forensics", "network", "downunderctf", "downunderctf-2024", "2024", "ctf-writeup"]
summary: "As we can see, it contains over than 5,700 packets."
source:
  name: "CTFtime writeup #39334"
  url: "https://ctftime.org/writeup/39334"
original_source: "https://medium.com/@embossdotar/ctf-writeup-downunderctf-2024-babys-first-forensics-39de2a121eb7"
ctf:
  name: "DownUnderCTF 2024"
  year: 2024
  challenge: "Baby’s First Forensics"
---

## Metadata

- **CTF:** DownUnderCTF 2024
- **Task:** Baby’s First Forensics
- **Author team:** ctfrrteam
- **CTFtime:** <https://ctftime.org/writeup/39334>
- **Original writeup:** <https://medium.com/@embossdotar/ctf-writeup-downunderctf-2024-babys-first-forensics-39de2a121eb7>

---
Hi All,

As we can see, it contains over than 5,700 packets. I suppose that you don’t want to check them all:P

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*DOHOsXV9Ve3l9kQld4dkxQ.png>)

[Wireshark](<https://github.com/wireshark/wireshark>) and file’s number of packets, source: DownUnderCTF 2024 — Baby’s First Forensics

Strings utility connected with grep for instance is often quite good idea.

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*u1EuUv8VvVr7crCNaV1Ybw.png>)

Checking the file with strings and grep utilities — nope, source: DownUnderCTF 2024

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*eNdKGCxcaa5tJR1CNHvYnQ.png>)

Checking the file with strings and grep utilities — nope (in these examples), source: DownUnderCTF 2024

But unfortunately, not this time:D At least, not in this way.

Let’s use awesome [Wireshark](<https://www.wireshark.org/>) again! Sorted by ID (No. — number):

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*Vdmd1_h-m3gOfRwehmKOjg.png>)

Wireshark in action — sorted by ID (No. — number), source: DownUnderCTF 2024

And now, sorted by Protocols:

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*QLmHlx0p3AzqV66h04AhpQ.png>)

Wireshark in action — sorted by Protocols, source: DownUnderCTF 2024

Voilà!

Flag — solution: **DUCTF{nikto_2.1.6}**

Bonus info!

![](<https://miro.medium.com/v2/resize:fit:720/format:webp/1*4nIA0CglRz_o02kVGUZDDA.png>)

Flag from other approach, source: DownUnderCTF 2024

You could also take a Flag using strings utility and grep ‘User-Agent’. 

Bonus info #2!

Additional resources:

<https://github.com/sullo/nikto/>

<https://www.freecodecamp.org/news/an-introduction-to-web-server-scanning-with-nikto>

<https://en.wikipedia.org/wiki/Nikto_(vulnerability_scanner)>

<https://www.cisa.gov/resources-tools/services/nikto>

I hope you enjoy!
