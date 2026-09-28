---
title: "Tiny Flag - V1t CTF 2025"
category: "web"
type: "writeup"
tags: ["web", "tiny", "v1t-ctf", "v1t-ctf-2025", "2025", "ctf-writeup"]
summary: "We are presented with a simple website that appears purely decorative, containing nothing of immediate relevance."
source:
  name: "CTFtime writeup #40476"
  url: "https://ctftime.org/writeup/40476"
original_source: "https://ctf.dvzr.io/competitions/v1t-ctf-2025/tiny-flag/"
ctf:
  name: "V1t CTF 2025"
  year: 2025
  challenge: "Tiny Flag"
---

## Metadata

- **CTF:** V1t CTF 2025
- **Task:** Tiny Flag
- **Author team:** CaptureTheFat
- **CTFtime:** <https://ctftime.org/writeup/40476>
- **Original writeup:** <https://ctf.dvzr.io/competitions/v1t-ctf-2025/tiny-flag/>

---
## Connections

  * ⇩ https://tommytheduck.github.io/tiny_flag/


## Recon

We are presented with a simple website that appears purely decorative, containing nothing of immediate relevance.

![Landing page](https://ctf.dvzr.io/assets/files/v1t-ctf-2025/tiny-flag/web.png)

## Flag capture

What is the smallest element on a webpage that can conceal a flag in plain sight? It’s larger than a single pixel, but only just: the favicon!

![Browser tab](https://ctf.dvzr.io/assets/files/v1t-ctf-2025/tiny-flag/tag.png)

By opening and zooming in on <https://tommytheduck.github.io/tiny_flag/favicon.ico>, you can clearly see the flag.

![Flag](https://ctf.dvzr.io/assets/files/v1t-ctf-2025/tiny-flag/flag.png)

```
    Flag: V1T{T1NY_ICO}
```

[← Back to V1t CTF 2025](https://ctf.dvzr.io/competitions/v1t-ctf-2025/)
