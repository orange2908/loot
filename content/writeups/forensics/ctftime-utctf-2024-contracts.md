---
title: "Contracts - UTCTF 2024"
category: "forensics"
type: "writeup"
tags: ["forensics", "contracts", "utctf", "utctf-2024", "2024", "ctf-writeup"]
summary: "Given a PDF with the context that it was signed with the flag by accident, so looking into PDF extraction I find pdfly which seems to have capabilities to extract images and other data from a PDF."
source:
  name: "CTFtime writeup #39082"
  url: "https://ctftime.org/writeup/39082"
original_source: "https://seall.dev/posts/utctf2024#contracts"
ctf:
  name: "UTCTF 2024"
  year: 2024
  challenge: "Contracts"
---

## Metadata

- **CTF:** UTCTF 2024
- **Task:** Contracts
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39082>
- **Original writeup:** <https://seall.dev/posts/utctf2024#contracts>

---
# Forensics/Contracts  
> > Magical contracts are hard. Occasionally, you sign with the flag instead of your name. It happens.

Given a PDF with the context that it was signed with the flag by accident, so looking into PDF extraction I find [`pdfly`](<https://github.com/py-pdf/pdfly>) which seems to have capabilities to extract images and other data from a PDF. I install pdfly with pipx to start.

```  
$ pipx install pdfly  
...  
installed package pdfly 0.3.1, installed using Python 3.9.19  
These apps are now globally available  
\- pdfly  
done! ✨ ? ✨  
```

Afterwards I use the `extract-images` function to pull out the images inside the PDF.

```  
$ pdfly extract-images contract.pdf  
Extracted 6 images:  
\- 0-Image5.jpg  
\- 1-Image5.jpg  
\- 2-Image5.jpg  
\- 2-fzImg0.png  
\- 2-fzImg1.png  
\- 2-fzImg2.png  
```

One of the images, `2-fzImg1.png`, contains the flag!

![contracts](https://seall.dev/images/ctfs/utctf2024/contracts.png)

Flag: `utflag{s1mple_w1z4rding_mist4k3s}`
