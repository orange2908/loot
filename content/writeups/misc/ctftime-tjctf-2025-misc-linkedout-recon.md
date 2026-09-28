---
title: "misc/linkedout-recon - TJCTF 2025"
category: "misc"
subcategory: "image"
type: "writeup"
tags: ["misc", "osint", "lsb", "zsteg", "linkedout-recon", "image", "tjctf", "tjctf-2025", "2025", "ctf-writeup"]
summary: "1\\. We have a pdf file with infomation about ALEX MARMADUKE : 6560 Braddock Rd, Alexandria, VA 22312 | ctf.tjctf.org | [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)"
source:
  name: "CTFtime writeup #40305"
  url: "https://ctftime.org/writeup/40305"
ctf:
  name: "TJCTF 2025"
  year: 2025
  challenge: "misc/linkedout-recon"
---

## Metadata

- **CTF:** TJCTF 2025
- **Task:** misc/linkedout-recon
- **Author team:** RAT?!
- **CTFtime tags:** misc, osint
- **CTFtime:** <https://ctftime.org/writeup/40305>

---
1\. We have a pdf file with infomation about **ALEX MARMADUKE** : `6560 Braddock Rd, Alexandria, VA 22312 | [ctf.tjctf.org](http://ctf.tjctf.org) | [[email protected]](https://ctftime.org/cdn-cgi/l/email-protection)`  
2\. Using search engine like `Duck Duck Go` or tool like `Sherlock` to easy find link github of ALEX `<https://github.com/ctf-researcher-alex/>`  
3\. Follow link in `DEFCON 2023 Notes`, we have `<https://www.notion.so/SIGINT-Workflow-Summary-20b5e464bf3580378cacd452c1174941>` and `<https://drive.google.com/file/d/1LAh1UUpHlfeagrN72dL_M9AsS8PRRGVz/view?usp=sharing>`  
4\. Download file `.zip`, crack it with `john+rockyou` and find the password is `princess`  
5\. Using tool like `zsteg` or `[aperisolve.com](http://aperisolve.com)` to get the flag  
```  
(myvenv) jayce@Jayce:~$ zsteg encoded.png  
b1,rgb,lsb,xy .. text: "29:marmaduke:tjctf{linkedin_out}"  
b2,r,lsb,xy .. text: "QUeVAUie"  
b2,bgr,lsb,xy .. text: "M\r&MIBMI"  
b2,rgba,lsb,xy .. text: "k[7sssS'o'"  
b3,g,lsb,xy .. text: "Z%DJ) J%$"  
b3,g,msb,xy .. text: "mI\"-R %\n"  
b3,b,msb,xy .. file: OpenPGP Secret Key  
b3,rgb,lsb,xy .. file: Tower/XP rel 3 object  
b4,b,msb,xy .. text: "]=S=Y=U]Y"  
```  
6\. Flag: `tjctf{linkedin_out}`
