---
title: "bfail - Nullcon Goa HackIM 2025 CTF"
category: "web"
type: "writeup"
tags: ["bcrypt", "web", "bfail", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "mH4ck3r0n3 Ethical Hacking/CTFs/Jeopardy/Nullcon-Goa-HackIM-CTF-2025/Web"
source:
  name: "CTFtime writeup #39941"
  url: "https://ctftime.org/writeup/39941"
original_source: "https://mh4ck3r0n3.github.io/posts/2025/02/07/bfail/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "bfail"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** bfail
- **Author team:** QnQSec
- **CTFtime tags:** bcrypt, web
- **CTFtime:** <https://ctftime.org/writeup/39941>
- **Original writeup:** <https://mh4ck3r0n3.github.io/posts/2025/02/07/bfail/>

---
# 🌐 Bfail

## A detailed write-up of the Web challenge 'Bfail' from NullCon Goa HackIM CTF - 2025

[__mH4ck3r0n3](https://mh4ck3r0n3.github.io/ "Author")[ __Ethical Hacking/CTFs/Jeopardy/Nullcon-Goa-HackIM-CTF-2025/Web](https://mh4ck3r0n3.github.io/categories/ethical-hacking/ctfs/jeopardy/nullcon-goa-hackim-ctf-2025/web/)

__ 07/02/2025  __465 words __3 minutes

Contents __

[ ![/images/NullCon-Goa-HackIM-CTF-2025/Bfail/challenge_presentation.png](https://mh4ck3r0n3.github.io/svg/loading.min.svg) ](https://mh4ck3r0n3.github.io/images/NullCon-Goa-HackIM-CTF-2025/Bfail/challenge_presentation.png "Challenge Presentation")Challenge Presentation

# 📊 Challenge Overview

> Category | Details | Additional Info  
> ---|---|---  
> 🏆 Event | Nullcon Goa HackIM 2025 CTF | [Event Link](https://ctf.nullcon.net/challenges#Bfail-58)  
> 🔰 Category | Web | 🌐  
> 💎 Points | 500 | Out of 500 total  
> ⭐ Difficulty | 🟢 Easy | Personal Rating: 3/10  
> 👤 Author | @gehaxelt | [Profile]()  
> 🎮 Solves (At the time of flag submission) | 21 | XX% solve rate  
> 📅 Date | 01-02-2025 | Nullcon Goa HackIM 2025 CTF Day X  
> 🦾 Solved By | mH4ck3r0n3 | Team: QnQSec  
  
## 📝 Challenge Information

> To ‘B’ secure or to ‘b’ fail? Strong passwords for admins are always great, right? http://52.59.124.14:5013

## 🎯 Challenge Files & Infrastructure

### Provided Files

> 

```
>     1
>     
```
> 
> | 

```
>     Files: None
>     
```  
>   
> ---|---  
  
# 🔍 Initial Analysis

## First Steps

> Initially, the website appears as follows:
> 
> [ ![/images/NullCon-Goa-HackIM-CTF-2025/Bfail/site_presentation.png](https://mh4ck3r0n3.github.io/svg/loading.min.svg) ](https://mh4ck3r0n3.github.io/images/NullCon-Goa-HackIM-CTF-2025/Bfail/site_presentation.png "Site Presentation")Site Presentation
> 
> While inspecting the code with `ChromeDevTools`, I found this:
> 
> [ ![/images/NullCon-Goa-HackIM-CTF-2025/Bfail/source.png](https://mh4ck3r0n3.github.io/svg/loading.min.svg) ](https://mh4ck3r0n3.github.io/images/NullCon-Goa-HackIM-CTF-2025/Bfail/source.png "Page Source")Page Source
> 
> Interesting, so by visiting `/source`, we will have the source code of the page:
> 
> [ ![/images/NullCon-Goa-HackIM-CTF-2025/Bfail/source_code.png](https://mh4ck3r0n3.github.io/svg/loading.min.svg) ](https://mh4ck3r0n3.github.io/images/NullCon-Goa-HackIM-CTF-2025/Bfail/source_code.png "Source Code")Source Code
> 
> As we can see, it leaks the password in bytes:
> 
>   * `\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76`
> 

> 
> and the full password in hash:
> 
>   * `$2b$12$8bMrI6D9TMYXeMv8pq8RjemsZg.HekhkQUqLymBic/cRhiKRa3YPK`
> 

> 
> and honestly, this comment is also very interesting:

```
>     1
>     2
>     3
>     
```
> 
> | 

```
>     # This is super strong! The password was generated quite securely. Here are the first 70 bytes, since you won't be able to brute-force the rest anyway...  
>     
>     strongpw = bcrypt.hashpw(os.urandom(128),bcrypt.gensalt()) # >>> strongpw[:71]
>     
```  
>   
> ---|---  
>   
> As we can see, the leak is of the first 70 bytes of the password, while a total of 71 bytes are used. Let’s proceed with the exploit.

## 🔬 Vulnerability Analysis

### Potential Vulnerabilities

>   * __Partial Hash Exposure (bcrypt)
> 


# 🎯 Solution Path

## Exploitation Steps

### Initial setup

> The exploit was based on brute-forcing that remaining byte since `71-70=1`. That’s a total of `256` combinations (nothing too challenging for a brute force). Once completed, we have the full password, which we will obviously verify by converting it into a hash and comparing it with the previously obtained hash.

### Exploitation

> I wrote a Python script to do all of this, and then I executed it:

```
>     1
>     
```
> 
> | 

```
>     python exploit.py
>     
```  
>   
> ---|---  
>   
> I also sent the request directly to the server using `Http`, since a simple `GET` or `POST` returned `Method Not Allowed`. I then took the server’s response, extracted the flag using a regex, and subsequently printed it.

### Flag capture

> [ ![/images/NullCon-Goa-HackIM-CTF-2025/Bfail/automated_flag.png](https://mh4ck3r0n3.github.io/svg/loading.min.svg) ](https://mh4ck3r0n3.github.io/images/NullCon-Goa-HackIM-CTF-2025/Bfail/automated_flag.png "Manual Flag")Manual Flag

# 🛠️ Exploitation Process

## Approach

> The exploit literally follows the procedure described above:
> 
>   * [__Exploit](https://mh4ck3r0n3.github.io/resources/NullCon-Goa-HackIM-CTF-2025/Bfail/exploit.py)
> 


# 🚩 Flag Capture

> __Flag __
> 
> #### 
>
>> ## Proof of Execution

> [ ![/images/NullCon-Goa-HackIM-CTF-2025/Bfail/automated_flag.png](https://mh4ck3r0n3.github.io/svg/loading.min.svg) ](https://mh4ck3r0n3.github.io/images/NullCon-Goa-HackIM-CTF-2025/Bfail/automated_flag.png "Automated Flag")Automated Flag _Screenshot of successful exploitation_

# 🔧 Tools Used

> Tool | Purpose  
> ---|---  
> Python | Exploit  
  
# 💡 Key Learnings

> ### New Knowledge
> 
> I discovered that if you know part of the hash with bcrypt, you can perform a brute force.
> 
> ### Skills Improved
> 
>   * __Binary Exploitation
>   * __Reverse Engineering
>   * __Web Exploitation
>   * __Cryptography
>   * __Forensics
>   * __OSINT
>   * __Miscellaneous
> 


* * *

# 📊 Final Statistics

Metric | Value | Notes  
---|---|---  
Time to Solve | 00:08 | From start to flag  
Global Ranking (At the time of flag submission) | 9/535 | Challenge ranking  
Points Earned | 500 | Team contribution  
  
_Created: 01-02-2025 • Last Modified: 01-02-2025_ _Author: mH4ck3r0n3 • Team: QnQSec_

Updated on 07/02/2025

[Read Markdown](https://mh4ck3r0n3.github.io/posts/2025/02/07/bfail/index.md)

[__](javascript:void\(0\); "Share on Twitter")[__](javascript:void\(0\); "Share on Facebook")[__](javascript:void\(0\); "Share on Linkedin")[__](javascript:void\(0\); "Share on WhatsApp")[__](javascript:void\(0\); "Share on Hacker News")[__](javascript:void\(0\); "Share on Reddit")[__](javascript:void\(0\); "Share on Line")[__](javascript:void\(0\); "Share on 微博")

__[🔓 Partial Password Exposure](https://mh4ck3r0n3.github.io/tags/partial-password-exposure/), [🔑 bcrypt](https://mh4ck3r0n3.github.io/tags/bcrypt/), [🌐 Web Exploitation](https://mh4ck3r0n3.github.io/tags/web-exploitation/) [Back](javascript:void\(0\);) | [Home](https://mh4ck3r0n3.github.io/)

[__🌐 Submission](https://mh4ck3r0n3.github.io/posts/2025/02/06/submission/ "🌐 Submission") [🌐 Crahp __](https://mh4ck3r0n3.github.io/posts/2025/02/07/crahp/ "🌐 Crahp")
