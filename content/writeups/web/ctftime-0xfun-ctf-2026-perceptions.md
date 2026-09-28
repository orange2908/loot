---
title: "Perceptions - 0xFUN CTF 2026"
category: "web"
type: "writeup"
tags: ["web", "perceptions", "0xfun-ctf", "0xfun-ctf-2026", "2026", "ctf-writeup"]
summary: "Perceptions | 0xFun CTF 2026"
source:
  name: "CTFtime writeup #40672"
  url: "https://ctftime.org/writeup/40672"
original_source: "https://axl0t0l.github.io/posts/0xfun/Perceptions"
ctf:
  name: "0xFUN CTF 2026"
  year: 2026
  challenge: "Perceptions"
---

## Metadata

- **CTF:** 0xFUN CTF 2026
- **Task:** Perceptions
- **Author team:** 0xDr460nZ
- **CTFtime:** <https://ctftime.org/writeup/40672>
- **Original writeup:** <https://axl0t0l.github.io/posts/0xfun/Perceptions>

---
Perceptions | 0xFun CTF 2026 __

Contents __

Perceptions | 0xFun CTF 2026

__

[![](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)](https://axl0t0l.github.io/assets/img/logos/axl0t0l.png)

##  Overview __

  * **Platform:** [0xFun](https://ctf.0xfun.org/)
  * **Challenge:** [Perceptions](https://ctf.0xfun.org/challenges#Perceptions-60)
  * **Categories:** Web
  * **Rating:** 9/10
  * **Difficulty:** Easy
  * **Sovling Time:** ~20 Minutes


## Challenge __

> “ _Take a look at the blog I created! It has a neat backend and, interestingly, seems to use fewer ports._ ”

## Walkthrough __

### Recon __

The website looks very normal, just we have a login page, later on that later.

Something looks fishy in `Secret Post`, by viewing the page source we can see some credentials: [![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/creds.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/creds.png)

### Solution Approach __

> “ _Flag format:`0xfun{}`_”

From recon we can try credentials we found in the login page

> Username is `Charlie`, you can see this at top of the site.

[![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/site.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/site.png)

Nothing has changes….. Wait they mentioned in a blog something about many things running on many ports, lets try to SSH into the server with the provided credentials.

____

`

```
    1
```

| 

```
    ssh -p 48385 Charlie@chall.0xfun.org
```  
  
---|---  
`

[![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/shell.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/shell.png)

And it worked!! Lets find the flag.

[![](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/flag.png)](https://axl0t0l.github.io/assets/img/posts/2026-02-14-Perceptions/flag.png)

#### Flag __

`0xfun{p3rsp3c71v3.15.k3y}`

**_Hope you enjoined the writeup, Don’t forget to leave a comment or a star on the[github repo](https://github.com/Axl0t0l) (;_**

__[0xFun CTF 2026](https://axl0t0l.github.io/categories/0xfun-ctf-2026/), [WarmUp](https://axl0t0l.github.io/categories/warmup/)

__[Web](https://axl0t0l.github.io/tags/web/)

This post is licensed under [ CC BY 4.0 ](https://creativecommons.org/licenses/by/4.0/) by the author.

Share [ __](https://twitter.com/intent/tweet?text=Perceptions%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xfun%2FPerceptions "Twitter") [ __](https://www.facebook.com/sharer/sharer.php?title=Perceptions%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l&u=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xfun%2FPerceptions "Facebook") [ __](https://t.me/share/url?url=https%3A%2F%2Faxl0t0l.github.io%2Fposts%2F0xfun%2FPerceptions&text=Perceptions%20%7C%200xFun%20CTF%202026%20-%20Axl0t0l "Telegram") __
