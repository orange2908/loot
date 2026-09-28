---
title: "My Third CTF - NahamCon CTF 2025"
category: "misc"
subcategory: "classical"
type: "writeup"
tags: ["misc", "caesar", "wordlists", "third", "classical", "nahamcon-ctf", "nahamcon-ctf-2025", "2025", "ctf-writeup"]
summary: "Since this is part 3, we'll probably need to ROT one more time (ROT3) now."
source:
  name: "CTFtime writeup #40300"
  url: "https://ctftime.org/writeup/40300"
original_source: "https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_third_ctf/"
ctf:
  name: "NahamCon CTF 2025"
  year: 2025
  challenge: "My Third CTF"
---

## Metadata

- **CTF:** NahamCon CTF 2025
- **Task:** My Third CTF
- **Author team:** CryptoCat
- **CTFtime:** <https://ctftime.org/writeup/40300>
- **Original writeup:** <https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_third_ctf/>

---
Since this is part 3, we'll probably need to ROT one more time (ROT3) now.

![](<https://cryptocat.me/blog/ctf/2025/nahamcon/web/my_third_ctf/images/rotated-wordlist-initial-failure.png>)

Didn't find anything, this challenge says "incrementally worse" so maybe we need to keep rotating? I tried every ROT up to and including ROT13, no luck.

Thinking about the hint again - maybe it means each word in the wordlist is rotated by a different value?  
```  
word1 -> ROT1  
word2 -> ROT2  
word3 -> ROT3  
etc..  
```

Unfortunately, this didn't work either! I didn't solve this one but it turns out you needed to try all iterations of ROT with each word, for each directory, e.g.  
```python  
/qbhf # ROT1: page  
/qbhf/oguucig # ROT2: message  
/qbhf/oguucig/wrnhq # ROT3: token  
/qbhf/oguucig/wrnhq/lewl # ROT4: hash  
```

Visiting `/qbhf/oguucig/wrnhq/lewl` would recover the flag!

Flag: `flag{afd87cae63c08a57db7770b4e52081d3}`
