---
title: "sess.io - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "prng"
type: "writeup"
tags: ["md5", "web", "crypto", "mt19937", "sess", "prng", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "We have this code that generates our \"secure session\" strings."
source:
  name: "CTFtime writeup #39846"
  url: "https://ctftime.org/writeup/39846"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "sess.io"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** sess.io
- **Author team:** DIONLABS
- **CTFtime tags:** md5, web, crypto
- **CTFtime:** <https://ctftime.org/writeup/39846>

---
### Explanation

```

```

We have this code that generates our "secure session" strings. So, we need to put attention to this string:  
```mt_srand(intval(bin2hex($SEEDS[md5($id)[0] % (count($SEEDS))]),16));```.

We can see that ```mt_srand``` function uses special seed for pseudo-random numbers generation. So, if we can discover the seed, we can recreate our session generator.

[!] Also, we should use PHP for our generator, because of special realization of [Mersenne Twister](<https://en.wikipedia.org/wiki/Mersenne_Twister>) algorithm in PHP. I tried to recreate this generator in Python, but even with the same seed, output was different.

Let's look at our mt_srand function. 

We should notice, that ```$SEEDS = str_split($FLAG, 4);``` is an array of 4-symbol strings of our flag. ```$id``` is a concatenated string of login and password.

```md5($id)[0]``` returns first symbol of MD5-hash (hex-like) of our string. So, ```0 <= md5($id)[0] <= 15```. We can use it to generate credentials for every MD5 value (just because we can't manipulate ```count($SEEDS)``` variable and it's the only way to get various parts of flag). So, let's generate credentials:

```  
import hashlib

ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789_-"

# weird generator, but anyway  
def find_creds_with_target_md5(md5):  
for a in ALPHA:  
for b in ALPHA:  
for c in ALPHA:  
for d in ALPHA:  
for a1 in ALPHA:  
for b1 in ALPHA:  
for c1 in ALPHA:  
for d1 in ALPHA:  
md5_hash = hashlib.md5(f"{a}{b}{c}{d}{a1}{b1}{c1}{d1}".encode()).hexdigest()  
if int(md5_hash[0], 16) == md5:  
print(f"FOUND FOR MD5 = {md5}: {a}{b}{c}{d} . {a1}{b1}{c1}{d1}")  
return

FOUND FOR MD5 = 0: aaaa . aaaf  
FOUND FOR MD5 = 1: aaaa . aaa2  
FOUND FOR MD5 = 2: aaaa . aaab  
FOUND FOR MD5 = 3: aaaa . aaaa  
FOUND FOR MD5 = 4: aaaa . aaa9  
FOUND FOR MD5 = 5: aaaa . aaay  
FOUND FOR MD5 = 6: aaaa . aaag  
FOUND FOR MD5 = 7: aaaa . aaad  
FOUND FOR MD5 = 8: aaaa . aaao  
FOUND FOR MD5 = 9: aaaa . aaak  
FOUND FOR MD5 = 10: aaaa . aaan  
FOUND FOR MD5 = 11: aaaa . aaax  
FOUND FOR MD5 = 12: aaaa . aaae  
FOUND FOR MD5 = 13: aaaa . aaal  
FOUND FOR MD5 = 14: aaaa . aaac  
FOUND FOR MD5 = 15: aaaa . aaa0  
```

We can use this credentials to get session strings with various predefined MD5 values from website.

Well, next step: write a flag bruteforcer! :)

```

```

And now, if we try this bruteforcer with different credentials we generated before and website-generated tokens, we can retrieve different parts of flag! And then, we can recreate our flag with this parts!

### Flag

```ENO{SOME_SUPER_SECURE_FLAG_1333337_HACK}```
