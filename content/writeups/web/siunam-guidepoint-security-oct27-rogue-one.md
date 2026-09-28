---
title: "Rogue-One - GuidePoint-Security-Oct27 2022"
category: "web"
subcategory: "web"
type: "writeup"
tags: ["web", "rogue-one", "web-exploitation", "guidepoint-security-oct27", "siunam321", "rogue"]
summary: "In this challenge, we can start a docker instance:"
source:
  name: "siunam321.github.io"
  url: "https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Rogue-One/"
original_source:
  name: "siunam321/siunam321.github.io"
  url: "https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Rogue-One/README.md"
ctf:
  name: "GuidePoint-Security-Oct27"
  year: 2022
  challenge: "Rogue-One"
---

## Source

- **CTF:** GuidePoint-Security-Oct27 2022
- **Challenge:** Rogue-One
- **Author:** [siunam321](https://siunam321.github.io/)
- **Writeup:** <https://siunam321.github.io/ctf/GuidePoint-Security-Oct27-2022/Web/Rogue-One/>
- **Source file:** <https://github.com/siunam321/siunam321.github.io/blob/87b2af97016b8b5def0b3ffc0b37a6e89d876d95/ctf/GuidePoint-Security-Oct27-2022/Web/Rogue-One/README.md>

---
# Rogue One

## Overview

- Overall difficulty for me: Very easy

**In this challenge, we can start a docker instance:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063644.png)

## Find the flag

**Home page:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063716.png)

**When we click the `Begin here`, it'll generate a random string:**

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063801.png)

![](https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/GuidePoint-Security-Oct27-2022/images/Pasted%20image%2020221028063926.png)

**Too slow... Alright then, I'll write a [python script](https://github.com/siunam321/CTF-Writeups/blob/main/GuidePoint-Security-Oct27-2022/Web/Rogue-One/solve.py) to solve this:**
```py
#!/usr/bin/env python3

import requests

url = 'http://10.10.100.200:38125/number/'

s = requests.Session()

r = s.get(url)
number = r.text

result = s.get(url + '?answer=' + number)
print(result.text)
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/GuidePoint-Security-Oct27-2022/Web/Rogue-One]
└─# python3 solve.py
GPSCTF{2692edb3426f224b78d695938de352e3}
```

We got the flag!

# Conclusion

What we've learned:

1. Sending GET Requests in Python
