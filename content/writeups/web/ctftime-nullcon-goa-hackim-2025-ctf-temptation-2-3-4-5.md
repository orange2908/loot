---
title: "Temptation - Nullcon Goa HackIM 2025 CTF"
category: "web"
subcategory: "ssti"
type: "writeup"
tags: ["web", "ssti", "base64", "temptation", "nullcon-goa-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "Screenshots (<https://imgur.com/a/VdhVCiX>)"
source:
  name: "CTFtime writeup #39849"
  url: "https://ctftime.org/writeup/39849"
ctf:
  name: "Nullcon Goa HackIM 2025 CTF"
  year: 2025
  challenge: "Temptation"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2025 CTF
- **Task:** Temptation
- **Author team:** DIONLABS
- **CTFtime tags:** web
- **CTFtime:** <https://ctftime.org/writeup/39849>

---
> ###### The attempted attempt to tempt the untempted into a tempting but contemptible scheme was an untempting temptation that exemplified not only contempt but also a preemptive exemption from any redemptive attempts.  
>   
> ###### Author: @gehaxelt

Write-up author: twenty5

### Explanation 

Screenshots (<https://imgur.com/a/VdhVCiX>)

The name and the description gave me a hint that it might be an SSTI (**Server-Side Template Injection**).   
So the challenge consists of a simple web page with a submission form.

![webpage](<https://i.imgur.com/PjnIWYP.png>)

When I you try to submit anything it just returns Too Tempted!

![Too Tempted!](<https://i.imgur.com/mj65AJr.png>)

Then I checked the page's html code. There was a comment with a url parameter that allows to fetch the source code of the webpage.

![html](<https://i.imgur.com/zyYNtWe.png>)

In the source code it became obvious that it's an SSTI because the user input is passed to the template engine without any sanitization (highlighted in red).

![source code](<https://i.imgur.com/5oZfnzR.png>)

Then I've googled the webpy's documentation and there was a block about builtins and globals. I was trying to figure out what functions were available and went to webpy's github repository.

![docs](<https://i.imgur.com/lhmeq5Z.png>)

Looking through the [template.py](http://template.py) code (<https://github.com/webpy/webpy/blob/master/web/template.py>) I've found TEMPLATE_BUILTIN_NAMES and there was a builtin import function.

![git](<https://i.imgur.com/QAh9ZVK.png>)

After that I was trying to figure out how to exploit it and came up with a payload that imports os module and calls the system function that runs a curl command sending a post request to my collaborator with the output of any command in the body. 

![payload](<https://i.imgur.com/qDMPnlq.png>)

The flag was in the /tmp folder (look at the source code of the chall), but it can't be read as /tmp/flag.txt because there's an if statement that checks for the word flag in the user input, so I used /tmp/\\*.txt and encoded it with base64.

![missed it](<https://i.imgur.com/OX3EO4O.png>)

Then I checked the colaborator and there it was!  
![flag](<https://i.imgur.com/cK0EJuJ.png>)

Flag: **ENO{T3M_Pl4T_3s_4r3_s3cUre!!}**
